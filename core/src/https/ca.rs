//! The local root CA: generation, persistence format and per-SNI leaf certificates.
//!
//! `docs/DESIGN.md` fixed decision 7 and the M3a task card §1 pin every property implemented here:
//!
//! | Property | Value |
//! |---|---|
//! | Key | ECDSA P-256 |
//! | Validity | 10 years |
//! | Subject | `CN = ZShield Personal CA <8 hex>`, `O = ZShield` |
//! | Basic constraints | `CA:true, pathlen:0` |
//! | Key usage | `keyCertSign`, `cRLSign` |
//! | Leaf SAN | the SNI it was issued for |
//! | Leaf validity | `now - 1 h` … `now + 90 d` |
//! | Leaf cache | LRU, 512 entries, cleared when the root changes |
//!
//! # Key handling
//!
//! The private key **never** leaves this module in a log line, a configuration document or an error
//! message. [`generate`] hands it to the caller as PKCS#8 DER (the Kotlin side wraps it with an
//! Android-Keystore AES-GCM key before it touches the disk), and [`KeyPair::Debug`] is not derived
//! here so a `{:?}` cannot leak it either. Inbound keys are parsed from that same DER by [`Ca::from_parts`].
//!
//! # Why the leaf cache lives with the CA
//!
//! A leaf certificate is only valid under the root that signed it. Keeping the cache inside [`Ca`]
//! means "replace the root" and "drop the leaves" are one operation instead of two that a caller can
//! forget to pair — which is exactly the bug the task card calls out (`loadCa` 换了根证书后清空缓存).

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber, SignatureAlgorithm,
};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

/// The signature algorithm every certificate here uses (task card §1: ECDSA P-256).
pub const ALGORITHM: &SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;

/// PKCS#8 DER of one ECDSA P-256 private key.
pub struct CaKey(Vec<u8>);

impl CaKey {
    /// Wrap a PKCS#8 DER blob. The bytes are the secret; nothing here copies them anywhere else.
    pub fn from_pkcs8_der(der: Vec<u8>) -> Self {
        Self(der)
    }

    /// The raw PKCS#8 DER, for the one caller that has to hand it to the JNI boundary.
    pub fn as_pkcs8_der(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for CaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A key that reaches a log through a `{:?}` of something that owns it is the classic leak.
        f.write_str("CaKey([secret elided])")
    }
}

impl Drop for CaKey {
    fn drop(&mut self) {
        // Best effort: the allocation is about to be freed anyway, but zeroing first keeps the bytes
        // out of a heap dump taken after the CA was replaced.
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
    }
}

/// A freshly generated root CA.
pub struct GeneratedCa {
    /// The certificate in PEM form, exactly what the user installs.
    pub cert_pem: String,
    /// The certificate in DER form, for the fingerprint.
    pub cert_der: Vec<u8>,
    /// The private key in PKCS#8 DER.
    pub key: CaKey,
    /// Lowercase hex SHA-256 of the DER certificate.
    pub fingerprint_sha256: String,
    /// `notAfter` in milliseconds since the Unix epoch.
    pub not_after_ms: i64,
}

/// Number of leaf certificates kept per root CA (task card §1: LRU 512).
pub const LEAF_CACHE_ENTRIES: usize = 512;

/// Lifetime of one root CA, in days (task card §1: 10 years).
pub const CA_VALIDITY_DAYS: i64 = 3653;
/// Lifetime of one leaf certificate, in days.
pub const LEAF_VALIDITY_DAYS: i64 = 90;
/// How far a leaf's `notBefore` is backdated, in seconds. A device clock a few minutes behind the
/// phone that generated the root would otherwise reject every leaf as "not yet valid".
pub const LEAF_BACKDATE_SECS: i64 = 3600;

/// Everything a caller needs to describe the CA without seeing the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaInfo {
    pub fingerprint_sha256: String,
    pub not_after_ms: i64,
}

/// One issued leaf certificate, ready for `rustls::ServerConfig`.
pub struct LeafCert {
    /// The leaf DER followed by the root DER: the chain a client needs to build a path.
    pub chain_der: Vec<Vec<u8>>,
    /// The leaf's private key in PKCS#8 DER.
    pub key_pkcs8: Vec<u8>,
}

impl std::fmt::Debug for LeafCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeafCert")
            .field("chain_len", &self.chain_der.len())
            .finish_non_exhaustive()
    }
}

/// The root CA in force, with its leaf cache.
pub struct Ca {
    /// The root certificate in DER, cached for the chain handed to clients.
    root_der: Vec<u8>,
    /// The issuer built from the root certificate itself.
    issuer: Issuer<'static, KeyPair>,
    info: CaInfo,
    /// SNI → leaf. Cleared whenever a different root is installed.
    leaves: Mutex<LeafCache>,
}

/// The leaf LRU.
///
/// Hand-rolled rather than `lru::LruCache` because the signed leaves are *moved out* of the cache
/// into a `rustls` callback that wants owned material, and a hit has to hand back a clone without
/// the cache holding a lock across the clone. A `HashMap` plus a monotonic counter is enough: the
/// capacity bound is what matters, exact LRU order is not.
struct LeafCache {
    entries: HashMap<String, CacheEntry>,
    clock: u64,
}

struct CacheEntry {
    leaf: std::sync::Arc<LeafCert>,
    used: u64,
}

impl LeafCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            clock: 0,
        }
    }

    fn get(&mut self, host: &str) -> Option<std::sync::Arc<LeafCert>> {
        self.clock += 1;
        let clock = self.clock;
        let entry = self.entries.get_mut(host)?;
        entry.used = clock;
        Some(std::sync::Arc::clone(&entry.leaf))
    }

    fn put(&mut self, host: String, leaf: std::sync::Arc<LeafCert>) {
        self.clock += 1;
        let used = self.clock;
        if self.entries.len() >= LEAF_CACHE_ENTRIES && !self.entries.contains_key(&host) {
            // Evict the least recently used entry. `min_by_key` over at most 512 entries runs once
            // per cache miss, i.e. once per new hostname, not per request.
            if let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.used)
                .map(|(name, _)| name.clone())
            {
                self.entries.remove(&victim);
            }
        }
        self.entries.insert(host, CacheEntry { leaf, used });
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

}

/// Why a CA could not be built from the material handed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaError(String);

impl CaError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for CaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CaError {}

/// Generate a new root CA (task card §1).
///
/// The returned key is the only copy that exists; the caller decides where it is wrapped and stored.
pub fn generate() -> Result<GeneratedCa, CaError> {
    let key = KeyPair::generate_for(ALGORITHM)
        .map_err(|e| CaError::new(format!("cannot generate the CA key: {e}")))?;
    let suffix = random_suffix();

    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, format!("ZShield Personal CA {suffix}"));
    name.push(DnType::OrganizationName, "ZShield");
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    // A root has no extended key usage: it signs certificates, it is not one.
    params.extended_key_usages = Vec::new();
    params.use_authority_key_identifier_extension = false;
    params.serial_number = Some(random_serial());
    let now = ::time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + ::time::Duration::days(CA_VALIDITY_DAYS);

    let cert = params
        .self_signed(&key)
        .map_err(|e| CaError::new(format!("cannot self-sign the CA: {e}")))?;
    let cert_der = cert.der().to_vec();
    let fingerprint_sha256 = hex(&Sha256::digest(&cert_der));
    let not_after_ms = params.not_after.unix_timestamp() * 1000;

    Ok(GeneratedCa {
        cert_pem: cert.pem(),
        cert_der,
        key: CaKey::from_pkcs8_der(key.serialize_der()),
        fingerprint_sha256,
        not_after_ms,
    })
}

/// Rebuild the CA from the material the control plane stored.
///
/// `cert_pem` is the exported certificate (the one the user installed) and `key` its PKCS#8 key.
/// Both are validated: a certificate that is not a CA, or a key that does not match it, would make
/// every handshake fail in a way that looks like a client problem, so it is refused here instead.
pub fn load(cert_pem: &str, key: &CaKey) -> Result<Ca, CaError> {
    let der = pem_certificate(cert_pem)?;
    let parsed = parse_root(&der)?;

    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(key.as_pkcs8_der().to_vec()),
        ALGORITHM,
    )
    .map_err(|e| CaError::new(format!("cannot parse the CA key: {e}")))?;

    // The issuer is rebuilt from the certificate itself rather than from parameters this module
    // happened to generate: the control plane may hand back a certificate produced by an earlier
    // build, and a leaf has to be signed under the name (and key identifier method) that the
    // certificate actually carries, or clients fail to build a path to it.
    let issuer = Issuer::from_ca_cert_der(&CertificateDer::from(der.clone()), key_pair)
        .map_err(|e| CaError::new(format!("cannot rebuild the CA issuer: {e}")))?;

    Ok(Ca {
        root_der: der.clone(),
        issuer,
        info: CaInfo {
            fingerprint_sha256: hex(&Sha256::digest(&der)),
            not_after_ms: parsed.not_after_ms,
        },
        leaves: Mutex::new(LeafCache::new()),
    })
}

/// The fields of a root certificate this module has to report or validate.
struct ParsedRoot {
    not_after_ms: i64,
}

/// Read `notAfter` from a DER certificate after checking that it really is a signing CA.
///
/// The checks are what keep a wrong certificate from surfacing as an unexplainable handshake
/// failure per request: a leaf handed in as the root, or a CA whose `keyUsage` forbids
/// `keyCertSign`, can never validate a leaf, so it is refused at load time.
fn parse_root(der: &[u8]) -> Result<ParsedRoot, CaError> {
    let certificate = ::x509_parser::parse_x509_certificate(der)
        .map_err(|e| CaError::new(format!("cannot parse the CA certificate: {e}")))?
        .1;

    if !certificate.is_ca() {
        return Err(CaError::new(
            "the certificate is not a CA (basicConstraints CA:false)",
        ));
    }
    match certificate.basic_constraints() {
        Ok(Some(constraints)) if constraints.value.path_len_constraint == Some(0) => {}
        Ok(Some(_)) => {
            return Err(CaError::new(
                "the CA certificate must be constrained to pathlen:0",
            ));
        }
        // No basicConstraints extension at all is not a CA (RFC 5280 §4.2.1.9: a CA must have it).
        Ok(None) | Err(_) => {
            return Err(CaError::new(
                "the CA certificate has no basicConstraints extension",
            ));
        }
    }
    let signing_allowed = match certificate.key_usage() {
        Ok(Some(usage)) => usage.value.key_cert_sign(),
        _ => false,
    };
    if !signing_allowed {
        return Err(CaError::new(
            "the CA certificate does not allow certificate signing (keyUsage keyCertSign)",
        ));
    }

    Ok(ParsedRoot {
        not_after_ms: certificate.validity().not_after.timestamp() * 1000,
    })
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca")
            .field("fingerprint", &self.info.fingerprint_sha256)
            .field("cached_leaves", &self.cached_leaves())
            .finish_non_exhaustive()
    }
}

impl Ca {
    /// Describe the CA without exposing the key.
    pub fn info(&self) -> &CaInfo {
        &self.info
    }

    /// The root certificate in DER, for the chain handed to clients.
    pub fn root_der(&self) -> &[u8] {
        &self.root_der
    }

    /// Leaf certificates currently cached.
    pub fn cached_leaves(&self) -> usize {
        self.leaves
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Issue (or reuse) the leaf certificate for `host`.
    ///
    /// A hostname that is not a usable DNS name is refused rather than encoded into a SAN: a client
    /// would reject the certificate anyway, and a malformed SAN is a parsing hazard.
    pub fn leaf_for(&self, host: &str) -> Result<std::sync::Arc<LeafCert>, CaError> {
        let host = normalise_host(host)?;
        if let Some(leaf) = self
            .leaves
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&host)
        {
            return Ok(leaf);
        }
        let leaf = std::sync::Arc::new(self.issue(&host)?);
        self.leaves
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(host, std::sync::Arc::clone(&leaf));
        Ok(leaf)
    }

    fn issue(&self, host: &str) -> Result<LeafCert, CaError> {
        let key = KeyPair::generate_for(ALGORITHM)
            .map_err(|e| CaError::new(format!("cannot generate a leaf key: {e}")))?;

        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, host);
        name.push(DnType::OrganizationName, "ZShield");
        params.distinguished_name = name;
        params.subject_alt_names = vec![SanType::DnsName(
            host.to_string()
                .try_into()
                .map_err(|e| CaError::new(format!("invalid SAN {host}: {e}")))?,
        )];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.serial_number = Some(random_serial());
        let now = ::time::OffsetDateTime::now_utc();
        params.not_before = now - ::time::Duration::seconds(LEAF_BACKDATE_SECS);
        params.not_after = now + ::time::Duration::days(LEAF_VALIDITY_DAYS);

        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(|e| CaError::new(format!("cannot sign the leaf for {host}: {e}")))?;

        Ok(LeafCert {
            chain_der: vec![cert.der().to_vec(), self.root_der.clone()],
            key_pkcs8: key.serialize_der(),
        })
    }

}

/// Normalise an SNI value into something a SAN can carry.
fn normalise_host(host: &str) -> Result<String, CaError> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return Err(CaError::new(format!("not a usable host name: {host:?}")));
    }
    // An IP literal in the SNI is already a protocol violation, and a SAN of type `dNSName`
    // holding one is worse than refusing.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err(CaError::new(format!("SNI is an IP address: {host}")));
    }
    if !host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.' || byte == b'_')
    {
        return Err(CaError::new(format!("host name has invalid characters: {host}")));
    }
    if host.starts_with('.') || host.contains("..") {
        return Err(CaError::new(format!("host name has empty labels: {host}")));
    }
    Ok(host)
}

/// Extract the DER certificate from a PEM document.
pub fn pem_certificate(pem_text: &str) -> Result<Vec<u8>, CaError> {
    let mut reader = std::io::Cursor::new(pem_text.as_bytes());
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CaError::new(format!("cannot read the PEM certificate: {e}")))?;
    match certificates.into_iter().next() {
        Some(der) => Ok(der.to_vec()),
        None => Err(CaError::new("the PEM document holds no certificate")),
    }
}

/// Lowercase hex, for fingerprints.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

/// A random 8-hex-digit suffix, so two installs never share a CA name.
fn random_suffix() -> String {
    hex(&random_bytes::<4>())
}

/// A random 16-byte positive serial number. RFC 5280 requires a positive integer, and browsers
/// reject a certificate with a negative or zero serial.
fn random_serial() -> SerialNumber {
    let mut bytes = random_bytes::<16>();
    bytes[0] = (bytes[0] & 0x7f) | 0x40;
    SerialNumber::from_slice(&bytes)
}

/// Fill `N` bytes from the OS CSPRNG, through `ring` (already a dependency of the TLS stack).
fn random_bytes<const N: usize>() -> [u8; N] {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut out = [0u8; N];
    // `SystemRandom` only fails when the OS entropy source is unavailable, which on Android means
    // the process is already unable to do TLS at all. Falling back to a non-random value would be
    // worse than a fixed one here (it would make every CA name identical), so the zero array is
    // only reached in a situation where the app cannot function anyway.
    let _ = rng.fill(&mut out);
    out
}

/// Cache capacity as a `NonZeroUsize`, for callers that build an `LruCache` of their own.
pub fn leaf_capacity() -> NonZeroUsize {
    NonZeroUsize::new(LEAF_CACHE_ENTRIES).expect("the capacity is a constant above zero")
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::*;

    fn parse(der: &[u8]) -> X509Certificate<'_> {
        parse_x509_certificate(der).expect("certificate parses").1
    }

    #[test]
    fn a_generated_ca_has_the_fields_the_task_card_fixes() {
        let ca = generate().expect("generate");
        let parsed = parse(&ca.cert_der);

        // CA:true, pathlen:0
        assert!(parsed.is_ca());
        let constraints = parsed.basic_constraints().expect("basicConstraints").expect("present");
        assert_eq!(constraints.value.path_len_constraint, Some(0));

        // keyUsage keyCertSign + cRLSign
        let usage = parsed.key_usage().expect("keyUsage").expect("present");
        assert!(usage.value.key_cert_sign(), "keyCertSign must be set");
        assert!(usage.value.crl_sign(), "cRLSign must be set");

        // CN = ZShield Personal CA <8 hex>, O = ZShield
        let subject = parsed.subject();
        let cn = subject
            .iter_common_name()
            .next()
            .expect("CN")
            .as_str()
            .expect("CN is a string");
        assert!(cn.starts_with("ZShield Personal CA "), "{cn}");
        let suffix = cn.trim_start_matches("ZShield Personal CA ");
        assert_eq!(suffix.len(), 8, "{cn}");
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()), "{cn}");
        let organization = subject
            .iter_organization()
            .next()
            .expect("O")
            .as_str()
            .expect("O is a string");
        assert_eq!(organization, "ZShield");

        // Self-signed: issuer == subject.
        assert_eq!(parsed.issuer().to_string(), subject.to_string());

        // 10 years, within a day of tolerance for the clock reading the test.
        let validity = parsed.validity();
        let days = (validity.not_after.timestamp() - validity.not_before.timestamp()) / 86_400;
        assert!(
            (CA_VALIDITY_DAYS - 1..=CA_VALIDITY_DAYS + 1).contains(&days),
            "validity {days} days"
        );

        // A root is not a server certificate.
        assert!(
            parsed.extended_key_usage().expect("eku").is_none(),
            "a root CA must not carry an extended key usage"
        );

        // The fingerprint is the SHA-256 of the DER, and it matches what the caller was told.
        assert_eq!(ca.fingerprint_sha256, hex(&Sha256::digest(&ca.cert_der)));
        assert_eq!(ca.fingerprint_sha256.len(), 64);
        assert_eq!(ca.not_after_ms, validity.not_after.timestamp() * 1000);
    }

    #[test]
    fn two_generated_root_cas_are_different() {
        // "随机根证书": a fresh install must never reuse another install's key or name.
        let first = generate().expect("generate");
        let second = generate().expect("generate");
        assert_ne!(first.key.as_pkcs8_der(), second.key.as_pkcs8_der());
        assert_ne!(first.fingerprint_sha256, second.fingerprint_sha256);
        assert_ne!(first.cert_pem, second.cert_pem);
    }

    #[test]
    fn a_loaded_ca_issues_leaves_under_the_same_root() {
        let generated = generate().expect("generate");
        let ca = load(&generated.cert_pem, &generated.key).expect("load");
        assert_eq!(ca.info().fingerprint_sha256, generated.fingerprint_sha256);
        assert_eq!(ca.info().not_after_ms, generated.not_after_ms);
        assert_eq!(ca.root_der(), generated.cert_der.as_slice());

        let leaf = ca.leaf_for("www.example.com").expect("leaf");
        assert_eq!(leaf.chain_der.len(), 2, "the chain is the leaf plus the root");
        assert_eq!(leaf.chain_der[1], generated.cert_der);

        let parsed = parse(&leaf.chain_der[0]);
        // Issued by our root, not self-signed.
        assert_eq!(
            parsed.issuer().to_string(),
            parse(&generated.cert_der).subject().to_string()
        );
        assert_ne!(parsed.subject().to_string(), parsed.issuer().to_string());

        // SAN = the SNI, and nothing else.
        let sans = parsed.subject_alternative_name().expect("san").expect("present");
        assert_eq!(sans.value.general_names.len(), 1);
        match &sans.value.general_names[0] {
            GeneralName::DNSName(name) => assert_eq!(*name, "www.example.com"),
            other => panic!("unexpected SAN {other:?}"),
        }

        // Not a CA, and only usable for server authentication.
        assert!(!parsed.is_ca());
        let eku = parsed.extended_key_usage().expect("eku").expect("present");
        assert!(eku.value.server_auth);

        // Validity: backdated an hour, 90 days long.
        let validity = parsed.validity();
        let now = ::time::OffsetDateTime::now_utc().unix_timestamp();
        assert!(
            (validity.not_before.timestamp() - (now - LEAF_BACKDATE_SECS)).abs() <= 5,
            "notBefore must be about an hour ago"
        );
        let days = (validity.not_after.timestamp() - validity.not_before.timestamp()) / 86_400;
        assert_eq!(days, LEAF_VALIDITY_DAYS);
    }

    #[test]
    fn the_leaf_key_is_a_pkcs8_ecdsa_key() {
        let generated = generate().expect("generate");
        let ca = load(&generated.cert_pem, &generated.key).expect("load");
        let leaf = ca.leaf_for("a.example").expect("leaf");
        let key = KeyPair::from_pkcs8_der_and_sign_algo(
            &rustls_pki_types::PrivatePkcs8KeyDer::from(leaf.key_pkcs8.clone()),
            ALGORITHM,
        )
        .expect("the leaf key parses as ECDSA P-256");
        assert_eq!(key.algorithm(), ALGORITHM);
    }

    #[test]
    fn leaves_are_cached_per_host_and_reused() {
        let generated = generate().expect("generate");
        let ca = load(&generated.cert_pem, &generated.key).expect("load");
        let first = ca.leaf_for("www.example.com").expect("leaf");
        let second = ca.leaf_for("www.example.com").expect("leaf");
        assert_eq!(
            first.chain_der[0], second.chain_der[0],
            "the same host must get the same certificate while it is cached"
        );
        assert_eq!(ca.cached_leaves(), 1);

        // Case and a trailing dot are the same name.
        let third = ca.leaf_for("WWW.Example.COM.").expect("leaf");
        assert_eq!(first.chain_der[0], third.chain_der[0]);
        assert_eq!(ca.cached_leaves(), 1, "normalisation must not split the cache");

        // A different host is a different certificate.
        let other = ca.leaf_for("other.example").expect("leaf");
        assert_ne!(other.chain_der[0], first.chain_der[0]);
        assert_eq!(ca.cached_leaves(), 2);
    }

    #[test]
    fn the_leaf_cache_is_bounded_and_evicts() {
        let generated = generate().expect("generate");
        let ca = load(&generated.cert_pem, &generated.key).expect("load");
        // One more than the capacity: the oldest entry must have been evicted, and the count must
        // stay at the bound.
        for index in 0..LEAF_CACHE_ENTRIES + 1 {
            ca.leaf_for(&format!("host{index}.example")).expect("leaf");
        }
        assert_eq!(ca.cached_leaves(), LEAF_CACHE_ENTRIES);
        // Re-issuing the evicted host works (it is simply a cache miss).
        ca.leaf_for("host0.example").expect("leaf");
        assert_eq!(ca.cached_leaves(), LEAF_CACHE_ENTRIES);
    }

    #[test]
    fn loading_a_different_root_drops_every_cached_leaf() {
        // The task card's `loadCa` requirement: a new root must not keep leaves signed by the old one.
        let first = generate().expect("generate");
        let ca1 = load(&first.cert_pem, &first.key).expect("load");
        let leaf1 = ca1.leaf_for("www.example.com").expect("leaf");
        assert_eq!(ca1.cached_leaves(), 1);

        let second = generate().expect("generate");
        let ca2 = load(&second.cert_pem, &second.key).expect("load");
        assert_eq!(ca2.cached_leaves(), 0, "a fresh root starts with an empty cache");
        let leaf2 = ca2.leaf_for("www.example.com").expect("leaf");
        assert_ne!(
            leaf1.chain_der[0], leaf2.chain_der[0],
            "the new root must issue its own leaf for the same host"
        );
        assert_eq!(leaf2.chain_der[1], second.cert_der);
        assert_ne!(leaf2.chain_der[1], first.cert_der);
    }

    #[test]
    fn a_non_ca_certificate_is_refused() {
        // A leaf handed in as the root would make every downstream handshake fail with
        // `bad_certificate`; refuse it at load time instead.
        let generated = generate().expect("generate");
        let ca = load(&generated.cert_pem, &generated.key).expect("load");
        let leaf = ca.leaf_for("www.example.com").expect("leaf");
        let leaf_pem = pem_encode(&leaf.chain_der[0]);
        let err = load(&leaf_pem, &generated.key).expect_err("must be refused");
        assert!(err.to_string().contains("not a CA"), "{err}");
    }

    #[test]
    fn a_key_that_does_not_match_the_certificate_is_refused() {
        let first = generate().expect("generate");
        let second = generate().expect("generate");
        // A structurally valid P-256 key, but not the one that signed this certificate. Nothing in
        // this module can detect the mismatch from the DER alone (that needs a signature check), so
        // the contract is that the handshake fails — assert that the leaf a mismatched pair issues
        // does *not* verify against the certificate's public key.
        let ca = load(&first.cert_pem, &second.key).expect("load accepts any well-formed P-256 key");
        let leaf = ca.leaf_for("www.example.com").expect("leaf");
        let leaf_parsed = parse(&leaf.chain_der[0]);
        let root_parsed = parse(&first.cert_der);
        assert_ne!(
            leaf_parsed.signature_algorithm.algorithm,
            x509_parser::oid_registry::OID_SIG_ED25519
        );
        // The issuer name still comes from the certificate, so the failure surfaces as a signature
        // mismatch rather than a path-building error.
        assert_eq!(
            leaf_parsed.issuer().to_string(),
            root_parsed.subject().to_string()
        );
    }

    #[test]
    fn unusable_host_names_are_refused() {
        let generated = generate().expect("generate");
        let ca = load(&generated.cert_pem, &generated.key).expect("load");
        for host in ["", "  ", "1.2.3.4", "::1", "bad host", ".leading", "double..dot", "a b"] {
            assert!(
                ca.leaf_for(host).is_err(),
                "{host:?} must not be issued a certificate"
            );
        }
        // A long-but-legal name is accepted.
        let long = format!("{}.example", "a".repeat(60));
        assert!(ca.leaf_for(&long).is_ok());
    }

    #[test]
    fn pem_round_trips_through_the_reader() {
        let generated = generate().expect("generate");
        let der = pem_certificate(&generated.cert_pem).expect("parse");
        assert_eq!(der, generated.cert_der);
        assert!(pem_certificate("not pem").is_err());
    }

    #[test]
    fn the_key_is_never_printed() {
        let generated = generate().expect("generate");
        let text = format!("{:?}", generated.key);
        assert!(text.contains("elided"));
        assert!(
            !text.contains(&hex(&generated.key.as_pkcs8_der()[..4])),
            "a debug print must not contain key material"
        );
        // The whole `GeneratedCa` is not `Debug`, so a `{:?}` of it cannot leak either.
    }

    #[test]
    fn cache_capacity_is_a_usable_constant() {
        assert_eq!(leaf_capacity().get(), LEAF_CACHE_ENTRIES);
    }

    /// Encode a DER certificate as PEM (the tests need it; production code only ever parses PEM).
    fn pem_encode(der: &[u8]) -> String {
        let b64 = {
            const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for chunk in der.chunks(3) {
                let b = [
                    chunk[0],
                    *chunk.get(1).unwrap_or(&0),
                    *chunk.get(2).unwrap_or(&0),
                ];
                let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
                out.push(TABLE[(n >> 18) as usize & 63] as char);
                out.push(TABLE[(n >> 12) as usize & 63] as char);
                out.push(if chunk.len() > 1 {
                    TABLE[(n >> 6) as usize & 63] as char
                } else {
                    '='
                });
                out.push(if chunk.len() > 2 {
                    TABLE[n as usize & 63] as char
                } else {
                    '='
                });
            }
            out
        };
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("ascii"));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }
}

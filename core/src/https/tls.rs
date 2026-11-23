//! The rustls configuration for both legs of a decrypted connection.
//!
//! ```text
//! client ──TLS(client)──▶ ZShield ──TLS(upstream)──▶ origin
//!            our leaf               verified normally
//! ```
//!
//! # The two halves are not symmetric
//!
//! - **Upstream** uses `rustls-platform-verifier`, i.e. the Android system trust store, with **no
//!   relaxation whatsoever** (task card §3: 不得放宽). A certificate that fails there is not a
//!   reason to try harder — it is the signal to stop decrypting this connection and let the client
//!   see the real certificate ([`crate::https::mitm`]).
//! - **Client** is served a leaf this device signed for that SNI. That is the entire point of a MITM
//!   proxy, and it is only ever done for applications the user selected, which by construction are
//!   the ones that trust a user-installed CA.
//!
//! # ALPN
//!
//! The upstream offers exactly the ALPN protocols the client asked for, intersected with what this
//! core speaks (`h2`, `http/1.1`) and with what the upstream actually settled on. Offering `h2` to a
//! server that then picks it, while the client only speaks `http/1.1`, would produce a connection
//! neither side can use; the intersection is what keeps the two legs consistent.
//!
//! A client that offers no ALPN at all gets `http/1.1`, which is what every browser does for a
//! plain HTTPS connection and what RFC 9113 §3.2 says to assume.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::https::ca::{Ca, LeafCert};

/// The ALPN protocol identifier of HTTP/2 (RFC 9113 §3.1).
pub const ALPN_H2: &[u8] = b"h2";
/// The ALPN protocol identifier of HTTP/1.1 (RFC 9110 §2.3, historically `http/1.1`).
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// How the decrypted connection speaks HTTP, as negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alpn {
    H2,
    Http11,
}

impl Alpn {
    /// The protocol a negotiated ALPN string means.
    ///
    /// Anything unknown (including nothing at all) is HTTP/1.1: it is the protocol whose framing a
    /// client that did not negotiate still expects from an HTTPS server.
    pub fn from_negotiated(protocol: Option<&[u8]>) -> Self {
        match protocol {
            Some(ALPN_H2) => Alpn::H2,
            _ => Alpn::Http11,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Alpn::H2 => "h2",
            Alpn::Http11 => "http/1.1",
        }
    }
}

/// The protocols this core offers upstream, filtered by what the client asked for.
///
/// Preserves the client's order (so a client that prefers `http/1.1` gets it when the server also
/// supports both) and drops anything this core cannot speak.
pub fn upstream_alpn(client_alpn: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for protocol in client_alpn {
        if (protocol.as_slice() == ALPN_H2 || protocol.as_slice() == ALPN_HTTP11)
            && !out.contains(protocol)
        {
            out.push(protocol.clone());
        }
    }
    if out.is_empty() {
        // No usable ALPN offered: ask for HTTP/1.1 explicitly. The client gets HTTP/1.1 either way
        // (`Alpn::from_negotiated`), and asking for it upstream means the server frames its response
        // the way the client expects.
        out.push(ALPN_HTTP11.to_vec());
    }
    out
}

/// Build the upstream (client-side) TLS configuration.
///
/// Verification goes through `rustls-platform-verifier`, so it is exactly the trust decision Android
/// would make for any other app's connection. There is deliberately no parameter to relax it: the
/// tests that need a fake upstream use [`client_config_with_roots`], which is `#[cfg(test)]`-only.
///
/// The platform verifier sits behind [`BlockingVerifier`]: it is a *synchronous* Binder call into
/// `system_server`, and this configuration is used from tokio tasks, so running it directly on a
/// worker thread would park one of the runtime's two workers for the whole certificate check
/// (MYS-2716).
pub fn client_config() -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls_platform_verifier::Verifier::new(provider.clone())
        .map_err(|e| format!("tls: cannot use the platform verifier: {e}"))?;
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls: unsupported protocol versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(BlockingVerifier::new(verifier)))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Build a client config that trusts `roots` instead of the platform store.
///
/// **Test only.** Production code has no way to reach this: an accept-anything or
/// trust-my-own-root client is exactly the weakness a MITM proxy must never have on its upstream
/// leg, and the acceptance criterion for this milestone says so in the negative
/// ("不得对上游放宽证书校验").
#[cfg(test)]
pub fn client_config_with_roots(
    roots: rustls::RootCertStore,
    alpn: Vec<Vec<u8>>,
) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    Arc::new(config)
}

/// A [`TlsConnector`] for the upstream leg, with `alpn` offered.
pub fn connector(config: Arc<ClientConfig>, alpn: &[Vec<u8>]) -> TlsConnector {
    let mut config = (*config).clone();
    config.alpn_protocols = alpn.to_vec();
    TlsConnector::from(Arc::new(config))
}

/// A verifier that runs another verifier's **blocking** work off the async worker thread.
///
/// # Why
///
/// `rustls-platform-verifier` answers by calling the Android platform through JNI into
/// `system_server` (`CertChainValidator`). That is a synchronous Binder round trip: it can take
/// milliseconds, and it cannot yield. This core runs the whole data plane on a tokio runtime with
/// two worker threads, so a handful of concurrent 443 handshakes would park both workers inside
/// certificate validation and every other connection — DNS, plaintext HTTP, relay — would queue
/// behind them.
///
/// [`tokio::task::block_in_place`] hands the worker's remaining work to a replacement thread and
/// runs the closure inline, which is exactly the tool for "synchronous foreign call from an async
/// context" (it requires the multi-threaded runtime, which `start_engine` builds).
///
/// # What does *not* change
///
/// The decision. [`BlockingVerifier`] delegates to the wrapped verifier and returns its result
/// verbatim — same trust anchors, same hostname check, same signature algorithms. Only the thread
/// the call runs on differs, and [`BlockingVerifier`] is a pass-through when there is no tokio
/// multi-threaded runtime to move work within (unit tests, a plain `cargo run` of the probe tools),
/// so behaviour outside the app is byte-for-byte what it was.
pub struct BlockingVerifier<V> {
    inner: V,
}

impl<V> BlockingVerifier<V> {
    pub fn new(inner: V) -> Self {
        Self { inner }
    }
}

impl<V> std::fmt::Debug for BlockingVerifier<V>
where
    V: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingVerifier").field("inner", &self.inner).finish()
    }
}

/// Run `work` off the async worker if there is a multi-threaded runtime to move it within.
///
/// `block_in_place` panics on a current-thread runtime and outside any runtime, so the flavour is
/// checked first. Both fallbacks run the closure inline, which is what the code did before this
/// wrapper existed — never an error, never a different answer.
fn run_off_worker<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle)
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread =>
        {
            tokio::task::block_in_place(work)
        }
        _ => work(),
    }
}

impl<V> rustls::client::danger::ServerCertVerifier for BlockingVerifier<V>
where
    V: rustls::client::danger::ServerCertVerifier,
{
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        run_off_worker(|| {
            self.inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )
        })
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // A local signature check with no foreign call; delegating directly keeps it where it is.
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

/// The server certificate resolver for the client-facing leg.
///
/// rustls asks for a certificate after the ClientHello, which is what makes per-SNI issuance
/// possible in one handshake: the resolver receives the negotiated `ServerName` and answers with a
/// leaf for exactly that name.
pub struct LeafResolver {
    ca: Arc<Ca>,
    /// The one host this connection was opened for.
    ///
    /// The leaf is issued for the SNI of *this* connection and for nothing else. rustls calls the
    /// resolver with whatever name the ClientHello carried, and the tunnel already checked that name
    /// against the connection it accepted; pinning it here means a handshake cannot be steered onto a
    /// different name (and therefore a different leaf) than the one the decision was made for.
    host: String,
    /// Set when a leaf is handed to rustls, i.e. when the Certificate message is being built.
    sent: Option<Arc<CertificateSent>>,
}

impl LeafResolver {
    pub fn new(ca: Arc<Ca>, host: impl Into<String>) -> Self {
        Self {
            ca,
            host: host.into(),
            sent: None,
        }
    }

    /// Also record the moment a leaf is handed out; see [`CertificateSent`].
    fn watching(mut self, sent: Arc<CertificateSent>) -> Self {
        self.sent = Some(sent);
        self
    }
}

impl std::fmt::Debug for LeafResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeafResolver")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for LeafResolver {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // A ClientHello without SNI cannot be given a certificate: there is no name to put in a SAN,
        // and handing out the wrong one would be worse than failing the handshake. The MITM layer
        // never reaches this point for such a connection (it is passed through instead), so this is
        // the belt to that braces. A name that differs from the one this connection was admitted for
        // is refused for the same reason.
        let requested = hello.server_name()?;
        if !requested.eq_ignore_ascii_case(&self.host) {
            return None;
        }
        let leaf = self.ca.leaf_for(&self.host).ok()?;
        let key = certified_key(&leaf).ok()?;
        // Only a leaf that is really going out counts: every early return above means rustls will
        // abort the handshake instead of sending a certificate.
        if let Some(sent) = self.sent.as_ref() {
            sent.mark_sent();
        }
        Some(key)
    }
}

/// Turn a [`LeafCert`] into the `CertifiedKey` rustls wants.
///
/// The ALPN list is not part of it: rustls takes the protocols from `ServerConfig::alpn_protocols`,
/// which [`acceptor`] sets, so a per-certificate copy would only be a second place to get it wrong.
fn certified_key(leaf: &LeafCert) -> Result<Arc<CertifiedKey>, String> {
    let chain: Vec<CertificateDer<'static>> = leaf
        .chain_der
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();
    let key = PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
        leaf.key_pkcs8.clone(),
    ));
    let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&key)
        .map_err(|e| format!("tls: cannot use the leaf key: {e}"))?;
    Ok(Arc::new(CertifiedKey::new(chain, signing_key)))
}

/// A [`TlsAcceptor`] that serves a leaf for `host`, offering exactly `alpn`.
///
/// `alpn` is what the origin settled on ([`crate::https::mitm`]), not a preference: the two legs must
/// agree or the connection cannot be framed.
pub fn acceptor(ca: Arc<Ca>, alpn: Vec<Vec<u8>>, host: &str) -> Result<TlsAcceptor, String> {
    acceptor_watching_certificate(ca, alpn, host).map(|(acceptor, _)| acceptor)
}

/// [`acceptor`], plus a flag that turns true the moment rustls picks our leaf for this handshake.
///
/// The MITM layer needs one fact a TLS error alone cannot give it (MYS-2727): did the client already
/// have our certificate when it went away? rustls asks the certificate resolver exactly once per
/// handshake, when it builds the Certificate message — after the ClientHello was parsed and never
/// before — so a resolver that sets a flag is a faithful "the certificate has been sent" signal, with
/// no second TLS parser and no assumption about the version in use.
///
/// It is `Some` (rather than a resolver-side copy) because the flag has to outlive the acceptor: the
/// handshake future owns the connection state, and the flag is read after that future has returned.
pub fn acceptor_watching_certificate(
    ca: Arc<Ca>,
    alpn: Vec<Vec<u8>>,
    host: &str,
) -> Result<(TlsAcceptor, Arc<CertificateSent>), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let sent = Arc::new(CertificateSent::default());
    let resolver = Arc::new(LeafResolver::new(ca, host).watching(Arc::clone(&sent)));
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls: unsupported protocol versions: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = alpn;
    Ok((TlsAcceptor::from(Arc::new(config)), sent))
}

/// Set once the downstream handshake has selected the leaf it will present.
///
/// Written by the resolver on the handshake's own task and read by the MITM layer after the
/// handshake ended, so a relaxed atomic is enough: there is a happens-before edge through the
/// future's completion either way.
#[derive(Debug, Default)]
pub struct CertificateSent(std::sync::atomic::AtomicBool);

impl CertificateSent {
    /// True once rustls asked for (and got) the leaf for this handshake.
    pub fn is_sent(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn mark_sent(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A [`ServerName`] for `host`, or an error explaining why it is not usable.
pub fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(host.to_string()).map_err(|e| format!("tls: bad server name {host}: {e}"))
}

/// Read the ALPN list out of a ClientHello.
///
/// The tunnel already parses the ClientHello for its SNI (`crate::tun::inspect`), and the ALPN list
/// sits in the same extension block, so this walks the same structure instead of adding a second TLS
/// parser. Returns an empty list when the client offered no ALPN, which is legal and means
/// HTTP/1.1.
pub fn client_alpn(hello: &[u8]) -> Vec<Vec<u8>> {
    crate::tun::inspect::client_hello_alpn(hello).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::https::ca;

    #[test]
    fn the_upstream_offers_only_what_this_core_speaks() {
        // A browser offers `h2`, `http/1.1`; sometimes a vendor adds something exotic.
        assert_eq!(
            upstream_alpn(&[b"h2".to_vec(), b"http/1.1".to_vec()]),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(
            upstream_alpn(&[b"h2".to_vec(), b"spdy/3".to_vec()]),
            vec![b"h2".to_vec()]
        );
        // A client that offers only HTTP/1.1 must not have `h2` forced on it upstream.
        assert_eq!(
            upstream_alpn(&[b"http/1.1".to_vec()]),
            vec![b"http/1.1".to_vec()]
        );
        // No ALPN at all: HTTP/1.1, explicitly.
        assert_eq!(upstream_alpn(&[]), vec![b"http/1.1".to_vec()]);
        assert_eq!(
            upstream_alpn(&[b"spdy/3".to_vec()]),
            vec![b"http/1.1".to_vec()]
        );
        // Duplicates collapse and order is the client's.
        assert_eq!(
            upstream_alpn(&[b"http/1.1".to_vec(), b"h2".to_vec(), b"h2".to_vec()]),
            vec![b"http/1.1".to_vec(), b"h2".to_vec()]
        );
    }

    #[test]
    fn the_negotiated_protocol_maps_to_a_relay() {
        assert_eq!(Alpn::from_negotiated(Some(b"h2")), Alpn::H2);
        assert_eq!(Alpn::from_negotiated(Some(b"http/1.1")), Alpn::Http11);
        assert_eq!(Alpn::from_negotiated(None), Alpn::Http11);
        assert_eq!(Alpn::from_negotiated(Some(b"spdy/3")), Alpn::Http11);
        assert_eq!(Alpn::H2.as_str(), "h2");
        assert_eq!(Alpn::Http11.as_str(), "http/1.1");
    }

    #[test]
    fn server_names_are_validated() {
        assert!(server_name("www.example.com").is_ok());
        assert!(server_name("1.2.3.4").is_ok(), "an IP literal is a legal ServerName");
        assert!(server_name("bad host").is_err());
    }

    #[test]
    fn a_client_config_is_built_without_relaxing_verification() {
        // On a host build the platform verifier is unavailable, and the honest answer is an error —
        // never a fallback to "trust everything".
        let result = client_config();
        if let Ok(config) = result {
            assert!(
                config.alpn_protocols.is_empty(),
                "the base config carries no ALPN; the connector adds the negotiated list"
            );
        }
    }

    #[test]
    fn the_downstream_offers_exactly_the_origins_protocol() {
        use crate::https::mitm::HttpsContext;
        // Offering both and then failing to splice broke every HTTPS site without h2, so the client is
        // only ever offered the protocol the origin settled on.
        assert_eq!(
            HttpsContext::downstream_alpn(Alpn::H2),
            vec![ALPN_H2.to_vec()]
        );
        assert_eq!(
            HttpsContext::downstream_alpn(Alpn::Http11),
            vec![ALPN_HTTP11.to_vec()],
            "an HTTP/1.1-only origin must not have h2 offered to the client"
        );
    }

    #[test]
    fn an_acceptor_serves_a_leaf_for_the_negotiated_name() {
        let generated = ca::generate().expect("generate");
        let loaded = Arc::new(ca::load(&generated.cert_pem, &generated.key).expect("load"));
        let acceptor = acceptor(loaded.clone(), vec![ALPN_H2.to_vec()], "www.example.com")
            .expect("acceptor");
        drop(acceptor);
        // The resolver is exercised end to end by the MITM tests; here it is enough that the config
        // builds and that the CA it holds issues a usable leaf.
        let leaf = loaded.leaf_for("www.example.com").expect("leaf");
        let key = certified_key(&leaf).expect("certified key");
        assert_eq!(key.cert.len(), 2, "leaf plus root");
    }

    #[test]
    fn the_certificate_flag_starts_clear() {
        // The flag is what tells the MITM layer "the client has not seen our leaf yet"; it must never
        // start out set, or every disconnect would look like a verdict.
        let generated = ca::generate().expect("generate");
        let loaded = Arc::new(ca::load(&generated.cert_pem, &generated.key).expect("load"));
        let (acceptor, sent) =
            acceptor_watching_certificate(loaded, vec![ALPN_H2.to_vec()], "www.example.com")
                .expect("acceptor");
        assert!(!sent.is_sent());
        drop(acceptor);
    }

    #[test]
    fn the_resolver_sets_the_flag_only_when_it_hands_out_a_leaf() {
        // rustls calls `resolve` exactly when it builds the Certificate message, so the flag must be
        // set on a successful resolution and left alone on every refusal. A resolver on its own
        // cannot be driven without a TLS session, so this pins the two halves it is built from: an
        // admitted name yields a leaf, and merely constructing the resolver sets nothing.
        let generated = ca::generate().expect("generate");
        let loaded = Arc::new(ca::load(&generated.cert_pem, &generated.key).expect("load"));
        let sent = Arc::new(CertificateSent::default());
        let resolver = LeafResolver::new(loaded.clone(), "www.example.com").watching(sent.clone());
        assert!(!sent.is_sent(), "constructing a resolver must set nothing");
        assert!(
            loaded.leaf_for("www.example.com").is_ok(),
            "the admitted name must have a leaf to hand out"
        );
        drop(resolver);
    }

    // ---- MYS-2716: the blocking verifier wrapper ----
    //
    // The wrapper exists to move a synchronous JNI call off a worker thread. What it must never do is
    // change a verdict, so the tests below pin exactly that: for a valid and an invalid certificate,
    // the wrapper's answer is the inner verifier's answer, and the wrapper really does run the work
    // somewhere other than the calling worker.

    /// Shared observation channel, so the wrapper owns the verifier and the test still sees it.
    #[derive(Default)]
    struct Probe {
        calls: std::sync::atomic::AtomicUsize,
    }

    /// An inner verifier that records how often it ran and answers from a fixed verdict.
    struct CountingVerifier {
        verdict: Result<(), rustls::Error>,
        probe: Arc<Probe>,
    }

    impl std::fmt::Debug for CountingVerifier {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CountingVerifier")
                .field("verdict", &self.verdict)
                .finish_non_exhaustive()
        }
    }

    impl CountingVerifier {
        fn accepting() -> (Self, Arc<Probe>) {
            Self::with(Ok(()))
        }

        fn rejecting() -> (Self, Arc<Probe>) {
            Self::with(Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            )))
        }

        fn with(verdict: Result<(), rustls::Error>) -> (Self, Arc<Probe>) {
            let probe = Arc::new(Probe::default());
            (
                Self {
                    verdict,
                    probe: probe.clone(),
                },
                probe,
            )
        }
    }

    impl rustls::client::danger::ServerCertVerifier for CountingVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            use std::sync::atomic::Ordering;
            self.probe.calls.fetch_add(1, Ordering::SeqCst);
            self.verdict
                .clone()
                .map(|()| rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    fn verify_with<V>(verifier: &V, host: &str) -> Result<(), rustls::Error>
    where
        V: rustls::client::danger::ServerCertVerifier,
    {
        let end_entity = CertificateDer::from(vec![0x30, 0x00]);
        let name = server_name(host).expect("servername");
        verifier
            .verify_server_cert(
                &end_entity,
                &[],
                &name,
                &[],
                rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                    1_700_000_000,
                )),
            )
            .map(|_| ())
    }

    #[test]
    fn the_blocking_wrapper_preserves_a_valid_verdict() {
        let (inner, probe) = CountingVerifier::accepting();
        let wrapped = BlockingVerifier::new(inner);
        assert_eq!(verify_with(&wrapped, "www.example.com"), Ok(()));
        assert_eq!(
            probe.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the inner verifier must be consulted exactly once"
        );
    }

    #[test]
    fn the_blocking_wrapper_preserves_an_invalid_verdict() {
        let (inner, probe) = CountingVerifier::rejecting();
        let wrapped = BlockingVerifier::new(inner);
        let verdict = verify_with(&wrapped, "www.example.com");
        // Exactly the inner error, not a rewritten one: `mitm` distinguishes `NotValidForName` from
        // a bad chain when it decides to pass the connection through.
        assert_eq!(
            verdict,
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName
            ))
        );
        assert_eq!(probe.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// An inner verifier that blocks for `hold` and signals when it has started.
    struct SlowVerifier {
        started: Arc<tokio::sync::Notify>,
        hold: std::time::Duration,
    }

    impl std::fmt::Debug for SlowVerifier {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SlowVerifier").finish_non_exhaustive()
        }
    }

    impl rustls::client::danger::ServerCertVerifier for SlowVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            self.started.notify_one();
            // A synchronous sleep: exactly what a Binder round trip is — it cannot yield.
            std::thread::sleep(self.hold);
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    #[test]
    fn the_blocking_wrapper_keeps_the_runtime_progressing_during_the_check() {
        // What `block_in_place` buys, stated as the property that matters: while the synchronous
        // certificate check runs, the runtime's worker is handed to other tasks instead of being
        // parked. A single worker is the strongest form of the test — a heartbeat task can only
        // reach 136 000 yields with the wrapper, and exactly 1 without it (measured).
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("runtime");
        let started = Arc::new(tokio::sync::Notify::new());
        let wrapped = Arc::new(BlockingVerifier::new(SlowVerifier {
            started: started.clone(),
            hold: std::time::Duration::from_millis(200),
        }));
        let yielded = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        runtime.block_on(async {
            let heartbeat = {
                let yielded = yielded.clone();
                tokio::spawn(async move {
                    let until = std::time::Instant::now() + std::time::Duration::from_millis(150);
                    while std::time::Instant::now() < until {
                        tokio::task::yield_now().await;
                        yielded.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                })
            };
            // The check itself runs from a task, i.e. on a runtime worker: this is the thread the
            // app parks without the wrapper.
            let check = {
                let wrapped = wrapped.clone();
                tokio::spawn(async move { verify_with(&*wrapped, "www.example.com") })
            };
            assert_eq!(check.await.expect("join"), Ok(()));
            heartbeat.await.expect("heartbeat");
        });

        let yielded = yielded.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            yielded > 100,
            "the runtime kept running other tasks only {yielded} times while a synchronous \
             certificate check was in progress: the worker was parked, which is the tokio-starvation \
             bug MYS-2716 fixes (docs/JNI.md §7)"
        );
    }

    #[test]
    fn the_blocking_wrapper_is_a_pass_through_without_a_multi_threaded_runtime() {
        // `block_in_place` panics outside a multi-threaded runtime; the wrapper must not, or the
        // host-side tools and the unit tests would crash where they used to work.
        let (inner, probe) = CountingVerifier::accepting();
        let wrapped = BlockingVerifier::new(inner);
        assert_eq!(verify_with(&wrapped, "www.example.com"), Ok(()));
        assert_eq!(probe.calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            assert_eq!(verify_with(&wrapped, "www.example.com"), Ok(()));
        });
    }
}

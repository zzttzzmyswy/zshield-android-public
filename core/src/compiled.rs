//! The precompiled rule products and their on-disk envelope.
//!
//! Rationale (`docs/DESIGN.md` fixed decision 6): parsing a few million filter lines at every app
//! start is wasted work. The subscription system compiles once per rule change and the tunnel then
//! loads serialized artifacts:
//!
//! | File | Content | Produced by |
//! |---|---|---|
//! | `dns.bin` | the [`Filter`] the DNS layer consults | [`compile`](crate::compile) |
//! | `engine.bin` | a serialized adblock-rust `Engine` for M2/M3 | [`compile`](crate::compile) |
//!
//! Both are wrapped in the same [`Envelope`]: magic, format version, payload length and a CRC32 of
//! the payload. A file whose header does not match is rejected with an error instead of being
//! trusted — the Kotlin side then triggers a recompile (task card §4). Nothing here ever panics on
//! malformed input: a corrupt artifact must degrade to "recompile", never to a crash.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::dns::filter::Filter;

/// File name of the serialized DNS filter inside `files/compiled/`.
pub const DNS_FILE: &str = "dns.bin";
/// File name of the serialized adblock-rust engine inside `files/compiled/`.
pub const ENGINE_FILE: &str = "engine.bin";
/// File name of the rule text for the modifiers this core evaluates itself (`docs/JNI.md` §"$popup").
///
/// Text rather than a compiled blob: the rule sets are tiny (a few thousand lines), rebuilding them
/// costs milliseconds, and keeping the original lines means a rebuild after an upgrade of this core
/// uses the same rules instead of an opaque format an older version wrote.
pub const EXTRAS_FILE: &str = "extras.txt";

/// Magic of the DNS artifact. Distinct per artifact kind so the two files cannot be swapped.
const DNS_MAGIC: [u8; 8] = *b"ZSDNS\0\0\x01";
/// Magic of the adblock engine artifact.
const ENGINE_MAGIC: [u8; 8] = *b"ZSENG\0\0\x01";
/// Magic of the self-evaluated-modifier rule text.
const EXTRAS_MAGIC: [u8; 8] = *b"ZSEXT\0\0\x01";

/// Bumped whenever the payload layout or the rule semantics change in a way an old file would get
/// wrong. A mismatch is a normal, recoverable condition (recompile), so the value lives next to the
/// reader and the writer in this file only.
pub const FORMAT_VERSION: u16 = 1;

/// Header length: magic (8) + version (2) + reserved (2) + payload length (4) + CRC32 (4).
const HEADER_LEN: usize = 20;

/// Which artifact a header belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Artifact {
    Dns,
    Engine,
    Extras,
}

/// What an identity token prints for a component that is not installed at all.
///
/// A missing component is an *observation*, not the same thing as an unobserved one: the readiness
/// check refuses a run whose target rule set includes a component the log does not report, so the
/// difference between "absent" and "not reported" has to be visible in the line itself.
pub const ABSENT: &str = "-";

/// Stable content identity of one rule artifact's **payload**.
///
/// Why the payload and not the file: the envelope header carries the payload length and a CRC32,
/// which is a *description* of the payload rather than a cryptographic identity of it, and the
/// stage-4 review rejected "the artifact is N bytes" as a stand-in for "these are the rules under
/// measurement". This is SHA-256 over the bytes the loader actually deserialized, so the identity
/// describes the rule set in force rather than the file that happened to be on disk a moment later.
///
/// Cost and ownership: computed from the buffer the loader already holds — never by re-reading the
/// file — so a 41 MB `engine.bin` is hashed once on the load path (~40 ms on a Pixel 5 core, once per
/// start or successful swap) and the buffer is then dropped as before. No copy is retained: the
/// token is 64 hex characters plus a count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadIdentity {
    /// The number of payload bytes that were hashed.
    pub bytes: u64,
    /// Lower-case hex SHA-256 of exactly those bytes.
    pub sha256_hex: String,
}

impl PayloadIdentity {
    /// Identity of a payload the caller has already read.
    pub fn of_payload(payload: &[u8]) -> Self {
        Self {
            bytes: payload.len() as u64,
            // `ring` is already linked into this crate (it is the TLS backend's crypto and the entropy
            // source for the CA), and it is the implementation to use here for a measured reason: on
            // the release profile this crate builds with (`opt-level = "z"`, LTO), `sha2`'s portable
            // backend runs at 60 MB/s while `ring`'s assembly runs at 400 MB/s — 124 ms versus 19 ms
            // for a 7.4 MB engine artifact. A load path may not spend 100 ms on a log field.
            sha256_hex: hex(ring::digest::digest(&ring::digest::SHA256, payload).as_ref()),
        }
    }

    /// The identity of a file's payload as it is on disk **right now**.
    ///
    /// Only for callers that have no reason to hold the payload: the compile side after it wrote the
    /// artifact, and tests. A load path must use [`of_payload`](Self::of_payload) on the buffer it
    /// installed — re-reading would let a file that changed between load and hash be reported as the
    /// content in force, which is exactly the misreporting this exists to prevent.
    pub fn of_file(path: &Path, artifact: Artifact) -> Result<Self, ArtifactError> {
        let payload = Envelope::read_payload(path, artifact)?;
        Ok(Self::of_payload(&payload))
    }

    /// `sha256:<hex>:<bytes>` — one whitespace-free token, so a log line splits into fields.
    pub fn token(&self) -> String {
        format!("sha256:{}:{}", self.sha256_hex, self.bytes)
    }
}
/// The three artifacts the running engine's rule set is made of, as actually installed.
///
/// They are reported separately rather than folded into one "rule set id" because the compile writes
/// three files and a start or swap reads them one at a time: if the files were updated between two
/// of those reads, the engine really is running a mixture, and an observation that collapsed them
/// into a single id would hide exactly that. The consumer compares each component against the
/// target build's manifest and refuses on any disagreement (see `scripts/effectiveness/pss_idle.sh`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentitySet {
    pub dns: Option<PayloadIdentity>,
    pub engine: Option<PayloadIdentity>,
    pub extras: Option<PayloadIdentity>,
}

impl IdentitySet {
    /// `dns=<token> engine=<token> extras=<token>`, absent components rendered as [`ABSENT`].
    pub fn render(&self) -> String {
        fn one(name: &str, identity: &Option<PayloadIdentity>) -> String {
            match identity {
                Some(identity) => format!("{name}={}", identity.token()),
                None => format!("{name}={ABSENT}"),
            }
        }
        format!(
            "{} {} {}",
            one("dns", &self.dns),
            one("engine", &self.engine),
            one("extras", &self.extras)
        )
    }
}

/// Lower-case hex, the spelling the CA fingerprint and this token both use.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

impl Artifact {
    pub fn file_name(self) -> &'static str {
        match self {
            Artifact::Dns => DNS_FILE,
            Artifact::Engine => ENGINE_FILE,
            Artifact::Extras => EXTRAS_FILE,
        }
    }

    fn magic(self) -> [u8; 8] {
        match self {
            Artifact::Dns => DNS_MAGIC,
            Artifact::Engine => ENGINE_MAGIC,
            Artifact::Extras => EXTRAS_MAGIC,
        }
    }
}

/// A versioned envelope around a serialized artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub artifact: Artifact,
    pub format_version: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    /// The file does not start with the expected magic.
    BadMagic,
    /// The file was written by an incompatible format version.
    VersionMismatch { found: u16, expected: u16 },
    /// The payload length in the header does not match the file.
    Truncated { expected: usize, found: usize },
    /// The CRC32 in the header does not match the payload.
    BadChecksum,
    /// The payload itself could not be interpreted.
    Corrupt(String),
    /// I/O failure reading or writing.
    Io(String),
}

impl std::fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactError::BadMagic => write!(f, "bad magic (not a ZShield artifact)"),
            ArtifactError::VersionMismatch { found, expected } => {
                write!(f, "format version {found} != {expected}, recompile required")
            }
            ArtifactError::Truncated { expected, found } => {
                write!(f, "truncated: header says {expected} bytes, file has {found}")
            }
            ArtifactError::BadChecksum => write!(f, "payload checksum mismatch"),
            ArtifactError::Corrupt(msg) => write!(f, "corrupt payload: {msg}"),
            ArtifactError::Io(msg) => write!(f, "io: {msg}"),
        }
    }
}

impl std::error::Error for ArtifactError {}

impl Envelope {
    pub fn new(artifact: Artifact, payload: Vec<u8>) -> Self {
        Self {
            artifact,
            format_version: FORMAT_VERSION,
            payload,
        }
    }

    /// Serialize header + payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.artifact.magic());
        out.extend_from_slice(&self.format_version.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // reserved
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&crc32(&self.payload).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Read a header + payload, rejecting anything that is not a valid artifact of `artifact`.
    pub fn decode(artifact: Artifact, raw: &[u8]) -> Result<Self, ArtifactError> {
        Self::validate(artifact, raw)?;
        Ok(Self {
            artifact,
            format_version: FORMAT_VERSION,
            payload: raw[HEADER_LEN..].to_vec(),
        })
    }

    /// The identity of an artifact on disk, without reading its payload.
    ///
    /// `(payload length, CRC32 of the payload)` — both are already in the header, so this is a
    /// 20-byte read. It is what [`crate::jni_api::reload_engine`] uses to tell "the compile produced
    /// a different rule set" from "the compile ran again and wrote the same bytes".
    ///
    /// Not the file's mtime: this app recompiles on every start, so the mtime changes on every start
    /// even when the rules do not — which is exactly the case the check exists for.
    pub fn identity(path: &Path, artifact: Artifact) -> Result<(u32, u32), ArtifactError> {
        use std::io::Read;
        let mut header = [0u8; HEADER_LEN];
        let mut file = std::fs::File::open(path)
            .map_err(|e| ArtifactError::Io(format!("cannot open {}: {e}", path.display())))?;
        file.read_exact(&mut header)
            .map_err(|e| ArtifactError::Io(format!("cannot read {}: {e}", path.display())))?;
        if header[0..8] != artifact.magic() {
            return Err(ArtifactError::BadMagic);
        }
        let declared = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        let checksum = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
        Ok((declared, checksum))
    }

    /// Read and decode a file.
    pub fn read(path: &Path, artifact: Artifact) -> Result<Self, ArtifactError> {
        let raw = std::fs::read(path)
            .map_err(|e| ArtifactError::Io(format!("cannot read {}: {e}", path.display())))?;
        Self::decode(artifact, &raw)
    }

    /// Read a file and return just its payload, validated, without copying it a second time.
    ///
    /// [`read`](Self::read) reads the file into one buffer and then `to_vec`s the payload out of it,
    /// so a 41 MB `engine.bin` briefly holds 82 MB. This strips the 20-byte header in place with a
    /// single `drain`, leaving exactly one allocation of the payload's size. `docs/PERF.md` §14
    /// records the cold-start peak both ways.
    pub fn read_payload(path: &Path, artifact: Artifact) -> Result<Vec<u8>, ArtifactError> {
        let mut raw = std::fs::read(path)
            .map_err(|e| ArtifactError::Io(format!("cannot read {}: {e}", path.display())))?;
        Self::validate(artifact, &raw)?;
        raw.drain(..HEADER_LEN);
        Ok(raw)
    }

    /// Header validation shared by [`decode`](Self::decode) and
    /// [`read_payload`](Self::read_payload); checks magic, version, length and checksum.
    fn validate(artifact: Artifact, raw: &[u8]) -> Result<(), ArtifactError> {
        if raw.len() < HEADER_LEN {
            return Err(ArtifactError::Truncated {
                expected: HEADER_LEN,
                found: raw.len(),
            });
        }
        if raw[0..8] != artifact.magic() {
            return Err(ArtifactError::BadMagic);
        }
        let format_version = u16::from_le_bytes([raw[8], raw[9]]);
        if format_version != FORMAT_VERSION {
            return Err(ArtifactError::VersionMismatch {
                found: format_version,
                expected: FORMAT_VERSION,
            });
        }
        let declared = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]) as usize;
        let checksum = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]);
        let payload = &raw[HEADER_LEN..];
        if payload.len() != declared {
            return Err(ArtifactError::Truncated {
                expected: declared,
                found: payload.len(),
            });
        }
        if crc32(payload) != checksum {
            return Err(ArtifactError::BadChecksum);
        }
        Ok(())
    }

    /// Write the artifact atomically (`.tmp` + rename), so a reader never sees a half-written file.
    ///
    /// The header is written first and the payload streamed straight from `self.payload`, never
    /// concatenated into a second buffer: `engine.bin` is 41 MB, and an extra full-size copy is both
    /// a 41 MB allocation at the worst possible moment (right after `Engine::serialize` has already
    /// produced it) and a 41 MB `memcpy`. `docs/PERF.md` §14 measures the compile peak before and
    /// after.
    pub fn write_atomic(&self, path: &Path) -> Result<usize, ArtifactError> {
        let tmp = tmp_path(path);
        let mut header = [0u8; HEADER_LEN];
        header[0..8].copy_from_slice(&self.artifact.magic());
        header[8..10].copy_from_slice(&self.format_version.to_le_bytes());
        // header[10..12] stays zero (reserved).
        header[12..16].copy_from_slice(&(self.payload.len() as u32).to_le_bytes());
        header[16..20].copy_from_slice(&crc32(&self.payload).to_le_bytes());
        let written = {
            let mut file = std::fs::File::create(&tmp).map_err(|e| {
                ArtifactError::Io(format!("cannot create {}: {e}", tmp.display()))
            })?;
            file.write_all(&header)
                .and_then(|()| file.write_all(&self.payload))
                .map_err(|e| {
                    ArtifactError::Io(format!("cannot write {}: {e}", tmp.display()))
                })?;
            file.sync_all().map_err(|e| {
                ArtifactError::Io(format!("cannot sync {}: {e}", tmp.display()))
            })?;
            HEADER_LEN + self.payload.len()
        };
        std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            ArtifactError::Io(format!(
                "cannot rename {} -> {}: {e}",
                tmp.display(),
                path.display()
            ))
        })?;
        Ok(written)
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Serialize a compiled DNS filter into `dns.bin` bytes.
pub fn encode_dns(filter: &Filter) -> Vec<u8> {
    Envelope::new(Artifact::Dns, filter.encode_payload()).encode()
}

/// Load a `dns.bin` file back into a [`Filter`].
///
/// The payload is self-describing (it carries its own rule statistics), so nothing outside the
/// artifact is needed to restore a filter that reports the same counts it was compiled with.
pub fn decode_dns(raw: &[u8]) -> Result<Filter, ArtifactError> {
    let envelope = Envelope::decode(Artifact::Dns, raw)?;
    Filter::decode_payload(&envelope.payload).map_err(ArtifactError::Corrupt)
}

/// CRC32 (IEEE 802.3), the same polynomial ZIP and PNG use.
///
/// A table-driven implementation is ~40 lines and avoids a dependency; it runs once per artifact
/// write and once per load over a few MB, which is far below the cost of parsing the lists.
pub fn crc32(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = build_crc32_table();
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc = (crc >> 8) ^ TABLE[((crc ^ *byte as u32) & 0xff) as usize];
    }
    !crc
}

const fn build_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0usize;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 {
                0xedb8_8320 ^ (value >> 1)
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::filter::Verdict;

    fn sample_filter() -> Filter {
        let mut filter = Filter::new();
        filter.load_text(
            "||blocked.example^\n\
             @@||allowed.example^\n\
             ||important.example^$important\n\
             0.0.0.0 hosts.example\n\
             |exact.example^\n\
             0.0.0.0 93.184.216.34\n",
        );
        filter.add_allowlist(["user-allowed.example"]);
        filter
    }

    #[test]
    fn crc32_matches_known_vectors() {
        // Standard test vectors for CRC-32/ISO-HDLC.
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b"hello"), 0x3610_a686);
    }

    #[test]
    fn envelope_round_trips() {
        let envelope = Envelope::new(Artifact::Dns, b"payload".to_vec());
        let encoded = envelope.encode();
        let decoded = Envelope::decode(Artifact::Dns, &encoded).expect("decode");
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let envelope = Envelope::new(Artifact::Dns, b"payload".to_vec());
        let encoded = envelope.encode();
        // An engine artifact handed to the DNS reader must be refused even though the envelope is
        // structurally valid: the two payload formats are not interchangeable.
        let err = Envelope::decode(Artifact::Engine, &encoded).expect_err("must fail");
        assert_eq!(err, ArtifactError::BadMagic);

        let mut corrupted = encoded;
        corrupted[0] = b'X';
        let err = Envelope::decode(Artifact::Dns, &corrupted).expect_err("must fail");
        assert_eq!(err, ArtifactError::BadMagic);
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let mut encoded = Envelope::new(Artifact::Dns, b"payload".to_vec()).encode();
        encoded[8..10].copy_from_slice(&(FORMAT_VERSION + 1).to_le_bytes());
        let err = Envelope::decode(Artifact::Dns, &encoded).expect_err("must fail");
        assert!(matches!(err, ArtifactError::VersionMismatch { .. }), "{err:?}");
        assert!(err.to_string().contains("recompile"), "{err}");
    }

    #[test]
    fn truncated_and_corrupted_payloads_are_rejected() {
        let encoded = Envelope::new(Artifact::Dns, b"payload".to_vec()).encode();
        let err = Envelope::decode(Artifact::Dns, &encoded[..encoded.len() - 2]).expect_err("short");
        assert!(matches!(err, ArtifactError::Truncated { .. }), "{err:?}");

        let err = Envelope::decode(Artifact::Dns, &encoded[..4]).expect_err("too short");
        assert!(matches!(err, ArtifactError::Truncated { .. }), "{err:?}");

        let mut flipped = encoded.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0xff;
        let err = Envelope::decode(Artifact::Dns, &flipped).expect_err("corrupt");
        assert_eq!(err, ArtifactError::BadChecksum);
    }

    #[test]
    fn dns_artifact_round_trip_preserves_every_verdict() {
        let filter = sample_filter();
        let encoded = encode_dns(&filter);
        let restored = decode_dns(&encoded).expect("decode");

        for name in [
            "blocked.example",
            "sub.blocked.example",
            "allowed.example",
            "sub.allowed.example",
            "important.example",
            "hosts.example",
            "exact.example",
            "sub.exact.example",
            "user-allowed.example",
            "93.184.216.34",
            "clean.example",
        ] {
            assert_eq!(
                filter.match_domain(name),
                restored.match_domain(name),
                "verdict changed for {name}"
            );
        }
        assert_eq!(
            restored.match_domain("user-allowed.example"),
            Verdict::Allow,
            "the user allowlist must survive serialization"
        );
        assert_eq!(restored.stats().block_rules, filter.stats().block_rules);
    }

    #[test]
    fn dns_artifact_survives_a_corrupted_body_of_the_right_length() {
        // Same length, wrong bytes: only the checksum can catch this.
        let filter = sample_filter();
        let mut encoded = encode_dns(&filter);
        let last = encoded.len() - 1;
        encoded[last] = b'Z';
        let err = decode_dns(&encoded).expect_err("must fail");
        assert_eq!(err, ArtifactError::BadChecksum);
    }

    #[test]
    fn artifacts_are_written_atomically() {
        let dir = std::env::temp_dir().join(format!("zshield-artifact-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(DNS_FILE);

        let envelope = Envelope::new(Artifact::Dns, b"first".to_vec());
        envelope.write_atomic(&path).expect("write");
        assert!(!dir.join("dns.bin.tmp").exists(), "temporary file must not remain");

        let second = Envelope::new(Artifact::Dns, b"second-payload".to_vec());
        second.write_atomic(&path).expect("rewrite");
        let read_back = Envelope::read(&path, Artifact::Dns).expect("read");
        assert_eq!(read_back.payload, b"second-payload");

        std::fs::remove_dir_all(&dir).ok();
    }
}

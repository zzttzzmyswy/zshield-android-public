//! HTTPS filtering (M3a, `docs/ROADMAP.md`).
//!
//! The plaintext pipeline of M2b (`crate::http`) already knows how to judge one request and answer
//! it. What M3a adds is the layer in front of it:
//!
//! ```text
//! TUN ─▶ sniff (SNI + ALPN + ClientHello bytes)
//!          │
//!          ├─ not selected (not a browser / excluded host / auto-bypassed) ─▶ verbatim passthrough
//!          │
//!          └─ selected ─▶ upstream TLS with the client's SNI+ALPN, verified normally
//!                            │
//!                            ├─ upstream invalid ─▶ passthrough (client sees the real certificate)
//!                            │
//!                            └─ ok ─▶ client TLS with a leaf for that SNI
//!                                       ├─ h2  ─▶ per-stream decision, forward the rest
//!                                       └─ h1.1 ─▶ crate::http::relay (scheme https)
//! ```
//!
//! Module map:
//! - [`ca`] — the root CA, its persistence contract and the per-SNI leaf cache;
//! - [`policy`] — *which* connections are decrypted (browser list, user packages, excluded hosts,
//!   auto-bypass) and the short-lived owner-uid cache;
//! - [`modifiers`] — the decrypted-only rule modifiers (`$removeparam`, `$removeheader`, `$csp`,
//!   `$redirect` already lives in `http::decision`);
//! - [`extras`] — the modifiers the pinned engine *rejects* and this core evaluates itself (`$popup`,
//!   `$denyallow`, `$removeparam=<regex>`);
//! - [`entity_domains`] — `$domain=example.*`, which the engine parses but can never match;
//! - [`tls`] — the rustls client/server configuration: platform-verified upstream, leaf-signed
//!   downstream;
//! - [`h2`] — the HTTP/2 leg: one connection, one decision per stream;
//! - [`mitm`] — the state machine that ties the above together for one tunnelled connection;
//! - [`stats`] — the HTTPS counters `statsJson` reports.

pub mod ca;
pub mod entity_domains;
pub mod extras;
pub mod h2;
pub mod mitm;
pub mod modifiers;
pub mod policy;
pub mod stats;
pub mod tls;

pub use ca::{Ca, CaError, CaInfo, GeneratedCa, LeafCert};
pub use extras::ExtraModifiers;
pub use mitm::{HttpsContext, HttpsOutcome};
pub use policy::{
    AutoBypass, ClientFailure, HandshakePhase, HttpsPolicy, OwnerLookup, UidSelection, Verdict,
};
pub use stats::{HttpsSnapshot, HttpsStats};

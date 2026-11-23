//! Plaintext HTTP filtering: the request model, the decision, and the keep-alive pipeline.
//!
//! This is the layer M3 (`docs/ROADMAP.md`) reuses: once the MITM side can hand over an
//! already-decrypted request, the URL/source/type model, the adblock decision and the synthetic
//! responses below apply unchanged. Only the transport (TLS-terminated streams instead of a plain
//! `TcpStream`) differs, which is why nothing here knows about the tunnel, smoltcp or sockets.
//!
//! Module map:
//! - [`head`] — incremental HTTP/1.x request-head parsing (request line + the headers the decision
//!   needs), including the bounded-buffer rejection of oversized heads;
//! - [`resource`] — request-type inference from `Sec-Fetch-Dest` / `Accept`;
//! - [`decision`] — [`FilterDecision`] and the adblock-rust query that produces it;
//! - [`resources`] — the built-in `$redirect` substitutes (`noopjs`, `noopcss`, `1x1.gif`, ...);
//! - [`response`] — the synthesized responses (403 page, empty 204, redirect body);
//! - [`relay`] — the per-connection keep-alive loop that ties the above together;
//! - [`engine`] — runtime loading / hot replacement of `engine.bin`;
//! - [`log`] — the bounded recent-request ring buffer behind `recentRequestsJson`.
//!
//! Design notes that are easy to get wrong (`docs/DESIGN.md` decision 6, task card §2):
//!
//! - **A missing `Referer` means first-party, not third-party.** adblock-rust's
//!   `Request::new` treats a source URL it cannot parse as third-party, which would make every
//!   `$third-party` rule fire on requests that simply carry no referrer. [`decision`] therefore
//!   constructs requests through `Request::preparsed` and states the party explicitly.
//! - **Nothing here blocks on a guess.** A head that does not parse, a `CONNECT`, an `Upgrade`, or
//!   an HTTP/2 preface falls back to byte-for-byte relaying — the tunnel never becomes the reason a
//!   site stops working.

pub mod body;
pub mod decision;
pub mod engine;
pub mod head;
pub mod log;
pub mod relay;
pub mod resource;
pub mod resources;
pub mod response;
pub mod rewrite;
pub mod responses;

pub use decision::{FilterDecision, HttpFilter, RedirectBody};
pub use engine::{LAST_ENGINE_BYTES, LAST_ENGINE_LOAD_MICROS};
pub use head::{HttpRequest, ParsedHead, ParseResult, Version};
pub use log::{
    BlockReason, LogKind, RequestLog, RequestLogEntry, RequestOutcome, MAX_LOGGED_URL,
    QUIC_DEDUPE_WINDOW, REASON_CNAME, REQUEST_LOG_CAPACITY,
};
pub use body::{ChunkProgress, ChunkedScanner};
pub use relay::{HttpContext, HttpStats, RelayOutcome};
pub use responses::{BodyRule, Progress, ResponseTracker};
pub use rewrite::{Edits, ModifierSource, ResponseRewriter};
pub use resource::RequestKind;

#[cfg(test)]
mod e2e_tests;

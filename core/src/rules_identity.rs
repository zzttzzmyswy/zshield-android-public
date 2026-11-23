//! Which rule content is in force, in a form a measurement can pin and a script can parse.
//!
//! # Why this module exists
//!
//! Stage 4 delivered a PSS measurement that could not answer the one question its own acceptance
//! criterion asks: *was the sample taken while this run's rule set was in force?* The tooling checked
//! a PID and a readiness line, and the delivered evidence compared **artifact byte counts and rule
//! counts** against the target. The stage-4 review rejected that on a concrete counter-example: two
//! rule sets of the same length and the same rule count produce the same numbers and different rules,
//! so a byte count cannot distinguish "the rules I meant to measure" from "some other rules of the
//! same size". Reviewing the tool alone could not fix it — the numbers existed because the core never
//! observed what it had installed — so the observation is added here, where the bytes are.
//!
//! # What is observed, and when
//!
//! The identity of a rule set is the SHA-256 of each artifact's **payload** as the loader installed it:
//! `dns.bin` (hostname rules), `engine.bin` (the network-rule engine) and `extras.txt` (the modifiers
//! this core evaluates itself). All three travel together through one compile, so all three are
//! reported: a start that installed a newer `engine.bin` over an older `dns.bin` is a mixture, and a
//! single fused id would hide it.
//!
//! The cost is paid **only on the paths that already read the bytes**: a start, and a successful
//! reload. The hash is taken from the buffer the loader is about to consume, so nothing is read twice,
//! no request-path work is added, and no copy of the rules is kept — a [`PayloadIdentity`] is 64 hex
//! characters and a byte count. Nothing here runs per request.
//!
//! # What a generation means
//!
//! [`RulesState::generation`] is a counter over *successful* installs on one handle: `1` is what the
//! first `start` installs, and each successful swap takes the next value. A failed load or a failed
//! swap takes none — it leaves the previous identity and generation in force, which is the truth, and
//! emits the `ok=false` variant of the line saying so. That is what makes "this batch of samples
//! belongs to generation N" checkable instead of assumed: a swap that lands between two samples
//! changes the generation, and the measurement can be discarded rather than silently mixing two rule
//! sets.
//!
//! # What is printed
//!
//! One line per event, tagged so it cannot be confused with the older free-form lines:
//!
//! ```text
//! rules identity: event=start ok=true handle=1 generation=1 pid=4242 dns=sha256:<hex>:<bytes> engine=sha256:<hex>:<bytes> extras=sha256:<hex>:<bytes>
//! rules identity: event=swap ok=true handle=1 generation=2 pid=4242 dns=… engine=… extras=…
//! rules identity: event=swap ok=false handle=1 generation=1 pid=4242 reason=dns:no dns.bin in /data/…
//! ```
//!
//! Only hashes, counts and handles: no rule text, no URL, no key material. `extras.txt` is the one
//! artifact that carries original rule lines, and it is hashed, never echoed.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::compiled::{IdentitySet, PayloadIdentity};

/// The log tag every identity line starts with. A consumer matches this exact prefix, so a
/// free-form line that happens to mention a hash cannot be mistaken for an observation.
pub const LINE_PREFIX: &str = "rules identity:";

/// Process-wide monotonic counter, so two handles' generations are still totally ordered in one
/// logcat stream even though `handle` alone would only order installs within one tunnel.
///
/// It is not the identity a consumer keys on (that is `handle` + `generation`); it exists so a reader
/// can tell which of two lines from two handles came first.
static LAST_GENERATION: AtomicU64 = AtomicU64::new(0);

/// What one handle has in force. `generation` is 0 before the first successful install.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulesState {
    pub generation: u64,
    pub identities: IdentitySet,
}

impl RulesState {
    /// Record a successful install of `identities` and return the new generation.
    pub fn installed(&mut self, identities: IdentitySet) -> u64 {
        self.generation = LAST_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        self.identities = identities;
        self.generation
    }
}

/// The rule content a start or swap installed, for one event line.
#[derive(Debug, Clone)]
pub struct IdentityEvent {
    /// `start` or `swap`.
    pub event: &'static str,
    pub ok: bool,
    pub handle: u64,
    /// The generation in force after this event. On `ok=false` it is the **unchanged** previous one:
    /// a failure never advances it.
    pub generation: u64,
    pub identities: IdentitySet,
    /// Why the event failed. Only on `ok=false`, and never contains rule text or a URL.
    pub reason: Option<String>,
}

impl IdentityEvent {
    /// The single, parseable line described in the module docs.
    pub fn render(&self, pid: u32) -> String {
        let mut line = format!(
            "{LINE_PREFIX} event={} ok={} handle={} generation={} pid={pid} {}",
            self.event,
            self.ok,
            self.handle,
            self.generation,
            self.identities.render()
        );
        if let Some(reason) = &self.reason {
            // The reason is a loader error message (a path, a deserialize failure). Spaces would make
            // the field unparseable, so they become `_`; the line stays one field per token.
            line.push_str(&format!(" reason={}", one_token(reason)));
        }
        line
    }

    /// Log it. The caller decides *when* — after the install, never before.
    pub fn log(&self) {
        crate::log_msg("info", &self.render(std::process::id()));
    }
}

/// Replace whitespace so a free-form reason stays a single log token.
fn one_token(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_whitespace() {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    out
}

/// Collect an identity for each component that was installed, from the identities the loaders
/// produced. `None` for a component is reported as absent, never filled in from the file on disk.
pub fn identities(
    dns: Option<PayloadIdentity>,
    engine: Option<PayloadIdentity>,
    extras: Option<PayloadIdentity>,
) -> IdentitySet {
    IdentitySet {
        dns,
        engine,
        extras,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: &[u8]) -> PayloadIdentity {
        PayloadIdentity::of_payload(seed)
    }

    #[test]
    fn a_line_is_one_token_per_field() {
        let event = IdentityEvent {
            event: "swap",
            ok: false,
            handle: 3,
            generation: 7,
            identities: identities(
                Some(identity(b"dns payload")),
                None,
                Some(identity(b"popup.example##.ad")),
            ),
            reason: Some("engine: cannot deserialize the engine: bad".to_string()),
        };
        let line = event.render(4242);
        assert!(
            line.starts_with("rules identity: event=swap ok=false handle=3 generation=7 pid=4242")
        );
        assert!(line.contains(" dns=sha256:"), "{line}");
        // A component that is not installed is *reported* as absent rather than omitted: a consumer
        // has to be able to tell "no extras" from "this build does not say".
        assert!(line.contains(" engine=-"), "{line}");
        assert!(
            line.contains(" reason=engine:_cannot_deserialize"),
            "{line}"
        );
        // `rules identity:` (2) + event/ok/handle/generation/pid (5) + three components (3) + reason
        // (1): the reason's spaces were folded, so it cannot split a reader's field parse.
        assert_eq!(
            line.split_whitespace().count(),
            11,
            "the reason must not add tokens: {line}"
        );
    }

    #[test]
    fn the_token_carries_the_hash_and_the_length() {
        let token = identity(b"abc").token();
        assert!(token.starts_with(
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad:"
        ));
        assert!(token.ends_with(":3"), "{token}");
    }

    #[test]
    fn a_generation_only_advances_on_a_successful_install() {
        let mut state = RulesState::default();
        assert_eq!(
            state.generation, 0,
            "nothing is installed before the first start"
        );
        let first = state.installed(identities(Some(identity(b"one")), None, None));
        assert!(first > 0);
        assert_eq!(state.generation, first);
        // Recording the same identities again is a new install of the same content: the generation
        // still moves, because what it counts is *installs*, not content changes.
        let second = state.installed(identities(Some(identity(b"one")), None, None));
        assert!(second > first);
        assert_eq!(state.identities.dns.as_ref().unwrap().bytes, 3);
    }

    #[test]
    fn equal_length_different_content_has_different_identities() {
        // The counter-example the stage-4 review produced: same byte count, same rule count, other
        // rules. Length is not identity; the hash is.
        let a = identity(b"||a.example^\n");
        let b = identity(b"||b.example^\n");
        assert_eq!(a.bytes, b.bytes);
        assert_ne!(a.sha256_hex, b.sha256_hex);
        assert_ne!(a.token(), b.token());
    }
}

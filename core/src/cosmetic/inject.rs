//! The streaming cosmetic rewriter: one response in, the rewritten response out.
//!
//! [`Rewriter`] is fed the origin's response bytes as they arrive — head first, then body — and returns
//! the bytes to send to the client, in order, without ever buffering the whole document (task card §3):
//!
//! ```text
//! origin head ─▶ buffer until \r\n\r\n ─▶ 200 + HTML + a coding we decode?
//!                                          ├─ no  ─▶ relay verbatim, done
//!                                          └─ yes ─▶ buffer body until an insertion point is known
//!                                                     ├─ window full, no place ─▶ relay verbatim, done
//!                                                     └─ place found ─▶ rewrite head (drop CE/CL,
//!                                                        add chunked, extend CSP) ─▶ <style>/<script>
//!                                                        ─▶ scan class/id ─▶ generic <style> before
//!                                                        </body> ─▶ chunk (H1) / raw (H2)
//! ```
//!
//! # Nothing is written until the rewrite is certain
//!
//! Every output byte is held until the first decision is settled: a document this code cannot handle is
//! delivered **exactly as the origin sent it**, compressed bytes included, so the filter is never the
//! reason a page breaks. Keeping the origin's bytes while undecided is what makes that literal rather
//! than approximate. The only case that cannot be recovered is a body coding that turns out to be
//! corrupt *after* decoding started; that is reported as [`Emitted::broke`] so the caller closes the
//! connection instead of delivering half a document.

use crate::cosmetic::chunked::Dechunker;
use crate::cosmetic::csp::{self, Element};
use crate::cosmetic::gzip::{GzipDecoder, GzipProgress};
use crate::cosmetic::head::{self, Coding, OutFraming, ResponseHead};
use crate::cosmetic::scan::{self, AttributeScanner, Found};

/// How much of the origin's bytes the HTTP/1.1 driver keeps while injection is undecided.
///
/// The insert-point decision needs at most [`scan::SCAN_WINDOW`] of *decoded* body; a gzip stream of that
/// is normally far smaller, so twice the window bounds the compressed side comfortably. Past it the
/// origin's bytes are dropped: the response is no longer replayable, and holding an unbounded copy of a
/// large page is worse than losing a give-up path that is already unreachable at that size.
fn raw_cap() -> usize {
    2 * crate::cosmetic::scan::SCAN_WINDOW
}

/// How many selectors go into one CSS rule list. See [`style_element`].
const SELECTORS_PER_BLOCK: usize = 200;

/// The rules a document is injected with.
#[derive(Default, Clone)]
pub struct Plan {
    /// Selectors that apply to this document's hostname, already exception-filtered by the engine.
    pub hide_selectors: Vec<String>,
    /// Selectors this document's hostname explicitly *unhides* (`#@#`), which the generic query needs
    /// so an unhide rule is honoured.
    pub exceptions: std::collections::HashSet<String>,
    /// `#@#`/`*#@#` rules, which the pinned engine silently discards
    /// ([`crate::cosmetic::unhide`]).
    ///
    /// Applied here, on top of the engine's answer, because the engine cannot express a *global*
    /// unhide: `#@#.cls` is rejected outright and `*#@#.cls` parses into a location that never
    /// matches. Without this a list's "this class is not an ad anywhere" rule does nothing.
    pub global_unhides: std::sync::Arc<crate::cosmetic::unhide::GlobalUnhides>,
    /// The script the engine built from the `##+js(...)` rules; empty when there are none.
    pub injected_script: String,
    /// The procedural and action rules for this document, already screened
    /// ([`crate::cosmetic::procedural::Screen`]).
    ///
    /// Separate from [`hide_selectors`](Self::hide_selectors) because they cannot be expressed as
    /// CSS: they are applied by the runtime in [`crate::cosmetic::procedural`], which the document
    /// receives as one `<script>`.
    pub procedural: Vec<crate::cosmetic::procedural::Rule>,
    /// Procedural rules the engine offered but screening dropped, for the statistics.
    pub procedural_dropped: usize,
    /// `$generichide` applies: skip the generic class/id query.
    pub generichide: bool,
    /// The engine, for the generic query. `None` when there is no engine to ask.
    pub engine: Option<std::sync::Arc<adblock::Engine>>,
    /// `$removeheader` names to drop from the rewritten response head.
    pub drop_response_headers: Vec<String>,
    /// `$csp` directives to append to the response's policy.
    ///
    /// The filter's own directive, so it is sent verbatim and never relaxed with a nonce: a `$csp` rule
    /// asks for *more* restriction. An element the added policy would refuse is therefore not injected.
    pub extra_csp: Option<String>,
}

impl Plan {
    /// True when there is nothing this document could be injected with, so the response is untouched.
    pub fn is_empty(&self) -> bool {
        self.hide_selectors.is_empty()
            && self.injected_script.is_empty()
            && self.procedural.is_empty()
            && !self.uses_generic()
    }

    fn uses_generic(&self) -> bool {
        !self.generichide && self.engine.is_some()
    }

    fn style_wanted(&self) -> bool {
        !self.hide_selectors.is_empty()
    }
}


/// Where a body injector is in the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyPhase {
    /// Holding the prefix until an insertion point is known.
    Locate,
    /// Streaming the body.
    Body,
    /// Finished, given up, or broken.
    Done,
}

/// Rewrites one response **body**: decode, inject, reframe.
///
/// Protocol-agnostic on purpose: the head is the caller's business, because HTTP/1.1 parses it off the
/// wire and HTTP/2 builds it from a `HeaderMap`. What this type owns is the document — where the markup
/// goes, the `class`/`id` scan, and the output framing.
pub struct BodyInjector {
    plan: Plan,
    framing: OutFraming,
    coding: Coding,
    inflater: Option<GzipDecoder>,
    /// Compressed bytes belonging to whatever follows the gzip member (passed through at the end).
    decode_pending: Vec<u8>,
    phase: BodyPhase,
    /// The document prefix held while looking for the insertion point.
    prefix: Vec<u8>,
    /// Resumes the insert-point search instead of re-scanning the prefix on every feed.
    locator: scan::Locator,
    scanner: AttributeScanner,
    /// `nonce="…"` for the injected `<style>` / `<script>`.
    style_nonce: Option<String>,
    script_nonce: Option<String>,
    /// Whether the policies allow an injected `<style>` at all.
    ///
    /// A `<script>` the policies would refuse is dropped before it reaches this point: `new` clears
    /// `plan.injected_script` when a `$csp` rule refuses it, so there is nothing left to check.
    style_allowed: bool,
    /// The `Content-Security-Policy` values the response must carry.
    policies: Vec<String>,
    /// The `$removeheader` names the response head must drop.
    drop_headers: Vec<String>,
    /// Set once the markup that follows `<head>` has been written.
    head_markup_done: bool,
    /// Set once the generic `<style>` has been attempted.
    generic_done: bool,
    /// Compressed bytes dropped because they followed the gzip member (a second member, or junk).
    ///
    /// Counted rather than emitted: the response this core sends is chunked, and unframed bytes inside a
    /// chunked body are a framing error the client reports as a broken page.
    trailing_bytes: usize,
    /// The origin's framing broke part-way through the body, so what has been written is a prefix.
    truncated: bool,
    /// Injection was abandoned (no insertion point in the window): the body is still decoded and framed
    /// by this type, it just carries no injected markup.
    gave_up: bool,
    /// Set once the body has ended, so a second `finish` is a no-op.
    finished: bool,
    report: CosmeticReport,
}

impl std::fmt::Debug for BodyInjector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyInjector")
            .field("plan", &self.plan)
            .field("framing", &self.framing)
            .field("coding", &self.coding)
            .field("phase", &self.phase)
            .field("report", &self.report)
            .finish_non_exhaustive()
    }
}

impl BodyInjector {
    /// Prepare one document body. `None` when the plan has nothing to inject.
    ///
    /// `policies` are the origin's `Content-Security-Policy` values; the injector extends them with the
    /// nonces the injected elements carry (see [`crate::cosmetic::csp`]).
    pub fn new(plan: Plan, framing: OutFraming, coding: Coding, policies: &[String]) -> Option<Self> {
        if plan.is_empty() {
            return None;
        }
        let mut elements = Vec::new();
        // A `<style>` is injected either for the hostname-scoped selectors *or* for the generic ones
        // found in the document (`write_generic`). Whether the latter will be needed is only known once
        // the body has been seen, so the style element is always requested here: a plan with no specific
        // selectors but a generic rule still needs the nonce its `<style>` will carry.
        if plan.style_wanted() || plan.uses_generic() {
            elements.push(Element::Style);
        }
        if !plan.injected_script.is_empty() || !plan.procedural.is_empty() {
            elements.push(Element::Script);
        }
        let planned = csp::plan(policies, &elements);
        let mut rewritten = match planned.as_ref() {
            Some(planned) => planned.policies.clone(),
            None => policies.to_vec(),
        };
        let mut style_nonce = planned
            .as_ref()
            .and_then(|planned| planned.nonce(Element::Style))
            .map(str::to_string);
        let mut script_nonce = planned
            .as_ref()
            .and_then(|planned| planned.nonce(Element::Script))
            .map(str::to_string);
        // A `$csp` rule is the *filter's* own policy: sent verbatim, never relaxed with a nonce, because
        // relaxing it is the opposite of what the rule asked for. An element it refuses is not injected.
        let mut plan = plan;
        if let Some(extra) = plan.extra_csp.as_deref() {
            if !csp::allows_unmodified(extra, Element::Style) {
                plan.hide_selectors.clear();
                style_nonce = None;
            }
            if !csp::allows_unmodified(extra, Element::Script) {
                plan.injected_script.clear();
                plan.procedural.clear();
                script_nonce = None;
            }
            // Appended once: a caller that already put the `$csp` directive into `policies` (the v2
            // forwarding path does, because it builds the response head from headers) must not end up
            // sending it twice.
            if !rewritten.iter().any(|policy| policy == extra) {
                rewritten.push(extra.to_string());
            }
        }
        let inflater = match coding {
            Coding::Gzip => Some(GzipDecoder::new()),
            Coding::Identity => None,
        };
        // Procedural rules the screen dropped are counted from the start: the loss happened before
        // this document's body existed, and a counter that only saw the `<style>` path would let a
        // subscription's broken procedural rules disappear silently.
        let report = CosmeticReport {
            rejected_selectors: plan.procedural_dropped,
            procedural_rules: plan.procedural.len(),
            ..CosmeticReport::default()
        };
        Some(Self {
            drop_headers: plan.drop_response_headers.clone(),
            plan,
            framing,
            coding,
            inflater,
            decode_pending: Vec::new(),
            phase: BodyPhase::Locate,
            prefix: Vec::new(),
            locator: scan::Locator::new(),
            scanner: AttributeScanner::new(),
            style_nonce,
            script_nonce,
            style_allowed: true,
            policies: rewritten,
            head_markup_done: false,
            generic_done: false,
            trailing_bytes: 0,
            truncated: false,
            gave_up: false,
            finished: false,
            report,
        })
    }

    /// The `Content-Security-Policy` values the response head must carry.
    pub fn policies(&self) -> &[String] {
        &self.policies
    }

    /// The `$removeheader` names the response head must drop.
    pub fn drop_response_headers(&self) -> &[String] {
        &self.drop_headers
    }

    /// What was inserted so far.
    pub fn report(&self) -> CosmeticReport {
        self.report
    }

    /// True once an insertion point has been found and markup is being written.
    ///
    /// False after [`BodyInjector::abandon`], which is what lets the HTTP/1.1 driver replay the origin's
    /// own bytes instead of a decoded body it would have had to frame itself.
    pub fn is_injecting(&self) -> bool {
        self.phase != BodyPhase::Locate && !self.gave_up
    }

    /// Feed origin body bytes; get the bytes to send.
    pub fn push(&mut self, data: &[u8]) -> Emitted {
        let mut emitted = Emitted::default();
        if data.is_empty() || self.finished {
            if self.phase == BodyPhase::Done {
                emitted.bytes.extend_from_slice(data);
            }
            return emitted;
        }
        self.decode_into(data, &mut emitted);
        emitted
    }

    /// The origin's body ended.
    ///
    /// `origin_complete` says whether the origin's own framing ended properly (a `Content-Length` that was
    /// satisfied, or a chunked body that reached its terminal chunk). When it did not, the document this
    /// core has been writing is **truncated**, and closing it as if it were whole would hand the client a
    /// page that looks complete and may be cached. `emitted.broke` then tells the caller to close the
    /// connection (HTTP/1.1) or reset the stream (HTTP/2) instead of writing an end-of-body marker.
    pub fn finish(&mut self, origin_complete: bool) -> Emitted {
        let mut emitted = Emitted::default();
        if self.finished {
            return emitted;
        }
        self.finished = true;
        // A gzip member that has not reached its end means the body is cut, whatever the HTTP framing
        // said: the client must not be told it has the whole document.
        let coding_complete = match self.coding {
            Coding::Identity => true,
            Coding::Gzip => self.inflater.as_ref().is_some_and(|inflater| inflater.is_done()),
        };
        let complete = origin_complete && coding_complete && !self.truncated;
        match self.phase {
            BodyPhase::Locate => {
                let prefix = std::mem::take(&mut self.prefix);
                // At end of body the whole prefix is present once; the incremental locator's cursor does
                // not help (and `at_eof` changes the answer), so the full search is the right one here.
                match scan::find_insertion(&prefix, true) {
                    Found::At(offset) => {
                        self.begin(offset, &prefix, &mut emitted);
                        self.write_generic(&mut emitted);
                        if complete {
                            self.close(&mut emitted);
                        } else {
                            emitted.broke = true;
                        }
                    }
                    // Not a document this code can place markup in. Nothing was written, so the caller
                    // can still send the origin's bytes.
                    Found::NeedMore | Found::GiveUp => {
                        self.report = CosmeticReport::default();
                        emitted.verbatim = true;
                    }
                }
            }
            BodyPhase::Body => {
                self.write_generic(&mut emitted);
                if complete {
                    self.close(&mut emitted);
                } else {
                    emitted.broke = true;
                }
            }
            BodyPhase::Done => {}
        }
        self.phase = BodyPhase::Done;
        emitted.finished = true;
        emitted
    }

    /// Decode `data` and hand every decoded chunk to the document state machine.
    ///
    /// Expansion is drained in [`gzip::OUTPUT_CHUNK`] rounds so a decompression bomb cannot make one read
    /// materialize its whole expansion. Bytes after the gzip member are *counted and dropped*: emitting
    /// them would put unframed bytes into a body this core is chunking, which a client reads as a framing
    /// error.
    fn decode_into(&mut self, data: &[u8], emitted: &mut Emitted) -> bool {
        if self.coding == Coding::Identity {
            if !data.is_empty() {
                self.document(data, emitted);
            }
            return true;
        }
        {
            let Some(inflater) = self.inflater.as_mut() else {
                return false;
            };
            let progress = inflater.push(data);
            if inflater.failed() {
                emitted.broke = true;
                emitted.finished = true;
                self.phase = BodyPhase::Done;
                self.finished = true;
                return false;
            }
            if let GzipProgress::Finished(_) = progress {
                self.trailing_bytes += inflater.trailing().len();
            }
        }
        // Drain the buffered input in bounded rounds. The decoder is released between rounds so the
        // document state machine can borrow `self` — and so a round's chunk is written out before the
        // next one is produced.
        while let Some(chunk) = self.inflater.as_mut().and_then(GzipDecoder::drain) {
            if !chunk.is_empty() {
                self.document(&chunk, emitted);
            }
            if self.phase == BodyPhase::Done {
                // The document state machine gave up or broke; the rest of the member is not needed.
                break;
            }
        }
        true
    }

    fn document(&mut self, data: &[u8], emitted: &mut Emitted) {
        if self.phase == BodyPhase::Body {
            self.stream_body(data, emitted);
            return;
        }
        self.prefix.extend_from_slice(data);
        match self.locator.find(&self.prefix, false) {
            Found::NeedMore => {}
            Found::At(offset) => {
                let prefix = std::mem::take(&mut self.prefix);
                self.begin(offset, &prefix, emitted);
            }
            // Task card §3: once the window is exhausted there is no injection. The prefix is **not**
            // discarded: it is decoded document bytes, and the head has not been written yet on the
            // HTTP/2 path (which is what `abandon` is for). Dropping it would hand the client a page
            // with its first 64 KiB missing — and for a gzip document it would hand it compressed bytes
            // under a head that already says `identity`.
            Found::GiveUp => self.abandon(emitted),
        }
    }

    /// Stop injecting without losing a byte: emit the decoded prefix and stream the rest through.
    ///
    /// Unlike [`Rewriter::replay_verbatim`], there is no origin-framed body to replay here — this type
    /// only ever sees decoded document bytes — so "give up" means "keep going, but stop inserting". The
    /// response head has already been rewritten for a body this core owns, and that stays true: the body
    /// is still decoded and still framed by this type, so the prefix is exactly what the client needs.
    fn abandon(&mut self, emitted: &mut Emitted) {
        self.phase = BodyPhase::Body;
        self.gave_up = true;
        self.report = CosmeticReport::default();
        let prefix = std::mem::take(&mut self.prefix);
        if self.framing == OutFraming::Chunked && !prefix.is_empty() {
            // HTTP/1.1 keeps the origin's own bytes for exactly this case, and `emitted.verbatim` tells
            // its driver to replay them — so nothing is written here. Writing the decoded prefix would
            // *also* be correct, but replaying the origin's bytes keeps the response byte-identical,
            // which is the stronger promise and what `docs/JNI.md` documents.
            self.gave_up = false;
            self.phase = BodyPhase::Locate;
            self.prefix = prefix;
            emitted.verbatim = true;
            return;
        }
        if prefix.is_empty() {
            return;
        }
        // HTTP/2 has no origin-framed body to replay: the head already says `identity`, so the decoded
        // prefix (and everything after it) is what the client must receive.
        self.write_chunk(&prefix, emitted);
    }

    fn begin(&mut self, offset: usize, prefix: &[u8], emitted: &mut Emitted) {
        self.phase = BodyPhase::Body;
        let split = offset.min(prefix.len());
        let (before, after) = prefix.split_at(split);
        self.scan_and_write(before, emitted);
        self.write_head_markup(emitted);
        self.stream_body(after, emitted);
    }

    fn write_head_markup(&mut self, emitted: &mut Emitted) {
        if self.head_markup_done {
            return;
        }
        self.head_markup_done = true;
        let mut markup = String::new();
        if self.plan.style_wanted() {
            // A global unhide (`#@#`/`*#@#`) is a form the engine drops on the floor
            // ([`crate::cosmetic::unhide`]); it is applied here rather than in the plan so the
            // statistics below still count what the engine offered.
            let mut selectors = self.plan.hide_selectors.clone();
            self.plan.global_unhides.apply(&mut selectors);
            let (style, rejected) = style_element_counting(
                "specific",
                &selectors,
                self.style_nonce.as_deref(),
                crate::cosmetic::validate::shared(),
            );
            self.report.rejected_selectors += rejected;
            if !style.is_empty() {
                self.report.specific = selectors.len() - rejected;
                markup.push_str(&style);
            }
        }
        if !self.plan.injected_script.is_empty() {
            markup.push_str(&script_element(
                &self.plan.injected_script,
                self.script_nonce.as_deref(),
            ));
            self.report.scriptlet = true;
        }
        // The procedural rules travel as one `<script>`, after the scriptlets so a scriptlet's own
        // property definitions are in place before the first rule is evaluated.
        if let Some(script) = crate::cosmetic::procedural::script_element(
            &self.plan.procedural,
            self.script_nonce.as_deref(),
        ) {
            markup.push_str(&script);
            self.report.procedural = true;
        }
        if markup.is_empty() {
            return;
        }
        self.report.injected = true;
        self.write_chunk(markup.as_bytes(), emitted);
    }

    fn stream_body(&mut self, data: &[u8], emitted: &mut Emitted) {
        if !self.report.csp_meta
            && scan::find_ignore_ascii_case(data, b"http-equiv").is_some()
            && scan::find_ignore_ascii_case(data, b"content-security-policy").is_some()
        {
            self.report.csp_meta = true;
        }
        // After giving up, the body is still this type's to decode and frame — it just carries nothing.
        if self.gave_up || !self.plan.uses_generic() {
            self.scan_and_write(data, emitted);
            return;
        }
        // The generic `<style>` goes at the **end of the document**, not at the first `</body`.
        //
        // `</body` occurs inside inline scripts (`document.write("<body></body>")`, a template string,
        // a JSON blob), and inserting there would splice our markup — which contains newlines — into a
        // JavaScript string and break the page. Nothing tells a streaming reader which `</body` is the
        // real one without parsing HTML, and the end of the document is a position the HTML parser
        // accepts `<style>` in regardless (`</html>` may be followed by anything). So the body is
        // streamed through with no lookahead at all and the `<style>` is written when the body ends.
        self.scan_and_write(data, emitted);
    }

    fn scan_and_write(&mut self, data: &[u8], emitted: &mut Emitted) {
        if data.is_empty() {
            return;
        }
        self.scanner.feed(data);
        self.write_chunk(data, emitted);
    }

    fn write_generic(&mut self, emitted: &mut Emitted) {
        if self.generic_done || !self.plan.uses_generic() {
            return;
        }
        self.generic_done = true;
        if self.scanner.is_empty() || !self.style_allowed {
            return;
        }
        let Some(engine) = self.plan.engine.clone() else {
            return;
        };
        let (classes, ids) = self.scanner.snapshot();
        let mut selectors =
            engine.hidden_class_id_selectors(classes.iter(), ids.iter(), &self.plan.exceptions);
        // The engine cannot express a global unhide ([`crate::cosmetic::unhide`]), so a selector a
        // `#@#`/`*#@#` rule removes has to be dropped here too — otherwise the generic channel
        // reintroduces exactly what the specific channel just removed.
        self.plan.global_unhides.apply(&mut selectors);
        selectors.sort_unstable();
        selectors.dedup();
        if selectors.is_empty() {
            return;
        }
        let (style, rejected) = style_element_counting(
            "generic",
            &selectors,
            self.style_nonce.as_deref(),
            crate::cosmetic::validate::shared(),
        );
        self.report.rejected_selectors += rejected;
        if style.is_empty() {
            return;
        }
        self.report.generic = selectors.len() - rejected;
        self.report.injected = true;
        self.write_chunk(style.as_bytes(), emitted);
    }

    fn write_chunk(&mut self, data: &[u8], emitted: &mut Emitted) {
        if data.is_empty() {
            return;
        }
        if self.framing == OutFraming::Chunked {
            emitted
                .bytes
                .extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
            emitted.bytes.extend_from_slice(data);
            emitted.bytes.extend_from_slice(b"\r\n");
        } else {
            emitted.bytes.extend_from_slice(data);
        }
    }

    fn close(&mut self, emitted: &mut Emitted) {
        if self.framing != OutFraming::Chunked {
            return;
        }
        let pending = std::mem::take(&mut self.decode_pending);
        if !pending.is_empty() {
            emitted.bytes.extend_from_slice(&pending);
        }
        emitted.bytes.extend_from_slice(b"0\r\n\r\n");
    }
}

/// What the rewriter inserted, for `statsJson` and the tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CosmeticReport {
    /// At least one element was inserted into this document.
    pub injected: bool,
    /// How many hostname-scoped selectors were inserted.
    pub specific: usize,
    /// How many generic (class/id-keyed) selectors were inserted.
    pub generic: usize,
    /// The engine's scriptlet bundle was inserted.
    pub scriptlet: bool,
    /// The procedural runtime was inserted.
    pub procedural: bool,
    /// How many procedural rules that runtime was given.
    pub procedural_rules: usize,
    /// The body carried a `<meta http-equiv="Content-Security-Policy">`, which was left alone.
    pub csp_meta: bool,
    /// Selectors dropped because they could not be injected safely (see [`Rejected`]).
    ///
    /// Non-zero means a subscription carried a selector that would have escaped its rule block or closed
    /// the `<style>` element. It is a count rather than a silent skip because a list that keeps producing
    /// these is a list the user may want to remove.
    pub rejected_selectors: usize,
}

/// The outcome of one [`Rewriter::push`] or [`Rewriter::finish`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Emitted {
    /// Bytes to write to the client, in order.
    pub bytes: Vec<u8>,
    /// The body ended: every later `push` is a passthrough.
    pub finished: bool,
    /// The response can no longer be delivered consistently (a coding broke mid-body). The caller must
    /// close the connection rather than continue.
    pub broke: bool,
    /// The response is being relayed **byte for byte**, head included, from this point on.
    pub verbatim: bool,
}

impl Emitted {
    /// Merge another step's output into this one.
    fn absorb(&mut self, other: Emitted) {
        self.bytes.extend_from_slice(&other.bytes);
        self.finished |= other.finished;
        self.broke |= other.broke;
        self.verbatim |= other.verbatim;
    }
}

/// Why a selector cannot be injected into the `<style>` element.
///
/// A filter list is **untrusted input** — a subscription can point at any third-party URL — and the
/// selector is pasted into markup this core emits into every page the user visits. Both characters
/// screened for here end the element that carries them:
///
/// - `}` / `{`: a brace escapes the rule block and lets the list author arbitrary CSS (and, with a
///   `url()` or an `@import`, make requests of its own).
/// - `<`: it closes the `<style>` element. `div[title="</style><script>…</script>"]` is a legal CSS
///   selector and would end the style block early, turning every decrypted page into an XSS sink.
///   No real element-hiding selector needs a literal `<` — CSS attribute selectors compare strings,
///   and a `<` in a value is far more likely to be an attack than a rule someone meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// The selector contained `{` or `}`.
    Brace,
    /// The selector contained `<`.
    AngleBracket,
}

/// Screen one selector, or say why it cannot be injected.
pub fn screen_selector(selector: &str) -> Result<&str, Rejected> {
    let selector = selector.trim();
    if selector.contains(['{', '}']) {
        return Err(Rejected::Brace);
    }
    if selector.contains('<') {
        return Err(Rejected::AngleBracket);
    }
    Ok(selector)
}

/// The CSS rule list for a set of selectors that have already passed both screens, or `None` when
/// none are left.
fn css_for(selectors: &[&str]) -> Option<String> {
    if selectors.is_empty() {
        return None;
    }
    let mut css = String::with_capacity(selectors.iter().map(|s| s.len() + 3).sum::<usize>() + 64);
    css.push_str(&selectors.join(",\n"));
    css.push_str("\n{ display: none !important; }\n");
    Some(css)
}

/// The `<style>` element for one rule set, split into independent blocks.
///
/// Two independent safety properties, both required:
///
/// - **Injection safety** ([`screen_selector`]): a selector that could escape its rule block or close
///   the element is dropped. Cheap, and about the markup rather than about CSS.
/// - **Parseability** ([`crate::cosmetic::validate`]): a selector the browser's own grammar rejects is
///   dropped, because CSS discards a whole rule list over any one member (M5a §9.3.3). This is the
///   defect the module exists for; the split into blocks below is the second line of defence, not the
///   first.
///
/// Returns the element plus the number of selectors dropped, so the loss is visible in `statsJson`
/// rather than silent.
fn style_element_counting(
    marker: &str,
    selectors: &[String],
    nonce: Option<&str>,
    validator: &crate::cosmetic::validate::SelectorValidator,
) -> (String, usize) {
    let mut rejected = 0usize;
    let mut usable: Vec<&str> = Vec::with_capacity(selectors.len());
    for selector in selectors {
        if selector.trim().is_empty() {
            continue;
        }
        if screen_selector(selector).is_err() {
            rejected += 1;
            continue;
        }
        if !validator.check(selector).is_usable() {
            rejected += 1;
            continue;
        }
        usable.push(selector.trim());
    }
    let mut blocks = Vec::new();
    for chunk in usable.chunks(SELECTORS_PER_BLOCK) {
        if let Some(css) = css_for(chunk) {
            blocks.push(css);
        }
    }
    if blocks.is_empty() {
        return (String::new(), rejected);
    }
    let mut out = String::with_capacity(blocks.iter().map(String::len).sum::<usize>() + 96);
    out.push_str("<style");
    if let Some(nonce) = nonce {
        out.push_str(" nonce=\"");
        out.push_str(nonce);
        out.push('"');
    }
    out.push_str(" data-zshield=\"");
    out.push_str(marker);
    out.push_str("\">\n");
    for block in blocks {
        out.push_str(&block);
    }
    out.push_str("</style>\n");
    (out, rejected)
}

/// The `<script>` element for the engine's scriptlet bundle.
///
/// # Why the body is escaped
///
/// The script came from a `##+js(name, arg…)` rule in a subscription, and its *arguments* are arbitrary
/// text from that list. `</script>` anywhere in it would end the element early and let the rest of the
/// argument run as markup — a list could then inject any element it liked into every page. The body is
/// therefore emitted with the two sequences an HTML parser treats specially inside a script element
/// neutralized:
///
/// - `</` becomes `<\/` — in JavaScript a `\/` is just `/`, and the parser no longer sees the end tag.
///   This is the same defence every server-side JSON-in-HTML encoder uses.
/// - `<!--` becomes `<\!--` — `<!--` opens an HTML comment inside a script and would let the argument
///   comment out the rest of the bundle.
///
/// Both rewrites are byte-level and preserve the script's meaning: `str.replace` on the whole bundle
/// would also hit string literals, but the replacements are exactly the escapes a JavaScript source
/// would need there anyway.
fn script_element(script: &str, nonce: Option<&str>) -> String {
    let mut out = String::with_capacity(script.len() + 96);
    out.push_str("<script");
    if let Some(nonce) = nonce {
        out.push_str(" nonce=\"");
        out.push_str(nonce);
        out.push('"');
    }
    out.push_str(" data-zshield=\"scriptlets\">\n");
    escape_script_body_into(script, &mut out);
    out.push_str("\n</script>\n");
    out
}

/// Neutralize the sequences that would end or comment out an inline `<script>` element.
///
/// Case-insensitive on `</` because HTML tag names are, so `</SCRIPT>` and `</Script >` are both tags
/// the parser recognizes.
pub(crate) fn escape_script_body_into(script: &str, out: &mut String) {
    let bytes = script.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'<' {
            // `</` in any case: an end tag is starting.
            if bytes.get(index + 1) == Some(&b'/') {
                out.push_str("<\\/");
                index += 2;
                continue;
            }
            // `<!--`: an HTML comment opener.
            if bytes[index..].starts_with(b"<!--") {
                out.push_str("<\\!--");
                index += 4;
                continue;
            }
        }
        // Copy one whole character so a multi-byte sequence is never split.
        let rest = &script[index..];
        let character = rest.chars().next().expect("index is a char boundary");
        out.push(character);
        index += character.len_utf8();
    }
}

impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plan")
            .field("hide_selectors", &self.hide_selectors.len())
            .field("generichide", &self.generichide)
            .field("script_bytes", &self.injected_script.len())
            .field("engine", &self.engine.is_some())
            .finish()
    }
}

/// A response being rewritten on an HTTP/1.1 connection.
///
/// The head is this type's business — it is parsed off the wire, and the three headers that stop being
/// true once a body is rewritten (`Content-Length`, `Content-Encoding`, `Transfer-Encoding`) have to be
/// replaced — while everything about the body is delegated to [`BodyInjector`], which HTTP/2 uses
/// directly.
///
/// Until the injector commits to rewriting, every byte the client will receive is held, so a document
/// that cannot be injected is delivered exactly as the origin sent it.
pub struct Rewriter {
    plan: Plan,
    framing: OutFraming,
    /// Strips the origin's chunk framing, when it used any.
    ///
    /// A rewritten body is re-chunked locally, so the origin's framing has to come off first: feeding
    /// `1a5\r\n<gzip>` to the decoder would be decoding framing bytes as payload.
    dechunker: Option<Dechunker>,
    /// Where the head is in its own little state machine.
    head_state: HeadState,
    /// The origin's head bytes, kept until the rewrite is decided and for a verbatim replay.
    head: Vec<u8>,
    /// The origin's own bytes — head and body — received so far, for a verbatim replay.
    raw: Vec<u8>,
    /// How many of `raw`'s leading bytes are the response head.
    raw_head_len: usize,
    /// The origin's parsed head, once it has arrived.
    parsed: Option<ResponseHead>,
    /// The body injector, once the response has been accepted as injectable.
    inner: Option<BodyInjector>,
    finished: bool,
    report: CosmeticReport,
}

/// Where a [`Rewriter`] is in the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadState {
    /// Buffering the head.
    Head,
    /// The injector owns the body.
    Body,
    /// Relaying the origin's bytes unmodified.
    Verbatim,
    /// Finished, or broken.
    Done,
}

impl std::fmt::Debug for Rewriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rewriter")
            .field("plan", &self.plan)
            .field("head_state", &self.head_state)
            .field("inner", &self.inner)
            .field("report", &self.report)
            .finish()
    }
}

impl Rewriter {
    /// Start rewriting one response. `plan` is what the engine said about this document.
    pub fn new(plan: Plan, framing: OutFraming) -> Self {
        Self {
            plan,
            framing,
            dechunker: None,
            head_state: HeadState::Head,
            head: Vec::new(),
            raw: Vec::new(),
            raw_head_len: 0,
            parsed: None,
            inner: None,
            finished: false,
            report: CosmeticReport::default(),
        }
    }

    /// What was inserted so far.
    pub fn report(&self) -> CosmeticReport {
        self.report
    }

    /// True while the response is being relayed unmodified.
    pub fn is_verbatim(&self) -> bool {
        matches!(self.head_state, HeadState::Verbatim | HeadState::Done) && self.inner.is_none()
    }

    /// Feed origin response bytes; get the bytes to send.
    pub fn push(&mut self, data: &[u8]) -> Emitted {
        let mut emitted = Emitted::default();
        if data.is_empty() {
            return emitted;
        }
        match self.head_state {
            HeadState::Head => {
                self.raw.extend_from_slice(data);
                self.head_state = self.push_head(data, &mut emitted);
            }
            HeadState::Body => {
                // `raw` exists only for the window in which injection can still be abandoned. Once the
                // injector has committed (its first byte is out) the origin's bytes are no longer
                // replayable, and keeping them would make a large document resident in memory for
                // nothing — so it is dropped, not merely stopped.
                if self.raw.len() <= raw_cap() {
                    self.raw.extend_from_slice(data);
                } else {
                    self.raw = Vec::new();
                }
                self.push_body(data, &mut emitted);
            }
            HeadState::Verbatim | HeadState::Done => emitted.bytes.extend_from_slice(data),
        }
        emitted
    }

    /// The origin's body ended.
    ///
    /// `origin_complete` is the caller's verdict on the origin's own framing — a `Content-Length` that was
    /// satisfied, or a chunked body that reached its terminal chunk. A truncated origin body must not be
    /// closed as if it were whole: see [`BodyInjector::finish`].
    pub fn finish(&mut self, origin_complete: bool) -> Emitted {
        let mut emitted = Emitted::default();
        if self.finished {
            return emitted;
        }
        self.finished = true;
        match self.head_state {
            // A head that never completed is not a response this code can rewrite: what came off the
            // wire is all there is.
            HeadState::Head => {
                let raw = std::mem::take(&mut self.raw);
                emitted.bytes.extend_from_slice(&raw);
                emitted.verbatim = true;
            }
            HeadState::Body => {
                let step = match self.inner.as_mut() {
                    Some(inner) => {
                        let step = inner.finish(origin_complete);
                        self.report = inner.report();
                        step
                    }
                    None => Emitted::default(),
                };
                if step.verbatim {
                    // The injector gave up. If the head was already rewritten the origin's bytes can no
                    // longer be reproduced and the caller has to close the connection; if it was not,
                    // the replay below puts them back.
                    if self.head.is_empty() {
                        emitted.broke = true;
                    } else {
                        self.replay_verbatim(&mut emitted);
                        self.head_state = HeadState::Done;
                        emitted.finished = true;
                        return emitted;
                    }
                } else {
                    self.write_head_if_committed(&mut emitted);
                    emitted.absorb(step);
                }
            }
            HeadState::Verbatim | HeadState::Done => {}
        }
        self.head_state = HeadState::Done;
        emitted.finished = true;
        emitted
    }

    /// Read the head; return the state the response is now in.
    fn push_head(&mut self, data: &[u8], emitted: &mut Emitted) -> HeadState {
        self.head.extend_from_slice(data);
        let Some(end) = head::head_end(&self.head) else {
            if self.head.len() > head::MAX_HEAD_BYTES {
                // Not a response head this core will ever parse.
                self.replay_verbatim(emitted);
                return HeadState::Verbatim;
            }
            return HeadState::Head;
        };
        let body = self.head[end..].to_vec();
        self.head.truncate(end);
        self.raw_head_len = end;

        let parsed_head = head::parse(&self.head);
        // Why a response was or was not rewritten is the first question a report asks, so the three
        // decisive fields are logged once per response.
        match parsed_head.as_ref() {
            Some(parsed) => crate::log_msg(
                "debug",
                &format!(
                    "cosmetic: response {} {:?} enc {:?} injectable {}",
                    parsed.status,
                    parsed.content_type,
                    parsed.content_encoding,
                    parsed.is_injectable_document()
                ),
            ),
            None => crate::log_msg("debug", "cosmetic: response head did not parse"),
        }
        let injectable = parsed_head
            .filter(|parsed| parsed.is_injectable_document())
            .and_then(|parsed| {
                let coding = parsed.coding()?;
                let inner = BodyInjector::new(self.plan.clone(), self.framing, coding, &parsed.csp)?;
                Some((parsed, inner))
            });
        let Some((parsed, inner)) = injectable else {
            crate::log_msg("debug", "cosmetic: relaying this response verbatim");
            self.replay_verbatim(emitted);
            return HeadState::Verbatim;
        };
        self.dechunker = parsed.chunked.then(Dechunker::new);
        self.parsed = Some(parsed);
        self.inner = Some(inner);
        if !body.is_empty() {
            self.push_body(&body, emitted);
        }
        if !self.head.is_empty() {
            // Nothing was written (the body has not decided anything yet), so the state stays `Body`
            // and the head is emitted by the first `push_body` that commits to injecting.
            return HeadState::Body;
        }
        HeadState::Body
    }

    fn push_body(&mut self, data: &[u8], emitted: &mut Emitted) {
        let Some(inner) = self.inner.as_mut() else {
            emitted.bytes.extend_from_slice(data);
            return;
        };
        // The origin's chunk framing is not part of the document: the injector re-frames the body
        // itself, so the framing has to come off before the bytes are decoded or scanned.
        let framed;
        let data = match self.dechunker.as_mut() {
            Some(dechunker) => {
                framed = dechunker.push(data);
                if dechunker.is_malformed() {
                    // The framing broke mid-body. Whatever was already injected is out; the caller has
                    // to close the connection rather than deliver a body of unknown length.
                    emitted.broke = true;
                    self.head_state = HeadState::Done;
                    return;
                }
                // Nothing to decode: this feed held only framing.
                if framed.is_empty() {
                    return;
                }
                framed.as_slice()
            }
            None => data,
        };
        let step = inner.push(data);
        self.report = inner.report();
        if step.broke {
            self.head_state = HeadState::Done;
            emitted.absorb(step);
            return;
        }
        if step.verbatim {
            // The insertion window was exhausted before anything was written, so the origin's own
            // bytes — head included — are still available and are what the client gets.
            self.replay_verbatim(emitted);
            return;
        }
        self.write_head_if_committed(emitted);
        emitted.absorb(step);
    }

    /// Emit the rewritten head, once, at the moment the injector commits to rewriting the body.
    fn write_head_if_committed(&mut self, emitted: &mut Emitted) {
        if self.head.is_empty() {
            return;
        }
        let Some(inner) = self.inner.as_ref() else {
            return;
        };
        if !inner.is_injecting() {
            return;
        }
        if let Some(rewritten) = head::rewrite(
            &self.head,
            self.framing,
            inner.policies(),
            inner.drop_response_headers(),
        ) {
            emitted.bytes.extend_from_slice(&rewritten);
        }
        self.head.clear();
        self.raw.clear();
    }

    /// Give up on injecting: the origin's bytes go out with only the request's own head edits applied.
    ///
    /// Those edits (`$removeheader`, `$csp`) belong to a different rule than the cosmetic one and were
    /// already granted, so they still apply. Nothing else about the head changes — `Content-Length` and
    /// `Content-Encoding` included — because the body is untouched.
    fn replay_verbatim(&mut self, emitted: &mut Emitted) {
        let raw = std::mem::take(&mut self.raw);
        self.head.clear();
        self.report = CosmeticReport::default();
        // The head edits (`$removeheader`, `$csp`) belong to the *request*, not to the cosmetic decision,
        // so they apply whenever a head was parsed — including when injection itself was abandoned. When
        // no head was parsed there is nothing to rewrite and the bytes go out as they arrived.
        if self.raw_head_len > 0 {
            let split = self.raw_head_len.min(raw.len());
            let (head_bytes, body) = raw.split_at(split);
            emitted
                .bytes
                .extend_from_slice(&crate::http::rewrite::rewrite_response_head(
                    head_bytes,
                    &self.plan.drop_response_headers,
                    self.plan.extra_csp.as_deref(),
                ));
            emitted.bytes.extend_from_slice(body);
        } else {
            emitted.bytes.extend_from_slice(&raw);
        }
        emitted.verbatim = true;
        self.inner = None;
        self.head_state = HeadState::Verbatim;
    }
}
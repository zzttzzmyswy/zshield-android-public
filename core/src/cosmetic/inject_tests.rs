//! End-to-end tests of the cosmetic rewriter.
//!
//! Each test drives [`Rewriter`] exactly as the relays do — the origin's head and body bytes are pushed
//! in pieces and the concatenation of everything returned is the response a client would see — so the
//! assertions are about the *wire*, not about internal state: the chunk framing, the head rewrite, the
//! injected markup and, most of all, that a document this code cannot rewrite comes back byte for byte.

use std::sync::Arc;

use adblock::lists::{FilterSet, ParseOptions};

use crate::cosmetic::head::OutFraming;
use crate::cosmetic::inject::{Plan, Rewriter};

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// An engine with `rules` compiled in and the scriptlet registry installed.
fn build_engine(rules: &str) -> Arc<adblock::Engine> {
    let mut set = FilterSet::new(false);
    set.add_filter_list(rules.to_string(), ParseOptions::default());
    let mut engine = adblock::Engine::new_with_filter_set(set);
    engine.use_resources(crate::cosmetic::scriptlets::resources().to_vec());
    Arc::new(engine)
}

/// The plan the relays build from the engine for one document URL.
fn plan_for(engine: &Arc<adblock::Engine>, url: &str) -> Plan {
    let resources = engine.url_cosmetic_resources(url);
    Plan {
        hide_selectors: resources.hide_selectors.into_iter().collect(),
        exceptions: resources.exceptions,
        global_unhides: std::sync::Arc::new(
            crate::cosmetic::unhide::GlobalUnhides::default(),
        ),
        injected_script: resources.injected_script,
        procedural: Vec::new(),
        procedural_dropped: 0,
        generichide: resources.generichide,
        engine: Some(engine.clone()),
        drop_response_headers: Vec::new(),
        extra_csp: None,
    }
}

/// gzip-encode `data`, as an origin with `Content-Encoding: gzip` would.
fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("compress");
    encoder.finish().expect("finish")
}

/// Drive a rewriter over `chunks` of the origin's response and return everything it emitted.
///
/// `chunks` are the *origin's* bytes in the order they arrive; each one is one `push`.
fn drive(rewriter: &mut Rewriter, chunks: &[&[u8]]) -> Run {
    let mut run = Run::default();
    for chunk in chunks {
        let emitted = rewriter.push(chunk);
        run.absorb(emitted);
    }
    let emitted = rewriter.finish(true);
    run.absorb(emitted);
    run.report = rewriter.report();
    run
}

/// Everything one rewrite produced.
#[derive(Default, Debug)]
struct Run {
    bytes: Vec<u8>,
    verbatim: bool,
    broke: bool,
    finished: bool,
    report: crate::cosmetic::inject::CosmeticReport,
}

impl Run {
    fn absorb(&mut self, emitted: crate::cosmetic::inject::Emitted) {
        self.bytes.extend_from_slice(&emitted.bytes);
        self.verbatim |= emitted.verbatim;
        self.broke |= emitted.broke;
        self.finished |= emitted.finished;
    }

}

/// The origin's response bytes for a document with `head_headers` extra lines and `body`.
fn response(extra_headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n");
    for header in extra_headers {
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}

/// Decode a chunked body into the bytes it carries. Panics on broken framing, which is the point.
fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = body.windows(2).position(|window| window == b"\r\n") else {
            panic!("no chunk size line in {:?}", String::from_utf8_lossy(body));
        };
        let size_text = std::str::from_utf8(&body[..line_end]).expect("ascii size");
        let size = usize::from_str_radix(size_text.trim(), 16)
            .unwrap_or_else(|_| panic!("bad chunk size {size_text:?}"));
        body = &body[line_end + 2..];
        if size == 0 {
            assert_eq!(body, b"\r\n", "the terminal chunk ends the body");
            return out;
        }
        assert!(body.len() >= size + 2, "chunk of {size} runs past the body");
        out.extend_from_slice(&body[..size]);
        assert_eq!(&body[size..size + 2], b"\r\n", "a chunk ends with CRLF");
        body = &body[size + 2..];
    }
}

/// Split a rewritten HTTP/1.1 response into its head and its de-chunked body.
fn split_response(response: &[u8]) -> (&[u8], Vec<u8>) {
    let end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a head terminator")
        + 4;
    let head = &response[..end];
    let text = String::from_utf8_lossy(head).to_ascii_lowercase();
    let body = if text.contains("transfer-encoding: chunked") {
        dechunk(&response[end..])
    } else {
        response[end..].to_vec()
    };
    (head, body)
}

// ---------------------------------------------------------------------------------------------
// Insertion point
// ---------------------------------------------------------------------------------------------

#[test]
fn a_style_goes_right_after_head_and_the_document_is_unchanged_otherwise() {
    let engine = build_engine("example.com##.ad-banner\n");
    let rules = plan_for(&engine, "https://example.com/page");
    let body = b"<!doctype html><html><head><title>t</title></head><body><div class=\"ad-banner\">ad</div></body></html>";
    let origin = response(&[], body);

    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (head, rewritten_body) = split_response(&run.bytes);

    let head_text = String::from_utf8_lossy(head).to_string();
    assert!(head_text.starts_with("HTTP/1.1 200 OK\r\n"), "{head_text}");
    assert!(
        head_text.to_ascii_lowercase().contains("transfer-encoding: chunked"),
        "the injected body has no length to declare: {head_text}"
    );
    assert!(
        !head_text.to_ascii_lowercase().contains("content-length"),
        "{head_text}"
    );

    let body_text = String::from_utf8_lossy(&rewritten_body).to_string();
    assert!(run.report.injected, "nothing was injected");
    assert_eq!(run.report.specific, 1);
    assert!(
        body_text.starts_with("<!doctype html><html><head><style"),
        "the style must follow <head>: {body_text}"
    );
    assert!(body_text.contains(".ad-banner\n{ display: none !important; }"), "{body_text}");
    assert!(
        body_text.ends_with("</body></html>"),
        "the document's own bytes must survive: {body_text}"
    );
    // The original document still appears in order, minus the `Content-Length`.
    assert!(body_text.contains("<title>t</title>"), "{body_text}");
}

#[test]
fn a_head_with_attributes_and_a_document_without_a_head_both_work() {
    let engine = build_engine("example.com##.ad\n");
    // `<head lang=…>`: the style goes after the closing bracket, not after the name.
    let body = b"<html><head lang=\"zh\"><title>x</title></head><body>y</body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(text.starts_with("<html><head lang=\"zh\"><style"), "{text}");

    // No `<head>` at all: after `<html>`.
    let body = b"<html><body><p>hi</p></body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(text.starts_with("<html><style"), "{text}");
}

#[test]
fn a_document_without_head_or_html_gets_the_style_after_the_doctype() {
    let engine = build_engine("example.com##.ad\n");
    let body = b"<!DOCTYPE html>\n<div class=ad>x</div>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(text.starts_with("<!DOCTYPE html>\n<style"), "{text}");
}

#[test]
fn a_bom_is_preserved_in_front_of_the_injected_markup() {
    let engine = build_engine("example.com##.ad\n");
    let mut body = vec![0xEF, 0xBB, 0xBF];
    body.extend_from_slice(b"<!DOCTYPE html>\n<p>x</p>");
    let mut origin = Vec::new();
    origin.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ");
    origin.extend_from_slice(body.len().to_string().as_bytes());
    origin.extend_from_slice(b"\r\n\r\n");
    origin.extend_from_slice(&body);

    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    assert_eq!(&rewritten[..3], &[0xEF, 0xBB, 0xBF], "the BOM must stay first");
    let text = String::from_utf8_lossy(&rewritten[3..]).to_string();
    assert!(text.starts_with("<!DOCTYPE html>\n<style"), "{text}");
}

#[test]
fn a_head_split_across_two_body_chunks_is_still_found() {
    let engine = build_engine("example.com##.ad\n");
    let body = b"<!doctype html><html><head lang=\"en\"><title>t</title></head><body>x</body></html>";
    let origin = response(&[], body);
    let head_end = origin
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("head end")
        + 4;
    // Split inside `<head lang=` — the exact byte a streaming parser has to wait for.
    let split_at = head_end + b"<!doctype html><html><hea".len();
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(
        &mut rewriter,
        &[&origin[..split_at], &origin[split_at..]],
    );
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(run.report.injected);
    assert!(text.starts_with("<!doctype html><html><head lang=\"en\"><style"), "{text}");
    // Every split point must work, not just the one above.
    for split_at in head_end..origin.len() {
        let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
        let run = drive(&mut rewriter, &[&origin[..split_at], &origin[split_at..]]);
        let (_, rewritten) = split_response(&run.bytes);
        assert_eq!(
            rewritten,
            String::from_utf8_lossy(&rewritten).to_string().as_bytes(),
            "split at {split_at}"
        );
        assert!(
            run.report.injected,
            "split at {split_at} lost the injection"
        );
    }
}

#[test]
fn a_document_with_no_insertion_point_within_the_window_is_delivered_unchanged() {
    let engine = build_engine("example.com##.ad\n");
    // A single line longer than the window with no `<head>`, `<html>` or `<body>` in it.
    let mut body = b"<div>".to_vec();
    body.extend(std::iter::repeat_n(b'x', crate::cosmetic::scan::SCAN_WINDOW + 1024));
    let origin = response(&[], &body);

    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    assert!(run.verbatim, "the response must be relayed verbatim");
    assert_eq!(
        run.bytes, origin,
        "a document that cannot be injected must arrive byte for byte"
    );
    assert!(!run.report.injected);
}

// ---------------------------------------------------------------------------------------------
// gzip
// ---------------------------------------------------------------------------------------------

#[test]
fn a_gzip_document_is_decoded_injected_and_sent_as_identity() {
    let engine = build_engine("example.com##.ad\n");
    let body = b"<!doctype html><html><head><title>t</title></head><body><div class=ad>x</div></body></html>";
    let compressed = gzip(body);
    let origin = response(
        &["Content-Encoding: gzip"],
        &compressed,
    );

    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (head, rewritten) = split_response(&run.bytes);
    let head_text = String::from_utf8_lossy(head).to_ascii_lowercase();
    assert!(!head_text.contains("content-encoding"), "{head_text}");
    assert!(!head_text.contains("content-length"), "{head_text}");
    assert!(head_text.contains("transfer-encoding: chunked"), "{head_text}");

    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(run.report.injected, "nothing injected");
    assert!(text.contains("<style"), "{text}");
    assert!(
        text.contains("<body><div class=ad>x</div></body>"),
        "the decompressed document must reach the client intact: {text}"
    );
}

#[test]
fn a_gzip_body_split_across_many_chunks_still_injects() {
    let engine = build_engine("example.com##.ad\n");
    let body = b"<!doctype html><html><head lang=en><title>t</title></head><body><div class=ad>x</div></body></html>";
    let compressed = gzip(body);
    let mut origin = Vec::new();
    origin.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n\r\n");
    origin.extend_from_slice(&compressed);

    // Every possible split of the compressed stream into two pushes.
    for split in 1..compressed.len() {
        let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
        let run = drive(
            &mut rewriter,
            &[
                &origin[..origin.len() - compressed.len() + split],
                &origin[origin.len() - compressed.len() + split..],
            ],
        );
        let (_, rewritten) = split_response(&run.bytes);
        let text = String::from_utf8_lossy(&rewritten).to_string();
        assert!(run.report.injected, "split at {split}: nothing injected");
        assert!(
            text.contains("<div class=ad>x</div>"),
            "split at {split}: the body was lost"
        );
    }
}

#[test]
fn a_chunked_gzip_document_is_dechunked_decoded_and_injected() {
    // The framing every real origin uses for a compressed document: `Transfer-Encoding: chunked` plus
    // `Content-Encoding: gzip`. The injector re-frames the body itself, so the origin's chunk framing
    // has to come off *before* the gzip decoder sees a byte of it.
    let engine = build_engine("example.com##.ad\n");
    let document = b"<!doctype html><html><head lang=en><title>t</title></head>\
                     <body><div class=ad>x</div></body></html>";
    let compressed = gzip(document);

    let mut origin = Vec::new();
    origin.extend_from_slice(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n\
          Transfer-Encoding: chunked\r\n\r\n",
    );
    // Several chunks, so the gzip stream is split across them the way a real origin sends it.
    for piece in compressed.chunks(97) {
        origin.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        origin.extend_from_slice(piece);
        origin.extend_from_slice(b"\r\n");
    }
    origin.extend_from_slice(b"0\r\n\r\n");

    let rules = plan_for(&engine, "https://example.com/");
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    assert!(!run.broke, "the response must be completable");
    let (head, rewritten) = split_response(&run.bytes);
    let head_text = String::from_utf8_lossy(head).to_ascii_lowercase();
    assert!(!head_text.contains("content-encoding"), "{head_text}");
    assert!(!head_text.contains("content-length"), "{head_text}");
    assert!(head_text.contains("transfer-encoding: chunked"), "{head_text}");

    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(run.report.injected, "nothing was injected");
    assert!(
        text.contains("<style data-zshield=\"specific\">"),
        "the hide rule must be injected: {text}"
    );
    assert!(
        text.contains("<div class=ad>x</div>"),
        "the decoded document must reach the client intact: {text}"
    );
    assert!(text.ends_with("</body></html>"), "{text}");
}

#[test]
fn a_chunked_gzip_document_split_at_every_byte_still_injects() {
    let engine = build_engine("example.com##.ad\n");
    let document = b"<!doctype html><html><head lang=en></head><body><div class=ad>x</div></body></html>";
    let compressed = gzip(document);
    let mut origin = Vec::new();
    origin.extend_from_slice(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n\
          Transfer-Encoding: chunked\r\n\r\n",
    );
    for piece in compressed.chunks(40) {
        origin.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        origin.extend_from_slice(piece);
        origin.extend_from_slice(b"\r\n");
    }
    origin.extend_from_slice(b"0\r\n\r\n");

    // Feeding one byte at a time is the pathological case for every state machine in this path: the
    // chunk-size line, the gzip header, the deflate stream, `</body>`, and the terminal chunk all end
    // up split.
    let rules = plan_for(&engine, "https://example.com/");
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let chunks: Vec<&[u8]> = origin.chunks(1).collect();
    let run = drive(&mut rewriter, &chunks);
    assert!(!run.broke, "the response must be completable");
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(run.report.injected, "nothing was injected");
    assert!(text.contains("<div class=ad>x</div>"), "{text}");
}

#[test]
fn a_corrupt_gzip_body_is_reported_instead_of_delivered_wrong() {
    let engine = build_engine("example.com##.ad\n");
    let body = b"<!doctype html><html><head></head><body>x</body></html>";
    let mut compressed = gzip(body);
    // Corrupt the deflate payload (not the 10-byte header).
    let middle = compressed.len() / 2;
    compressed[middle] ^= 0xFF;
    compressed[middle + 1] ^= 0xFF;
    let origin = response(&["Content-Encoding: gzip"], &compressed);

    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    assert!(
        run.broke,
        "a corrupt coding has to be reported so the connection is closed"
    );
}

// ---------------------------------------------------------------------------------------------
// Generic rules
// ---------------------------------------------------------------------------------------------

#[test]
fn generic_rules_are_keyed_on_the_class_and_id_values_the_document_contains() {
    // A generic rule (no hostname) that only applies when the page has `.ad-slot`.
    let engine = build_engine("##.ad-slot\n###sponsored\n");
    let body = b"<!doctype html><html><head></head><body>\
                 <div class=\"ad-slot\">ad</div><div id=\"sponsored\">s</div></body></html>";
    let origin = response(&[], body);

    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();

    assert!(run.report.generic >= 2, "report: {:?}", run.report);
    let generic_at = text.find("data-zshield=\"generic\"").expect("a generic style");
    let body_close = text.find("</body>").expect("the body's end");
    assert!(
        generic_at > body_close,
        "the generic style goes at the end of the document, not inside a script string that happens to \
         contain `</body>`: {text}"
    );
    assert!(text[generic_at..].contains(".ad-slot"), "{text}");
    assert!(text[generic_at..].contains("#sponsored"), "{text}");
}

/// The plan for `url`, with `unhide_rules` in force as global (`#@#`/`*#@#`) exceptions.
///
/// A separate helper rather than another argument to [`plan_for`] because most tests have no unhide
/// rules, and the ones that do are the ones this documents.
fn plan_with_unhides(engine: &Arc<adblock::Engine>, url: &str, unhide_rules: &str) -> Plan {
    let mut unhides = crate::cosmetic::unhide::GlobalUnhides::default();
    unhides.add_list(unhide_rules);
    let mut plan = plan_for(engine, url);
    plan.global_unhides = Arc::new(unhides);
    plan
}

#[test]
fn a_global_unhide_removes_the_selector_the_engine_still_hides() {
    // The element-hiding page's case 3, reduced: a domain rule hides two siblings, and a *global*
    // unhide (`*#@#` / `#@#`) un-hides one of them. adblock 0.13.5 drops both spellings — `#@#x` is a
    // `GenericUnhide` parse error and `*#@#x` hashes to a location that never matches — so the engine
    // hands back both selectors. Without [`crate::cosmetic::unhide`] the browser would hide the
    // element the list explicitly asked to keep.
    let engine = build_engine(
        "testcases.agrd.dev###case-3 > .test-banner\n\
         testcases.agrd.dev###case-3 > h2\n",
    );
    let url = "https://testcases.agrd.dev/x.html";
    // The engine's own answer: nothing was unhidden.
    assert_eq!(
        plan_for(&engine, url).hide_selectors.len(),
        2,
        "precondition: the engine does not honour a global unhide"
    );

    let plan = plan_with_unhides(&engine, url, "#@##case-3 > h2\n");
    assert_eq!(
        plan.hide_selectors.len(),
        2,
        "the plan still carries both; the unhide is applied when the style is written"
    );

    let body = b"<!doctype html><html><head></head><body>\
                 <div id=\"case-3\"><div class=\"test-banner\">b</div><h2>h</h2></div></body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(plan, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();

    assert!(
        text.contains("#case-3 > .test-banner"),
        "the rule the list did not except must still hide: {text}"
    );
    assert!(
        !text.contains("#case-3 > h2"),
        "the globally-unhidden selector must not reach the browser: {text}"
    );
    assert_eq!(run.report.specific, 1, "report: {:?}", run.report);
}

#[test]
fn a_global_unhide_also_removes_a_generic_selector() {
    // A `##` rule reaches the browser through the class/id channel, not the hostname channel, so an
    // unhide that only filtered `hide_selectors` would leave the generic style hiding it again.
    //
    // Two generic rules, one excepted: with only one, removing it leaves nothing to inject and the
    // test could not tell "the unhide worked" from "the rewriter gave up".
    let engine = build_engine("##.ad-slot\n##.kept-ad\n");
    let url = "https://example.com/";
    let body = b"<!doctype html><html><head></head><body>\
                 <div class=\"ad-slot\">ad</div><div class=\"kept-ad\">k</div></body></html>";

    let plan = plan_with_unhides(&engine, url, "*#@#.ad-slot\n");
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(plan, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();

    assert!(run.report.injected, "nothing was injected");
    assert!(
        !text.contains(".ad-slot"),
        "the generic channel reintroduced what the unhide removed: {text}"
    );
    assert!(
        text.contains(".kept-ad"),
        "the rule the unhide does not name must still hide: {text}"
    );
}

#[test]
fn plan_for_has_no_global_unhides_by_default() {
    // Guards the default: every existing test builds its plan through `plan_for`, so a non-empty
    // default here would silently change what those tests measure.
    let engine = build_engine("example.com##.ad-banner\n");
    let plan = plan_for(&engine, "https://example.com/");
    assert!(plan.global_unhides.is_empty());
}

#[test]
fn a_generic_rule_for_a_class_the_document_does_not_have_is_not_injected() {
    let engine = build_engine("##.ad-slot\n");
    let body = b"<!doctype html><html><head></head><body><div class=\"other\">x</div></body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert_eq!(run.report.generic, 0);
    assert!(!text.contains(".ad-slot"), "{text}");
}

#[test]
fn generichide_suppresses_the_generic_style_but_not_the_specific_one() {
    let engine = build_engine("example.com##.specific-ad\nexample.com#@#.ad-slot\n@@||example.com^$generichide\n##.ad-slot\n");
    let body = b"<!doctype html><html><head></head><body><div class=\"ad-slot specific-ad\">x</div></body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(run.report.injected, "the specific rule must still be injected");
    assert!(!text.contains("data-zshield=\"generic\""), "{text}");
    assert!(text.contains(".specific-ad"), "{text}");
}

#[test]
fn a_body_close_tag_inside_a_script_string_does_not_split_the_script() {
    // `</body` appears inside an inline script. Inserting the generic style at the *first* `</body`
    // would splice our newline-bearing markup into a JavaScript string and break the page; the end of
    // the document is a position the HTML parser accepts a `<style>` in regardless.
    let engine = build_engine("##.ad-slot\n");
    let body = b"<!doctype html><html><head></head><body>\
                 <script>document.write(\"<body><\\/body>\");</script>\
                 <div class=\"ad-slot\">x</div></body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(run.report.generic == 1, "the generic style must still be injected");
    let script_at = text.find("<script>document.write").expect("the page's script");
    let generic_at = text.find("data-zshield=\"generic\"").expect("the generic style");
    assert!(
        generic_at > script_at + 20,
        "the generic style must not land inside the page's script: {text}"
    );
    assert!(
        text.contains(r#"<script>document.write("<body><\/body>");</script>"#),
        "the page's own script must survive byte for byte: {text}"
    );
    // And every split point still produces the same document.
    for split in 1..origin.len() {
        let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
        let run = drive(&mut rewriter, &[&origin[..split], &origin[split..]]);
        let (_, split_rewritten) = split_response(&run.bytes);
        assert_eq!(split_rewritten, rewritten, "split at {split}");
    }
}

// ---------------------------------------------------------------------------------------------
// CSP
// ---------------------------------------------------------------------------------------------

#[test]
fn a_strict_csp_gets_a_nonce_and_the_element_carries_it() {
    let engine = build_engine("example.com##.ad\nexample.com##+js(set-constant, adsBlocked, true)\n");
    let body = b"<!doctype html><html><head></head><body><div class=ad>x</div></body></html>";
    let origin = response(
        &["Content-Security-Policy: default-src 'self'; script-src 'self'"],
        body,
    );
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (head, rewritten) = split_response(&run.bytes);
    let head_text = String::from_utf8_lossy(head).to_string();
    let body_text = String::from_utf8_lossy(&rewritten).to_string();

    let nonce = head_text
        .split("'nonce-")
        .nth(1)
        .and_then(|rest| rest.split('\'').next())
        .expect("a nonce in the policy");
    assert!(body_text.contains(&format!("nonce=\"{nonce}\"")), "{body_text}");
    assert!(head_text.contains("script-src 'self' 'nonce-"), "{head_text}");
    assert!(run.report.scriptlet);
}

#[test]
fn an_unsafe_inline_csp_gets_no_nonce_and_no_element_that_would_need_one() {
    let engine = build_engine("example.com##.ad\n");
    let body = b"<!doctype html><html><head></head><body><div class=ad>x</div></body></html>";
    let origin = response(
        &["Content-Security-Policy: default-src 'self' 'unsafe-inline'"],
        body,
    );
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (head, rewritten) = split_response(&run.bytes);
    let head_text = String::from_utf8_lossy(head).to_string();
    let body_text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(
        !head_text.contains("'nonce-"),
        "a nonce would switch 'unsafe-inline' off: {head_text}"
    );
    // The style is still injected: `'unsafe-inline'` allows it.
    assert!(body_text.contains("<style"), "{body_text}");
    assert!(!body_text.contains("nonce="), "{body_text}");
}

#[test]
fn a_default_src_only_policy_is_extended_on_default_src() {
    let engine = build_engine("example.com##.ad\n");
    let body = b"<!doctype html><html><head></head><body>x</body></html>";
    let origin = response(&["Content-Security-Policy: default-src 'none'"], body);
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (head, _) = split_response(&run.bytes);
    let head_text = String::from_utf8_lossy(head).to_string();
    assert!(head_text.contains("default-src 'none' 'nonce-"), "{head_text}");
    assert!(!head_text.contains("style-src"), "{head_text}");
}

#[test]
fn a_meta_csp_in_the_body_is_counted_and_left_alone() {
    let engine = build_engine("example.com##.ad\n");
    let body = b"<!doctype html><html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'\"></head><body>x</body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(run.report.csp_meta, "the meta policy has to be counted");
    assert!(
        text.contains("<meta http-equiv=\"Content-Security-Policy\""),
        "the meta tag must be untouched: {text}"
    );
}

// ---------------------------------------------------------------------------------------------
// Scriptlets
// ---------------------------------------------------------------------------------------------

#[test]
fn a_scriptlet_rule_puts_callable_code_in_the_document() {
    let engine = build_engine("example.com##+js(set-constant, adblockDetected, false)\n");
    let body = b"<!doctype html><html><head></head><body>x</body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(run.report.scriptlet);
    let script_at = text.find("data-zshield=\"scriptlets\"").expect("a script");
    assert!(text[script_at..].contains("function setConstantFn"));
    assert!(text[script_at..].contains("setConstant(\"adblockDetected\""));
    // And it is after the `<style>` when both are present, so a hiding rule applies before the
    // page's own scripts run.
    let doc = b"<!doctype html><html><head></head><body><div class=ad>x</div></body></html>";
    let engine2 = build_engine("example.com##.ad\nexample.com##+js(set-constant, a, false)\n");
    let origin2 = response(&[], doc);
    let mut rewriter = Rewriter::new(plan_for(&engine2, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin2]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    let style_at = text.find("data-zshield=\"specific\"").expect("a style");
    let script_at = text.find("data-zshield=\"scriptlets\"").expect("a script");
    assert!(style_at < script_at, "the style must come first: {text}");
}

// ---------------------------------------------------------------------------------------------
// Responses that must not be touched
// ---------------------------------------------------------------------------------------------

#[test]
fn a_non_html_response_is_byte_for_byte_unchanged() {
    let engine = build_engine("example.com##.ad\n");
    let origin = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"ok\":true}\n";
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[origin]);
    assert_eq!(run.bytes, origin.to_vec());
    assert!(run.verbatim);
    assert!(!run.report.injected);
}

#[test]
fn a_non_200_response_is_byte_for_byte_unchanged() {
    let engine = build_engine("example.com##.ad\n");
    let origin = b"HTTP/1.1 304 Not Modified\r\nContent-Type: text/html\r\n\r\n";
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[origin]);
    assert_eq!(run.bytes, origin.to_vec());
    assert!(run.verbatim);
}

#[test]
fn a_document_with_nothing_to_inject_is_byte_for_byte_unchanged() {
    // An empty plan — no engine at all — means the response is not this code's to touch.
    let body = b"<!doctype html><html><head></head><body>x</body></html>";
    let origin = response(&[], body);
    let rules = Plan::default();
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    assert_eq!(run.bytes, origin, "a page with no rule must be delivered unchanged");
    assert!(run.verbatim);
}

#[test]
fn a_page_no_rule_matches_keeps_its_bytes_when_generic_rules_are_possible() {
    // The engine has rules but none for this host, and a generic rule cannot match either. The
    // document's own bytes must still come back untouched — only the framing changes, because whether
    // a generic rule matches is only known at `</body>` and the length cannot be declared up front.
    let engine = build_engine("example.com##.ad\n##.unused-class\n");
    let body = b"<!doctype html><html><head></head><body>x</body></html>";
    let origin = response(&[], body);
    let rules = plan_for(&engine, "https://other.example/");
    assert!(rules.hide_selectors.is_empty());
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    assert_eq!(rewritten, body.to_vec(), "the document's bytes must not change");
    assert!(!run.report.injected, "nothing should have been inserted");
}

#[test]
fn an_undecodable_coding_is_byte_for_byte_unchanged() {
    let engine = build_engine("example.com##.ad\n");
    let mut origin = Vec::new();
    origin.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: br\r\n\r\n");
    origin.extend_from_slice(&[0x1b, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00]);
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    assert_eq!(run.bytes, origin, "a coding we cannot decode must not be touched");
    assert!(run.verbatim);
}

// ---------------------------------------------------------------------------------------------
// HTTP/2 framing
// ---------------------------------------------------------------------------------------------

#[test]
fn an_unframed_rewrite_sends_the_body_without_a_content_length_or_chunking() {
    let engine = build_engine("example.com##.ad\n");
    let body = b"<!doctype html><html><head></head><body><div class=ad>x</div></body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Unframed);
    let run = drive(&mut rewriter, &[&origin]);
    let (head, rewritten) = split_response(&run.bytes);
    let head_text = String::from_utf8_lossy(head).to_ascii_lowercase();
    assert!(!head_text.contains("transfer-encoding"), "{head_text}");
    assert!(!head_text.contains("content-length"), "{head_text}");
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(!text.contains("\r\n0\r\n"), "no terminal chunk on h2: {text:?}");
    assert!(text.contains("<style"), "{text}");
    assert!(text.ends_with("</body></html>"), "{text}");
}

// ---------------------------------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------------------------------

#[test]
fn a_document_delivered_one_byte_at_a_time_is_injected_correctly() {
    let engine = build_engine("example.com##.ad\n##.ad-slot\n");
    let body = b"<!doctype html><html><head><title>t</title></head><body><div class=\"ad ad-slot\">x</div></body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let chunks: Vec<&[u8]> = origin.chunks(1).collect();
    let run = drive(&mut rewriter, &chunks);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(run.report.injected);
    assert!(text.contains(".ad\n{ display: none !important; }"), "{text}");
    assert!(text.contains("<div class=\"ad ad-slot\">x</div>"), "{text}");
}

#[test]
fn a_large_document_is_streamed_without_buffering_it() {
    let engine = build_engine("example.com##.ad\n");
    let mut body = b"<!doctype html><html><head><title>t</title></head><body>".to_vec();
    for index in 0..20000 {
        body.extend_from_slice(format!("<div class=\"row-{index}\">row {index}</div>\n").as_bytes());
    }
    body.extend_from_slice(b"</body></html>");
    let origin = response(&[], &body);

    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    // 32 KiB feeds, the relay's own copy buffer: the output must not accumulate the whole document.
    let mut total = 0usize;
    let mut biggest = 0usize;
    for chunk in origin.chunks(32 * 1024) {
        let emitted = rewriter.push(chunk);
        total += emitted.bytes.len();
        biggest = biggest.max(emitted.bytes.len());
    }
    let last = rewriter.finish(true);
    total += last.bytes.len();
    biggest = biggest.max(last.bytes.len());
    assert!(
        biggest < body.len(),
        "one push must not emit the whole document ({biggest} of {})",
        body.len()
    );
    assert!(total > body.len(), "the document must actually come back out");
}

#[test]
fn a_selector_with_a_brace_cannot_escape_its_rule_block() {
    let rules = Plan {
        hide_selectors: vec![
            ".ok".to_string(),
            ".bad { } body { display: none }".to_string(),
        ],
        engine: Some(build_engine("")),
        ..Plan::default()
    };
    let body = b"<!doctype html><html><head></head><body>x</body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(text.contains(".ok"), "{text}");
    assert!(!text.contains("body { display: none }"), "{text}");
}

#[test]
fn the_report_says_what_was_inserted() {
    let engine = build_engine("example.com##.ad\nexample.com##+js(set-constant, x, false)\n##.ad-slot\n");
    let body = b"<!doctype html><html><head></head><body><div class=\"ad ad-slot\">x</div></body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(plan_for(&engine, "https://example.com/"), OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    assert!(run.report.injected);
    assert_eq!(run.report.specific, 1);
    assert_eq!(run.report.generic, 1);
    assert!(run.report.scriptlet);
    assert!(!run.report.csp_meta);
}

#[test]
fn many_selectors_are_split_into_independent_blocks() {
    let rules = Plan {
        hide_selectors: (0..450).map(|index| format!(".ad-{index}")).collect(),
        engine: Some(build_engine("")),
        ..Plan::default()
    };
    let body = b"<!doctype html><html><head></head><body>x</body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    // 450 selectors at 200 per block: three rule lists, so one bad selector cannot lose the rest.
    assert_eq!(
        text.matches("{ display: none !important; }").count(),
        3,
        "{text}"
    );
    assert!(text.contains(".ad-449"), "the last selector must be there");
}

// ---------------------------------------------------------------------------------------------
// Cost
// ---------------------------------------------------------------------------------------------

#[test]
fn the_injection_latency_budget_is_met() {
    // The acceptance criterion is "first-byte extra latency p50 < 20 ms". What the injector adds
    // before the first byte can be written is: decode the prefix, find the insertion point, build
    // the two `<style>`/`<script>` bodies, and query the engine for generic rules. This measures
    // exactly that on a realistic document, so a regression is caught here rather than on a device.
    let mut rules = String::new();
    for index in 0..2000 {
        rules.push_str(&format!("example.com##.ad-slot-{index}\n"));
    }
    let engine = build_engine(&rules);
    let selectors = plan_for(&engine, "https://example.com/page").hide_selectors;

    let mut body = b"<!doctype html><html><head><title>t</title></head><body>".to_vec();
    for index in 0..4000 {
        // A realistic row: a class that matches a generic rule and an id that does not.
        body.extend_from_slice(
            format!(
                "<div class=\"ad-slot-{} row-{index}\" id=\"item-{index}\">\
                 <a href=\"/p/{index}\">link {index}</a><span>text</span></div>\n",
                index % 2000
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(b"</body></html>");

    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Security-Policy: \
         default-src 'self'\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();

    let mut timings = Vec::new();
    for _ in 0..30 {
        let rules = Plan {
            hide_selectors: selectors.clone(),
            engine: Some(engine.clone()),
            ..Plan::default()
        };
        let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
        let started = std::time::Instant::now();
        // Feed the head plus the first 32 KiB of body — the relay's copy buffer — and stop as soon as
        // the injector has produced its first byte.
        let mut first = rewriter.push(&head);
        let rest = rewriter.push(&body[..32 * 1024]);
        first.bytes.extend_from_slice(&rest.bytes);
        let elapsed = started.elapsed();
        assert!(!first.bytes.is_empty(), "the first bytes must be produced");
        timings.push(elapsed);
    }
    timings.sort_unstable();
    let p50 = timings[timings.len() / 2];
    let p95 = timings[(timings.len() * 95) / 100];
    println!("injection latency: p50={p50:?} p95={p95:?}");
    assert!(
        p50 < std::time::Duration::from_millis(20),
        "p50 injection latency must stay under 20 ms, got {p50:?} (p95 {p95:?})"
    );
}

// ---------------------------------------------------------------------------------------------
// Security: a subscription is untrusted input (review item 1)
// ---------------------------------------------------------------------------------------------

#[test]
fn a_selector_that_would_close_the_style_element_is_dropped() {
    // `div[title="</style><script>…</script>"]` is a legal CSS selector that ends our `<style>` early
    // and turns every decrypted page into an XSS sink. The subscription that carried it is untrusted.
    let rules = Plan {
        hide_selectors: vec![
            ".honest-ad".to_string(),
            r#"div[title="</style><script>alert(1)</script>"]"#.to_string(),
            "a[b='<']".to_string(),
        ],
        engine: Some(build_engine("")),
        ..Plan::default()
    };
    let body = b"<!doctype html><html><head></head><body>x</body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();

    assert!(text.contains(".honest-ad"), "the honest rule must survive: {text}");
    assert!(!text.contains("<script>alert(1)"), "the payload must not reach the page: {text}");
    assert!(
        !text.contains("title=\""),
        "the hostile selector must be dropped entirely: {text}"
    );
    // Exactly the one style element we emit, and no second script.
    assert_eq!(text.matches("</style>").count(), 1, "{text}");
    assert_eq!(text.matches("alert(1)").count(), 0, "{text}");
    assert_eq!(run.report.rejected_selectors, 2, "both unsafe selectors are counted");
    assert_eq!(run.report.specific, 1, "only the honest selector is reported");
}

#[test]
fn a_generic_rule_selector_cannot_close_the_style_element_either() {
    // The generic path takes selectors from the same untrusted lists, by way of the engine.
    let mut rules = Plan {
        engine: Some(build_engine("")),
        ..Plan::default()
    };
    rules.hide_selectors.clear();
    // A generic selector that a document's class brings in, with a hostile `<` in it.
    rules.exceptions = Default::default();
    // The generic rule is keyed on `.ad-slot`; the hostile `[title=…]` tail comes with it.
    let engine = build_engine(r#"##.ad-slot[title="</style><script>x</script>"]"#);
    let _ = &engine;
    rules.engine = Some(engine);
    let body = br#"<!doctype html><html><head></head><body><div class="ad-slot" title="a"></div></body></html>"#;
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(!text.contains("<script>x</script>"), "{text}");
    // The engine *did* return it — that is what makes this test meaningful — and it was the only
    // selector, so the style element is now empty and correctly not emitted at all.
    assert!(
        !text.contains("ad-slot[title"),
        "the hostile generic selector must not reach the page: {text}"
    );
    assert!(
        run.report.rejected_selectors >= 1,
        "the dropped selector must be counted: {:?}",
        run.report
    );
    assert!(!run.report.injected, "nothing was injected: {:?}", run.report);
}

#[test]
fn a_scriptlet_argument_cannot_close_the_script_element() {
    // A scriptlet argument is arbitrary text from the list. `</script>` in it must not end our element.
    let rules = Plan {
        injected_script: "setConstant(\"a\", \"</script><script>alert(1)</script>\");".to_string(),
        engine: Some(build_engine("")),
        ..Plan::default()
    };
    let body = b"<!doctype html><html><head></head><body>x</body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();

    // Our `<script …>` opens; the *next* `</script` must be the one that closes it — no second one in
    // between, which is exactly what an unescaped `</script>` in the argument would produce.
    let open = text.find("data-zshield=\"scriptlets\"").expect("our script element");
    let after_open = &text[open..];
    let first_close = after_open.find("</script").expect("a closing tag");
    let between = &after_open[..first_close];
    assert!(
        !between.contains("</script"),
        "the argument must not close the element early: {between}"
    );
    assert_eq!(
        after_open.matches("</script").count(),
        1,
        "exactly one closing tag: {text}"
    );
    assert!(between.contains("<\\/script"), "the payload is escaped: {between}");
    assert!(!text.contains("<script>alert(1)</script>"), "{text}");
}

#[test]
fn a_html_comment_opener_in_a_scriptlet_is_escaped() {
    // `<!--` inside a script element starts an HTML comment and would comment out the rest of the bundle.
    let rules = Plan {
        injected_script: "var a = 1; <!-- var b = 2;".to_string(),
        engine: Some(build_engine("")),
        ..Plan::default()
    };
    let body = b"<!doctype html><html><head></head><body>x</body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(text.contains("<\\!--"), "the comment opener is escaped: {text}");
    assert!(!text.contains("<!-- var b"), "{text}");
}

// ---------------------------------------------------------------------------------------------
// The body state machine's own guarantees (review items 2-6, 8-9)
// ---------------------------------------------------------------------------------------------

#[test]
fn h2_give_up_keeps_the_whole_document_including_the_undecided_prefix() {
    // HTTP/2 has no origin-framed bytes to replay: the head this core already sent says `identity`, so
    // dropping the decoded prefix would hand the client a page with its first 64 KiB missing — and for a
    // gzip document it would hand it compressed bytes under an identity head.
    let engine = build_engine("example.com##.ad\n");
    let mut body = b"<div>".to_vec();
    body.extend(std::iter::repeat_n(b'x', crate::cosmetic::scan::SCAN_WINDOW + 4096));
    body.extend_from_slice(b"</div>");
    let payload_len = body.len();
    let compressed = gzip(&body);
    let mut origin = Vec::new();
    origin.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n\r\n");
    origin.extend_from_slice(&compressed);

    let rules = plan_for(&engine, "https://example.com/");
    let mut rewriter = Rewriter::new(rules, OutFraming::Unframed);
    let run = drive(&mut rewriter, &[&origin]);
    assert!(!run.broke, "the response must be completable");
    // The head is the caller's to render (HTTP/2 builds it from headers), so the driver's output here is
    // body bytes only — the same shape the h2 relay forwards.
    assert_eq!(
        run.bytes.len(),
        body.len(),
        "the decoded document must arrive whole ({payload_len} bytes)"
    );
    let first_difference = run
        .bytes
        .iter()
        .zip(body.iter())
        .position(|(left, right)| left != right);
    assert_eq!(first_difference, None, "and byte for byte");
    assert!(!run.report.injected, "nothing was injected");
}

#[test]
fn an_h2_document_whose_prefix_ends_mid_tag_is_still_whole() {
    // The body ends inside `<hea`: the injector must still emit everything it buffered.
    let engine = build_engine("example.com##.ad\n");
    let body = b"<html><hea";
    let origin = response(&[], body);
    let rules = plan_for(&engine, "https://example.com/");
    let mut rewriter = Rewriter::new(rules, OutFraming::Unframed);
    let run = drive(&mut rewriter, &[&origin]);
    assert!(!run.broke, "a short document is still completable");
    let (_, rewritten) = split_response(&run.bytes);
    assert_eq!(rewritten, body.to_vec(), "not one byte may be lost");
    let _ = rewriter;
}

#[test]
fn a_truncated_origin_body_is_not_closed_as_if_it_were_whole() {
    // The origin sent `Content-Length: 100` and then died after 40 bytes. The client must not be told it
    // has a complete document: no terminal chunk, and `broke` so the caller closes the connection.
    let engine = build_engine("example.com##.ad\n");
    let mut origin = Vec::new();
    origin.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 4000\r\n\r\n");
    origin.extend_from_slice(b"<!doctype html><html><head></head><body><div class=ad>x");
    let rules = plan_for(&engine, "https://example.com/");
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let mut run = Run::default();
    run.absorb(rewriter.push(&origin));
    // The origin's framing never completed, so the caller's verdict is "truncated".
    run.absorb(rewriter.finish(false));
    assert!(run.broke, "a truncated body must be reported, not closed");
    assert!(
        !run.bytes.ends_with(b"0\r\n\r\n"),
        "no terminal chunk may be written for a truncated body"
    );
}

#[test]
fn a_truncated_gzip_stream_is_not_closed_as_if_it_were_whole() {
    // The HTTP framing completed but the gzip member did not: the decoded bytes are a prefix of the
    // document, so the response is equally incomplete.
    let engine = build_engine("example.com##.ad\n");
    let document = b"<!doctype html><html><head></head><body>\
                     <p>a fairly long paragraph so the deflate stream has several blocks</p>\
                     <div class=ad>x</div></body></html>";
    let mut compressed = gzip(document);
    compressed.truncate(compressed.len() / 2);
    let mut origin = Vec::new();
    origin.extend_from_slice(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n\
          Content-Length: ",
    );
    origin.extend_from_slice(compressed.len().to_string().as_bytes());
    origin.extend_from_slice(b"\r\n\r\n");
    origin.extend_from_slice(&compressed);

    let rules = plan_for(&engine, "https://example.com/");
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let mut run = Run::default();
    run.absorb(rewriter.push(&origin));
    // The HTTP framing was satisfied (the origin sent exactly what it declared), but the gzip member
    // is cut — so the document is still incomplete and the injector must say so itself.
    run.absorb(rewriter.finish(true));
    assert!(
        run.broke,
        "an unfinished gzip member must not be closed as if the document were whole"
    );
    assert!(!run.bytes.ends_with(b"0\r\n\r\n"), "no terminal chunk");
}

#[test]
fn a_gzip_members_trailing_bytes_never_appear_unframed_in_the_body() {
    // Bytes after the gzip member (a second member, or junk) must not be written raw into a chunked
    // body: the client would read them as a chunk header and report a framing error.
    let engine = build_engine("example.com##.ad\n");
    let document = b"<!doctype html><html><head></head><body><div class=ad>x</div></body></html>";
    let mut compressed = gzip(document);
    compressed.extend_from_slice(b"GARBAGE-AFTER-THE-MEMBER");
    let mut origin = Vec::new();
    origin.extend_from_slice(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: ",
    );
    origin.extend_from_slice(compressed.len().to_string().as_bytes());
    origin.extend_from_slice(b"\r\n\r\n");
    origin.extend_from_slice(&compressed);

    let rules = plan_for(&engine, "https://example.com/");
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    // `split_response` de-chunks, so a framing error would panic there.
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(
        !text.contains("GARBAGE"),
        "trailing bytes must be dropped, not emitted: {text}"
    );
    assert!(text.contains("<div class=ad>x</div>"), "{text}");
}

#[test]
fn a_decompression_bomb_does_not_materialize_its_whole_expansion() {
    // 8 MiB of zeros compresses to a few KiB. The decoder must produce it in bounded rounds, so peak
    // memory stays near one round rather than near the whole expansion.
    let engine = build_engine("example.com##.ad\n");
    let mut document = b"<!doctype html><html><head></head><body><div class=ad>".to_vec();
    document.extend(std::iter::repeat_n(b'z', 8 * 1024 * 1024));
    document.extend_from_slice(b"</div></body></html>");
    let compressed = gzip(&document);
    assert!(
        compressed.len() < document.len() / 100,
        "the payload must actually be a bomb: {} -> {}",
        document.len(),
        compressed.len()
    );

    let mut origin = Vec::new();
    origin.extend_from_slice(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: ",
    );
    origin.extend_from_slice(compressed.len().to_string().as_bytes());
    origin.extend_from_slice(b"\r\n\r\n");
    origin.extend_from_slice(&compressed);

    // The property under test belongs to the decoder: what it holds in memory, not what it hands back.
    // A caller necessarily receives the whole document eventually (it is 8 MiB of content); what must
    // stay bounded is the buffer that exists *before* each round is handed over.
    let mut decoder = crate::cosmetic::gzip::GzipDecoder::new();
    decoder.push(&compressed);
    let mut biggest_round = 0usize;
    while let Some(chunk) = decoder.drain() {
        biggest_round = biggest_round.max(chunk.len());
    }
    assert!(
        biggest_round <= crate::cosmetic::gzip::OUTPUT_CHUNK,
        "each round must stay within OUTPUT_CHUNK, got {biggest_round}"
    );
    assert!(
        decoder.is_done(),
        "the whole member must have been expanded in those rounds"
    );
    assert!(
        decoder.buffered_input() < compressed.len() / 2,
        "input is consumed as it is expanded, not held: {} of {}",
        decoder.buffered_input(),
        compressed.len()
    );

    // And end to end through the rewriter, the document still arrives complete and correct in framing.
    let rules = plan_for(&engine, "https://example.com/");
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    // The only difference from the origin's document is the injected `<style>`: strip our markup and the
    // rest must be byte-identical, which also proves nothing was dropped along the way.
    let style_start = rewritten
        .windows(6)
        .position(|window| window == b"<style")
        .expect("the injected style");
    let close_at = rewritten
        .windows(8)
        .position(|window| window == b"</style>")
        .expect("the style's end")
        + 8;
    // The injected element ends with its own newline so the page's next byte starts on a fresh line.
    let style_end = close_at + usize::from(rewritten.get(close_at) == Some(&b'\n'));
    let mut without_style = Vec::new();
    without_style.extend_from_slice(&rewritten[..style_start]);
    without_style.extend_from_slice(&rewritten[style_end..]);
    // Summarized: an 8 MiB `assert_eq!` would dump both buffers into the failure message.
    assert_eq!(
        without_style.len(),
        document.len(),
        "the document must arrive whole once the injected markup is removed"
    );
    let first_difference = without_style
        .iter()
        .zip(document.iter())
        .position(|(left, right)| left != right);
    assert_eq!(
        first_difference, None,
        "the document must be byte-identical once the injected markup is removed"
    );
}

#[test]
fn an_abandoned_document_still_gets_its_response_head_edits() {
    // `$removeheader` and `$csp` belong to the *request*, not to the cosmetic decision. A document whose
    // injection was abandoned must still get them (review item 8).
    let engine = build_engine("example.com##.ad\n");
    let mut body = b"<div>".to_vec();
    body.extend(std::iter::repeat_n(b'x', crate::cosmetic::scan::SCAN_WINDOW + 4096));
    let origin = response(&["X-Drop: me"], &body);
    let mut rules = plan_for(&engine, "https://example.com/");
    rules.drop_response_headers = vec!["x-drop".to_string()];
    rules.extra_csp = Some("script-src 'none'".to_string());
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let text = String::from_utf8_lossy(&run.bytes).to_string();
    assert!(
        !text.to_ascii_lowercase().contains("x-drop"),
        "`$removeheader` must still apply: {text}"
    );
    assert!(
        text.contains("Content-Security-Policy: script-src 'none'"),
        "`$csp` must still apply: {text}"
    );
    assert_eq!(run.bytes, {
        let mut expected_head = Vec::new();
        expected_head.extend_from_slice(&run.bytes[..run.bytes.len() - body.len()]);
        let mut expected = expected_head;
        expected.extend_from_slice(&body);
        expected
    }, "the body itself must be untouched");
}

#[test]
fn a_generic_rule_gets_a_nonce_even_with_no_specific_selectors() {
    // The `<style>` a generic rule needs is only discovered mid-body, so the nonce for it has to be
    // decided up front — otherwise the element is refused by a strict `style-src` (review item 9).
    let rules = Plan {
        engine: Some(build_engine("##.ad-slot\n")),
        ..Plan::default()
    };
    assert!(rules.hide_selectors.is_empty(), "no specific selectors");
    let body = b"<!doctype html><html><head></head><body><div class=\"ad-slot\">x</div></body></html>";
    let origin = response(&["Content-Security-Policy: default-src 'self'"], body);
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (head, rewritten) = split_response(&run.bytes);
    let head_text = String::from_utf8_lossy(head).to_string();
    let body_text = String::from_utf8_lossy(&rewritten).to_string();
    let nonce = head_text
        .split("'nonce-")
        .nth(1)
        .and_then(|rest| rest.split('\'').next())
        .unwrap_or_else(|| panic!("a nonce must be granted: {head_text}"));
    assert!(
        body_text.contains(&format!("<style nonce=\"{nonce}\"")),
        "the generic style must carry the nonce: {body_text}"
    );
    assert_eq!(run.report.generic, 1);
}

// ---------------------------------------------------------------------------------------------
// Procedural and action rules (M5b §2)
// ---------------------------------------------------------------------------------------------

/// The plan the relays build, including the screened procedural channel.
fn plan_with_procedural(engine: &Arc<adblock::Engine>, url: &str) -> Plan {
    let resources = engine.url_cosmetic_resources(url);
    let validator = crate::cosmetic::validate::shared();
    let check = |selector: &str| validator.check(selector);
    let screen = crate::cosmetic::ProceduralScreen { validate: &check };
    let screened = screen.apply(&resources.procedural_actions);
    Plan {
        hide_selectors: resources.hide_selectors.into_iter().collect(),
        exceptions: resources.exceptions,
        global_unhides: std::sync::Arc::new(
            crate::cosmetic::unhide::GlobalUnhides::default(),
        ),
        injected_script: resources.injected_script,
        procedural: screened.rules,
        procedural_dropped: screened.dropped,
        generichide: resources.generichide,
        engine: Some(engine.clone()),
        drop_response_headers: Vec::new(),
        extra_csp: None,
    }
}

#[test]
fn a_pure_css_style_rule_never_reaches_the_procedural_channel() {
    // `:style()` on a plain selector is expressible as CSS, but the engine stores it in the
    // procedural channel. Screening must keep it there as *data* — what it must never do is hand the
    // selector to the `<style>` path, where the style would be lost.
    let engine = build_engine("example.com##.promo:style(margin:0 !important)\n");
    let resources = engine.url_cosmetic_resources("https://example.com/");
    assert!(
        resources.hide_selectors.is_empty(),
        "the engine must keep a `:style()` rule out of the plain-CSS set: {:?}",
        resources.hide_selectors
    );
    assert_eq!(resources.procedural_actions.len(), 1);

    let plan = plan_with_procedural(&engine, "https://example.com/");
    assert_eq!(plan.procedural.len(), 1);
    assert!(plan.procedural[0].json.contains(r#""type":"style""#));
    assert!(plan.procedural[0].json.contains("margin:0 !important"));
    assert_eq!(plan.procedural_dropped, 0);
}

#[test]
fn a_procedural_rule_is_injected_as_json_data_and_never_as_code() {
    // The acceptance criterion for the injection surface: a rule whose arguments contain
    // `</script>`, quotes and a newline must arrive as *data* — the script element may not end early
    // and no part of the rule may become executable.
    let engine = build_engine(
        "example.com##div:has-text(\"</script><img src=x onerror=alert(1)>\", 'quoted', \\n)\n\
         example.com##.ad:style(color:red)\n",
    );
    let plan = plan_with_procedural(&engine, "https://example.com/");
    let body = b"<!doctype html><html><head></head><body><div>x</div></body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(plan, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();

    // Exactly one `</script>` in the document: the one that ends the injected element. Any second one
    // would mean a rule argument closed it.
    assert_eq!(
        text.matches("</script>").count(),
        1,
        "a rule argument must not close the script element: {text}"
    );
    assert!(text.contains("data-zshield=\"procedural\""), "{text}");
    // The `</script>` in the argument survives as JS data, escaped.
    assert!(text.contains("<\\/script"), "{text}");
    assert!(!text.contains("onerror=alert(1)>\""), "the argument is data, not markup: {text}");
    assert!(run.report.procedural);
}

#[test]
fn one_broken_procedural_selector_costs_only_its_own_rule() {
    // The defect M5a measured, at the level of the injected bytes: a rule whose CSS half the browser
    // cannot parse must be dropped on its own, and the rules next to it must still be in the script.
    let engine = build_engine(
        "example.com##.good-one:style(color:red)\n\
         example.com##.broken:contains(Refresh)\n\
         example.com##.good-two:remove()\n",
    );
    let plan = plan_with_procedural(&engine, "https://example.com/");
    // `.broken` is dropped by the *engine's* own validation and never reaches the plan, so the count is
    // taken from what the engine offered: `:contains()` is not a procedural operator either.
    assert!(
        plan.procedural.len() + plan.procedural_dropped <= 3,
        "the plan cannot carry more rules than the list had"
    );
    let text = plan
        .procedural
        .iter()
        .map(|rule| rule.json.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains(".good-one"), "{text}");
    assert!(text.contains(".good-two"), "{text}");
    assert!(!text.contains(".broken"), "{text}");
    // Whichever way the engine classified it, the rule must not have cost the others.
    assert!(plan.procedural.len() >= 2);
}

#[test]
fn a_hidden_rule_list_never_contains_a_selector_the_browser_rejects() {
    // The same property for the `<style>` path: the second line of defence is the per-selector screen.
    let mut selectors: Vec<String> = (0..5).map(|i| format!(".ad-{i}")).collect();
    selectors.insert(2, "div:has-text(Sponsored)".to_string());
    selectors.insert(4, "x".repeat(3));
    let rules = Plan {
        hide_selectors: selectors,
        engine: Some(build_engine("")),
        ..Plan::default()
    };
    let body = b"<!doctype html><html><head></head><body>x</body></html>";
    let origin = response(&[], body);
    let mut rewriter = Rewriter::new(rules, OutFraming::Chunked);
    let run = drive(&mut rewriter, &[&origin]);
    let (_, rewritten) = split_response(&run.bytes);
    let text = String::from_utf8_lossy(&rewritten).to_string();
    assert!(!text.contains("has-text"), "{text}");
    for index in 0..5 {
        assert!(text.contains(&format!(".ad-{index}")), "{text}");
    }
    assert_eq!(run.report.rejected_selectors, 1);
}


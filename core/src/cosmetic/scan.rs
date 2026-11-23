//! Finding where injected markup goes, and reading the `class`/`id` values generic rules match on.
//!
//! # The insertion point
//!
//! Rules for a document, in order (task card §3):
//!
//! 1. right after the `>` that closes the first `<head …>`;
//! 2. otherwise right after the `>` that closes the first `<html …>`;
//! 3. otherwise at the very start of the document, skipping a UTF-8 BOM and a `<!doctype …>`.
//!
//! One extra rule is what makes (3) correct in a *stream*: a document with no `<head>` but a `<body>`
//! gets the markup immediately before `<body>`. That is where an HTML5 parser creates the implied
//! head, and inserting there puts the `<style>` in the head rather than inside the body's first
//! element. A document with none of the three is decided at its end ([`find_insertion`]'s `at_eof`).
//!
//! Only **ASCII tag bytes** are matched, never a decoded string: the document may be GBK, Shift-JIS or
//! anything else, and re-encoding it would be a second way to corrupt a page. Every byte this module
//! looks at is ASCII, and every byte it does not is copied through untouched.
//!
//! The search is bounded: a caller holds at most [`SCAN_WINDOW`] bytes. A prefix that long without a
//! place to insert is a pathological document (a data URL, a one-line minified monster), and the
//! caller gives up rather than buffering without bound — counted as `cosmeticSkipped`.
//!
//! # The generic-rule inputs
//!
//! Generic cosmetic rules (`##.ad-banner`, `###sponsored`) are far too numerous to inject as a whole,
//! so the engine is asked which of them the page's actual `class`/`id` values hit. That means
//! collecting those values while the body streams past. [`AttributeScanner`] does it incrementally and
//! never holds more than one unfinished attribute value.

/// How many bytes of a document are searched for the insertion point.
pub const SCAN_WINDOW: usize = 64 * 1024;

/// Longest `class`/`id` value kept. Real values are short; the cap exists so a hostile document cannot
/// make the scanner hold an unbounded string.
pub const MAX_ATTRIBUTE_VALUE: usize = 256;

/// What [`find_insertion`] concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// Insert after this many bytes of the document prefix that was scanned.
    At(usize),
    /// No place yet and the window is not full: the caller buffers more.
    NeedMore,
    /// The window is full without a place: the caller stops buffering and relays verbatim.
    GiveUp,
}

/// An incremental insert-point search over a growing document prefix.
///
/// The prefix grows one relay read at a time. The copy buffer is 32 KiB, so the 64 KiB window is reached
/// in two feeds on HTTP/1.1 — but a TLS or HTTP/2 stream can hand over far smaller pieces, hundreds of
/// them, and re-scanning the whole prefix each time is O(n²) in the number of feeds. This type remembers
/// what it has already established and looks only at the new bytes:
///
/// - where it stopped searching for `<head` / `<html` (`from`), so the next feed starts there;
/// - the end of an `<html …>` tag it has already found (`html_end`), because that tag is the answer only
///   once it is clear no `<head>` follows it, and re-finding it on every feed is the O(n²) part.
///
/// The one byte range that is always re-read is a short tail ([`PARTIAL_TAG_LOOKBEHIND`]), because a tag
/// split across two feeds (`<hea` + `d>`) is not recognisable until the second half arrives.
pub struct Locator {
    /// Where the next search for an opening tag starts.
    from: usize,
    /// One past the `>` of the first `<html …>`, once it has been seen.
    html_end: Option<usize>,
}

impl Locator {
    pub fn new() -> Self {
        Self {
            from: 0,
            html_end: None,
        }
    }

    /// Continue the search over `window`, which must be the whole prefix so far (it only ever grows, so
    /// the offsets this type remembers stay valid).
    pub fn find(&mut self, window: &[u8], at_eof: bool) -> Found {
        let total = window.len();
        // `<head>` wins over `<html>`, and it is the first thing to look for.
        let resume = self.from.saturating_sub(PARTIAL_TAG_LOOKBEHIND);
        match locate_open_tag(&window[resume..], b"head") {
            TagLookup::Found {
                end: Some(end), ..
            } => return Found::At(resume + end),
            TagLookup::Found { end: None, .. } | TagLookup::Partial => {
                // The search must not move past a tag that is still arriving.
                return if total >= SCAN_WINDOW {
                    Found::GiveUp
                } else {
                    Found::NeedMore
                };
            }
            TagLookup::Absent => {}
        }

        // No `<head` yet: find `<html …>` (once) and decide whether it is the answer.
        if self.html_end.is_none() {
            match locate_open_tag(&window[resume..], b"html") {
                TagLookup::Found { end: Some(end), .. } => self.html_end = Some(resume + end),
                TagLookup::Found { end: None, .. } | TagLookup::Partial => {
                    return if total >= SCAN_WINDOW {
                        Found::GiveUp
                    } else {
                        Found::NeedMore
                    };
                }
                TagLookup::Absent => {}
            }
        }
        if let Some(end) = self.html_end {
            // After `<html …>` only whitespace and comments may precede a `<head>`; any other byte means
            // the parser has already implied the head, so `<html>`'s end is the place to insert.
            return match html_content_started(&window[end.min(total)..]) {
                Decision::Started => Found::At(end),
                Decision::Undecided => {
                    if at_eof || total >= SCAN_WINDOW {
                        // No `<head>` is coming; the start of the document is the answer.
                        Found::At(document_start(window))
                    } else {
                        Found::NeedMore
                    }
                }
            };
        }

        if at_eof {
            return Found::At(document_start(window));
        }
        if total >= SCAN_WINDOW {
            return Found::GiveUp;
        }
        // Nothing decided; the next feed resumes just before the end so a split tag is still seen.
        self.from = total.saturating_sub(PARTIAL_TAG_LOOKBEHIND);
        Found::NeedMore
    }
}

impl Default for Locator {
    fn default() -> Self {
        Self::new()
    }
}

/// What the bytes after `<html …>` say about whether a `<head>` can still follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    /// Something other than whitespace or a comment has started: no `<head>` can follow.
    Started,
    /// Only whitespace and comments so far: a `<head>` may still arrive.
    Undecided,
}

/// Inspect the bytes after `<html …>` (HTML5 § 13.2.6.4.3, "before head" insertion mode).
fn html_content_started(rest: &[u8]) -> Decision {
    let mut index = 0usize;
    while index < rest.len() {
        if rest[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if rest[index..].starts_with(b"<!--") {
            match find_ignore_ascii_case(&rest[index + 4..], b"-->") {
                Some(close) => {
                    index = index + 4 + close + 3;
                    continue;
                }
                // An unfinished comment: undecided until it closes.
                None => return Decision::Undecided,
            }
        }
        return Decision::Started;
    }
    Decision::Undecided
}

/// How far an incremental search rewinds so a tag split across two feeds is still seen.
///
/// `<html` is the longest tag name matched here; one more byte covers the character that must follow it.
const PARTIAL_TAG_LOOKBEHIND: usize = 6;

/// Locate the insertion point in the document prefix `window`.
///
/// `at_eof` says the window is the whole document (it ended before the window filled), which makes the
/// last rule — "the start of the document" — decidable. While streaming it is `false`, and a document
/// with neither `<head` nor `<html` is undecided until the window fills, at which point the caller gives
/// up rather than buffer more (task card §3).
pub fn find_insertion(window: &[u8], at_eof: bool) -> Found {
    find_insertion_inner(window, at_eof, 0, window.len())
}

fn find_insertion_inner(window: &[u8], at_eof: bool, base: usize, total: usize) -> Found {
    for name in [b"head".as_slice(), b"html".as_slice()] {
        match locate_open_tag(window, name) {
            // Insert right after the tag's `>`.
            TagLookup::Found {
                end: Some(end), ..
            } => return Found::At(base + end),
            // The tag is there but its `>` has not arrived. Keep waiting, unless the window is full —
            // a `<head` whose attributes run past the window is not worth injecting into.
            TagLookup::Found { end: None, .. } | TagLookup::Partial => {
                return if total >= SCAN_WINDOW {
                    Found::GiveUp
                } else {
                    Found::NeedMore
                }
            }
            TagLookup::Absent => {}
        }
    }
    if at_eof {
        return Found::At(base + document_start(window));
    }
    if total >= SCAN_WINDOW {
        return Found::GiveUp;
    }
    Found::NeedMore
}

/// What [`locate_open_tag`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TagLookup {
    /// An opening tag starting at `start`; `end` is one past its `>` when that has arrived.
    Found { start: usize, end: Option<usize> },
    /// The window ends in the middle of `<name`, which may still become the tag.
    Partial,
    /// No such tag in the window.
    Absent,
}

/// Find the first `<name` opening tag, case-insensitively, and say whether it is closed.
fn locate_open_tag(window: &[u8], name: &[u8]) -> TagLookup {
    let mut index = 0usize;
    while let Some(found) = find_ignore_ascii_case(&window[index..], b"<") {
        let start = index + found;
        let after = start + 1;
        // A closing tag (`</head>`) is not an opening tag; a comment (`<!--`) is not either.
        if matches!(window.get(after), Some(b'/') | Some(b'!')) {
            index = after;
            continue;
        }
        if window.len() < after + name.len() {
            // `<hea` at the end of the window: could still become `<head`.
            if name[..window.len() - after].eq_ignore_ascii_case(&window[after..]) {
                return TagLookup::Partial;
            }
            index = after;
            continue;
        }
        if window[after..after + name.len()].eq_ignore_ascii_case(name) {
            // The name must end there: `<header>` is not `<head>`, `<htmlx>` is not `<html>`.
            match window.get(after + name.len()) {
                Some(byte) if *byte == b'>' || *byte == b'/' || byte.is_ascii_whitespace() => {
                    return TagLookup::Found {
                        start,
                        end: tag_end(window, start),
                    };
                }
                // `<head` with nothing after it in the window: undecided.
                None => {
                    return TagLookup::Found {
                        start,
                        end: None,
                    }
                }
                _ => {}
            }
        }
        index = after;
    }
    TagLookup::Absent
}

/// The offset just past the `>` that closes the tag starting at `open`.
fn tag_end(window: &[u8], open: usize) -> Option<usize> {
    // Quotes are honoured so an attribute value containing `>` does not end the tag early.
    let mut quote: Option<u8> = None;
    for (index, byte) in window.iter().enumerate().skip(open + 1) {
        match quote {
            Some(open_quote) => {
                if *byte == open_quote {
                    quote = None;
                }
            }
            None => match byte {
                b'"' | b'\'' => quote = Some(*byte),
                b'>' => return Some(index + 1),
                _ => {}
            },
        }
    }
    None
}

/// Where content starts: after a UTF-8 BOM, leading whitespace, and a `<!doctype …>` if there is one.
pub fn document_start(window: &[u8]) -> usize {
    let bom = if window.starts_with(&[0xEF, 0xBB, 0xBF]) { 3 } else { 0 };
    let after_bom = bom
        + window[bom..]
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .unwrap_or(window.len() - bom);
    if window.len() < after_bom + 9 || !window[after_bom..after_bom + 9].eq_ignore_ascii_case(b"<!doctype") {
        return after_bom;
    }
    let Some(end) = window[after_bom..].iter().position(|byte| *byte == b'>') else {
        return after_bom;
    };
    let mut offset = after_bom + end + 1;
    // The newline that ends the doctype's line stays with the doctype, so the injected markup starts
    // on its own line and the rest of the document keeps the line structure a diff would show.
    if window.get(offset) == Some(&b'\r') {
        offset += 1;
    }
    if window.get(offset) == Some(&b'\n') {
        offset += 1;
    }
    offset
}

/// ASCII-case-insensitive substring search.
pub fn find_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

/// True when `data` starts with a closing `</body` tag — where the generic-rule `<style>` goes.
pub fn is_body_close_at(data: &[u8]) -> bool {
    data.len() >= 6 && data[..6].eq_ignore_ascii_case(b"</body")
}

/// Collects the `class`/`id` values a document contains, incrementally.
///
/// Deliberately not an HTML parser: it looks for the two attribute names, reads a quoted or unquoted
/// value, and skips everything else. A token inside a `<script>` or a comment may be picked up as an
/// attribute — the only consequence is that one more generic rule is considered, and a rule only hides
/// an element that actually carries the class or id.
#[derive(Debug, Default)]
pub struct AttributeScanner {
    /// Bytes carried over from the previous feed: the tail of an unfinished token.
    carry: Vec<u8>,
    classes: std::collections::HashSet<String>,
    ids: std::collections::HashSet<String>,
}

impl AttributeScanner {
    /// Bytes kept between feeds: the longest possible unfinished value, plus room for a token prefix.
    const CARRY: usize = MAX_ATTRIBUTE_VALUE + 16;

    /// Most classes and most ids remembered. A page with more than this many distinct values is not
    /// going to be helped by the extra ones, and the engine query cost is linear in the input.
    const MAX_VALUES: usize = 4096;

    pub fn new() -> Self {
        Self::default()
    }

    /// Feed document bytes.
    pub fn feed(&mut self, data: &[u8]) {
        let mut buffer = std::mem::take(&mut self.carry);
        buffer.extend_from_slice(data);
        let consumed = self.scan(&buffer);
        let keep_from = consumed.max(buffer.len().saturating_sub(Self::CARRY));
        self.carry = buffer[keep_from..].to_vec();
    }

    /// Scan the readable part of `buffer`, returning how many bytes are finished with.
    ///
    /// Everything up to the last complete token is consumed; what is left is the tail that a later
    /// feed may complete.
    fn scan(&mut self, buffer: &[u8]) -> usize {
        let mut index = 0usize;
        let mut settled = 0usize;
        while index < buffer.len() {
            let Some(relative) = attribute_at(&buffer[index..]) else {
                // No attribute name starts in what is left. Only a partial name at the very end can
                // still matter, and that is at most 5 bytes.
                break;
            };
            index += relative;
            match read_value(buffer, index) {
                Value::Complete { start, end, quote } => {
                    let name = &buffer[index..];
                    let is_class = name.len() >= 5 && name[..5].eq_ignore_ascii_case(b"class");
                    if let Ok(text) = std::str::from_utf8(&buffer[start..end]) {
                        let target = if is_class {
                            &mut self.classes
                        } else {
                            &mut self.ids
                        };
                        for token in text.split_ascii_whitespace() {
                            if target.len() >= Self::MAX_VALUES {
                                break;
                            }
                            target.insert(token.to_string());
                        }
                    }
                    index = end + usize::from(quote.is_some());
                    settled = index;
                }
                Value::Unfinished => return settled,
                Value::NotAnAttribute => {
                    index += 1;
                    settled = index;
                }
            }
        }
        settled
    }

    pub fn classes(&self) -> impl Iterator<Item = &str> {
        self.classes.iter().map(String::as_str)
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.ids.iter().map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.ids.is_empty()
    }

    /// Everything collected so far, as the two lists the engine query takes.
    pub fn snapshot(&self) -> (Vec<String>, Vec<String>) {
        (
            self.classes.iter().cloned().collect(),
            self.ids.iter().cloned().collect(),
        )
    }
}

/// Offset of the next `class`/`id` attribute name in `data`, if any.
///
/// The name has to *start* an attribute: `data-class=` and `myclass=` are not `class=`. An attribute
/// name starts after whitespace, `<`, `/` or a quote, which is what [`is_attribute_boundary`] admits.
fn attribute_at(data: &[u8]) -> Option<usize> {
    let mut index = 0usize;
    while index < data.len() {
        let rest = &data[index..];
        let byte = rest[0];
        let boundary = index == 0 || is_attribute_boundary(data[index - 1]);
        if boundary
            && byte.eq_ignore_ascii_case(&b'c')
            && rest.len() >= 5
            && rest[..5].eq_ignore_ascii_case(b"class")
        {
            return Some(index);
        }
        if boundary
            && byte.eq_ignore_ascii_case(&b'i')
            && rest.len() >= 2
            && rest[..2].eq_ignore_ascii_case(b"id")
        {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// True when `byte` can immediately precede an attribute name inside a start tag.
fn is_attribute_boundary(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b'<' | b'/' | b'"' | b'\'')
}

/// The value of the attribute whose name starts at `name_start`.
fn read_value(buffer: &[u8], name_start: usize) -> Value {
    let rest = &buffer[name_start..];
    let name_len = if rest.len() >= 5 && rest[..5].eq_ignore_ascii_case(b"class") {
        5
    } else if rest.len() >= 2 && rest[..2].eq_ignore_ascii_case(b"id") {
        2
    } else {
        return Value::NotAnAttribute;
    };
    let mut index = name_len;
    // The name must end at a word boundary: `identifier=` is not `id=`.
    match rest.get(index) {
        None => return Value::Unfinished,
        Some(byte) if byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_' => {
            return Value::NotAnAttribute
        }
        _ => {}
    }
    while matches!(rest.get(index), Some(byte) if byte.is_ascii_whitespace()) {
        index += 1;
    }
    match rest.get(index) {
        None => return Value::Unfinished,
        Some(b'=') => index += 1,
        Some(_) => return Value::NotAnAttribute,
    }
    while matches!(rest.get(index), Some(byte) if byte.is_ascii_whitespace()) {
        index += 1;
    }
    let quote = match rest.get(index) {
        None => return Value::Unfinished,
        Some(byte @ (b'"' | b'\'')) => {
            index += 1;
            Some(*byte)
        }
        Some(_) => None,
    };
    // The value offsets are absolute, because the caller uses them to slice the buffer.
    let start = name_start + index;
    match quote {
        Some(quote) => match buffer[start..].iter().position(|byte| *byte == quote) {
            Some(end) => Value::Complete {
                start,
                end: start + end.min(MAX_ATTRIBUTE_VALUE),
                quote: Some(quote),
            },
            // An unterminated value is either still arriving or pathologically long. Over the cap it
            // is dropped rather than held, which is the same trade a browser makes with a bad document.
            None if buffer.len() - start > MAX_ATTRIBUTE_VALUE => Value::NotAnAttribute,
            None => Value::Unfinished,
        },
        None => {
            let end = buffer[start..]
                .iter()
                .position(|byte| byte.is_ascii_whitespace() || *byte == b'>')
                .map(|offset| start + offset);
            match end {
                Some(end) => Value::Complete {
                    start,
                    end: end.min(start + MAX_ATTRIBUTE_VALUE),
                    quote: None,
                },
                None if buffer.len() - start > MAX_ATTRIBUTE_VALUE => Value::Complete {
                    start,
                    end: start + MAX_ATTRIBUTE_VALUE,
                    quote: None,
                },
                None => Value::Unfinished,
            }
        }
    }
}

enum Value {
    /// A complete value: `[start, end)` in the buffer, plus its quote character if it had one.
    Complete {
        start: usize,
        end: usize,
        quote: Option<u8>,
    },
    /// The value may continue past the end of the buffer.
    Unfinished,
    /// Not an attribute after all.
    NotAnAttribute,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insertion_at_eof(document: &[u8]) -> usize {
        match find_insertion(document, true) {
            Found::At(offset) => offset,
            other => panic!("expected an insertion point for {document:?}, got {other:?}"),
        }
    }

    #[test]
    fn the_insertion_point_follows_the_first_head_tag() {
        let document = b"<!doctype html><html><head><title>x</title></head><body>hi</body></html>";
        let offset = insertion_at_eof(document);
        assert_eq!(&document[..offset], b"<!doctype html><html><head>");
    }

    #[test]
    fn a_head_with_attributes_is_inserted_after_its_closing_bracket() {
        let document = b"<html><HEAD lang=\"zh-CN\" data-x=\"a>b\"><meta charset=utf-8>";
        let offset = insertion_at_eof(document);
        assert_eq!(&document[..offset], b"<html><HEAD lang=\"zh-CN\" data-x=\"a>b\">");
    }

    #[test]
    fn without_a_head_the_html_tag_is_used() {
        let document = b"<!doctype html>\n<html lang=en><body>x</body></html>";
        let offset = insertion_at_eof(document);
        assert_eq!(&document[..offset], b"<!doctype html>\n<html lang=en>");
    }

    #[test]
    fn without_head_or_html_the_start_of_the_document_is_used() {
        let document = b"<div>just a fragment</div>";
        assert_eq!(insertion_at_eof(document), 0);

        // A BOM and a doctype are skipped, and the newline after the doctype is kept with it.
        let document = b"\xEF\xBB\xBF<!DOCTYPE html>\n<p>body only</p>";
        let offset = insertion_at_eof(document);
        assert_eq!(&document[..offset], b"\xEF\xBB\xBF<!DOCTYPE html>\n");

        // With only a BOM.
        let document = b"\xEF\xBB\xBF<p>x</p>";
        assert_eq!(insertion_at_eof(document), 3);
    }

    #[test]
    fn a_body_without_a_head_still_gets_the_markup_after_the_doctype() {
        // The task card fixes three places only (`<head>`, `<html>`, the start of the document); a
        // `<body>` with neither in front of it falls into the third.
        let document = b"<!doctype html>\n<p>lead</p><body class=x><p>text</p>";
        let offset = insertion_at_eof(document);
        assert_eq!(&document[..offset], b"<!doctype html>\n");
    }

    #[test]
    fn a_closing_head_tag_is_not_an_opening_tag() {
        let document = b"</head><html><body>x";
        let offset = insertion_at_eof(document);
        assert_eq!(&document[..offset], b"</head><html>");
    }

    #[test]
    fn header_is_not_head() {
        let document = b"<header>nav</header><html><body>x";
        let offset = insertion_at_eof(document);
        assert_eq!(&document[..offset], b"<header>nav</header><html>");
    }

    #[test]
    fn a_head_split_across_two_feeds_is_found_once_both_halves_are_there() {
        // The caller concatenates its buffer, so the second decision sees the whole prefix. What
        // matters here is that the first decision declines instead of guessing.
        let first = b"<!doctype html><ht";
        let second = b"ml><head lang=\"en\"><title>t</title>";
        assert_eq!(
            find_insertion(first, false),
            Found::NeedMore,
            "`<ht` could still become `<html>`"
        );
        let joined = [first.as_slice(), second.as_slice()].concat();
        assert_eq!(
            find_insertion(&joined, false),
            Found::At(b"<!doctype html><html><head lang=\"en\">".len())
        );
    }

    #[test]
    fn a_partial_head_tag_waits_for_more_bytes() {
        assert_eq!(find_insertion(b"<html><hea", false), Found::NeedMore);
        assert_eq!(find_insertion(b"<html><head", false), Found::NeedMore);
        assert_eq!(find_insertion(b"<html><head lang=", false), Found::NeedMore);
        assert_eq!(find_insertion(b"<html><head>", false), Found::At(12));
    }

    #[test]
    fn an_open_doctype_does_not_stop_the_head_from_being_found() {
        let document = b"<!doctype html><head><title>t";
        assert_eq!(find_insertion(document, false), Found::At(21));
    }

    #[test]
    fn a_window_that_never_closes_its_head_gives_up() {
        let mut document = b"<html><head ".to_vec();
        document.extend(std::iter::repeat_n(b'a', SCAN_WINDOW));
        assert_eq!(find_insertion(&document, false), Found::GiveUp);
    }

    #[test]
    fn a_window_that_fills_without_a_place_gives_up() {
        let mut document = b"<div>".to_vec();
        document.extend(std::iter::repeat_n(b'a', SCAN_WINDOW));
        // Task card §3: past the window there is no injection, only a verbatim relay.
        assert_eq!(find_insertion(&document, false), Found::GiveUp);
        // The same document is decided by the start-of-document rule once it has ended.
        assert_eq!(find_insertion(&document, true), Found::At(0));
    }

    #[test]
    fn a_streaming_document_with_no_place_yet_keeps_waiting() {
        // Nothing has arrived that could decide it, and the window is nowhere near full.
        assert_eq!(find_insertion(b"<", false), Found::NeedMore);
        assert_eq!(find_insertion(b"   ", false), Found::NeedMore);
    }

    #[test]
    fn a_class_and_id_are_collected_from_quoted_attributes() {
        let mut scanner = AttributeScanner::new();
        scanner.feed(br#"<div class="ad banner" id='sponsor'><span class=x id=y>t</span>"#);
        let (classes, ids) = scanner.snapshot();
        assert!(classes.contains(&"ad".to_string()), "{classes:?}");
        assert!(classes.contains(&"banner".to_string()), "{classes:?}");
        assert!(classes.contains(&"x".to_string()), "{classes:?}");
        assert!(ids.contains(&"sponsor".to_string()), "{ids:?}");
        assert!(ids.contains(&"y".to_string()), "{ids:?}");
    }

    #[test]
    fn attributes_split_across_feeds_are_still_collected() {
        let document = br#"<div class="ad-slot" id="banner-ad">"#;
        for split in 1..document.len() {
            let mut scanner = AttributeScanner::new();
            scanner.feed(&document[..split]);
            scanner.feed(&document[split..]);
            let (classes, ids) = scanner.snapshot();
            assert!(
                classes.contains(&"ad-slot".to_string()),
                "split at {split}: {classes:?}"
            );
            assert!(
                ids.contains(&"banner-ad".to_string()),
                "split at {split}: {ids:?}"
            );
        }
    }

    #[test]
    fn attributes_split_byte_by_byte_are_still_collected() {
        let document = br#"<div class="ad-slot" id="banner-ad">"#;
        let mut scanner = AttributeScanner::new();
        for byte in document {
            scanner.feed(&[*byte]);
        }
        let (classes, ids) = scanner.snapshot();
        assert_eq!(classes, vec!["ad-slot".to_string()]);
        assert_eq!(ids, vec!["banner-ad".to_string()]);
    }

    #[test]
    fn similar_names_are_not_mistaken_for_class_or_id() {
        let mut scanner = AttributeScanner::new();
        scanner.feed(br#"<div classname="nope" identifier="nope2" data-class="nope3" classes="nope4">"#);
        assert!(scanner.is_empty(), "{:?}", scanner.snapshot());
    }

    #[test]
    fn an_unquoted_value_ends_at_whitespace_or_the_tag() {
        let mut scanner = AttributeScanner::new();
        scanner.feed(b"<div class=ads id=top>");
        let (classes, ids) = scanner.snapshot();
        assert_eq!(classes, vec!["ads".to_string()]);
        assert_eq!(ids, vec!["top".to_string()]);
    }

    #[test]
    fn case_and_spacing_around_the_equals_sign_are_tolerated() {
        let mut scanner = AttributeScanner::new();
        scanner.feed(b"<div CLASS = \"Ad\" Id\n=\n'Sponsor'>");
        let (classes, ids) = scanner.snapshot();
        assert_eq!(classes, vec!["Ad".to_string()]);
        assert_eq!(ids, vec!["Sponsor".to_string()]);
    }

    #[test]
    fn an_unterminated_value_does_not_grow_without_bound() {
        let mut scanner = AttributeScanner::new();
        scanner.feed(b"<div class=\"");
        scanner.feed(&vec![b'x'; MAX_ATTRIBUTE_VALUE * 4]);
        scanner.feed(b"\">");
        // The over-long value is dropped rather than kept, and the scanner keeps working.
        scanner.feed(b"<i class=ad>");
        assert_eq!(scanner.snapshot().0, vec!["ad".to_string()]);
    }

    #[test]
    fn a_very_long_document_does_not_accumulate_memory() {
        let mut scanner = AttributeScanner::new();
        for _ in 0..64 {
            scanner.feed(&vec![b'a'; 64 * 1024]);
        }
        assert!(scanner.carry.len() <= AttributeScanner::CARRY + 1);
    }

    #[test]
    fn the_body_close_tag_is_recognised_case_insensitively() {
        assert!(is_body_close_at(b"</body>"));
        assert!(is_body_close_at(b"</BODY >"));
        assert!(!is_body_close_at(b"</bod"));
        assert!(!is_body_close_at(b"<body>"));
    }

    #[test]
    fn the_incremental_locator_finds_the_same_point_as_a_full_search() {
        // Every feed size and every document shape, so a cursor that resumes one byte too far cannot
        // hide a missed `<head>`.
        let documents: [&[u8]; 5] = [
            b"<!doctype html><html><head><title>t</title></head><body>x</body></html>",
            b"<html><head lang=\"en\"><body>x",
            b"<!doctype html>\n<html lang=en><body>x",
            b"  <div>no tags at all</div>",
            b"<!doctype html>\n<p>body only</p>",
        ];
        for document in documents {
            for feed in [1usize, 2, 3, 5, 7, 11, 64] {
                let mut locator = Locator::new();
                let mut prefix = Vec::new();
                let mut last = Found::NeedMore;
                for chunk in document.chunks(feed) {
                    prefix.extend_from_slice(chunk);
                    last = locator.find(&prefix, false);
                    if last != Found::NeedMore {
                        break;
                    }
                }
                // Whatever it decided mid-stream must agree with a full search over the same prefix.
                assert_eq!(
                    last,
                    find_insertion(&prefix, false),
                    "feed {feed} of {:?}",
                    String::from_utf8_lossy(document)
                );
            }
            // And at end of body both agree on the final answer.
            let mut locator = Locator::new();
            let mut prefix = Vec::new();
            for chunk in document.chunks(3) {
                prefix.extend_from_slice(chunk);
                let _ = locator.find(&prefix, false);
            }
            assert_eq!(
                locator.find(&prefix, true),
                find_insertion(document, true),
                "{:?}",
                String::from_utf8_lossy(document)
            );
        }
    }

    #[test]
    fn ascii_search_is_case_insensitive() {
        assert_eq!(find_ignore_ascii_case(b"xxHeAdyy", b"head"), Some(2));
        assert_eq!(find_ignore_ascii_case(b"xx", b"head"), None);
    }
}

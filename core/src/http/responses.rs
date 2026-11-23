//! Just enough response framing to know when the origin's response has ended.
//!
//! The relay decides each request and may answer it itself. A synthetic response must be written to
//! the client **in request order**, so before writing one the relay has to know whether an earlier
//! request's response is still on the wire; writing out of order would splice our bytes into the
//! middle of the origin's body (review item 6).
//!
//! This is not a response parser and deliberately not a general one. It answers exactly one
//! question — "has this response finished?" — using the framing rules of RFC 9112 §6.3:
//!
//! | Situation | Body |
//! |---|---|
//! | `HEAD` request, `1xx`, `204`, `304` | none |
//! | `Transfer-Encoding: chunked` | chunked, ended by the terminal chunk |
//! | `Content-Length` | exactly that many bytes |
//! | none of the above | until the connection closes (`RFC 9112` §6.3 item 7) |
//!
//! The bytes are still forwarded untouched — the tracker only observes. Anything it cannot follow
//! (a malformed status line, a chunked body it loses sync with) marks the response as
//! [`Progress::Unknown`], and the relay then stops writing synthetic responses on that connection:
//! a response that might still be in flight must never be interrupted by ours.

/// A chunked scanner is shared with the request side: the framing is identical (RFC 9112 §7.1).
use crate::http::body::{ChunkProgress, ChunkedScanner};

/// What one feed of server bytes established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// The response was still arriving.
    InFlight,
    /// A response ended during these bytes; another may already have started after it.
    Completed,
    /// The framing could not be followed, so the end is unknowable.
    Unknown,
}

/// Whether the origin owes this request a body at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyRule {
    /// `HEAD` and `CONNECT`: a response to these never has a body (`RFC 9112` §6.3 item 1).
    Never,
    /// Everything else: the headers decide.
    Framed,
}

/// Tracks one response at a time on a keep-alive connection.
#[derive(Debug)]
pub struct ResponseTracker {
    state: State,
    /// Set once the stream stops being trustworthy; the relay then stops synthesizing responses.
    broken: bool,
    /// Offset one past the last byte of the response that most recently completed, if any.
    ///
    /// The cosmetic injector needs it: it rewrites one *response*, and a single read can carry the end
    /// of one response and the beginning of the next. Without the boundary, the next response's bytes
    /// would be fed into the document being injected.
    completed_at: Option<usize>,
}

#[derive(Debug)]
enum State {
    /// Waiting for (or reading) a response head.
    Head { buf: Vec<u8> },
    /// `Content-Length` framing: this many body bytes remain.
    Length(usize),
    /// `Transfer-Encoding: chunked`.
    Chunked(ChunkedScanner),
    /// No length and not chunked: the body runs to the connection's end.
    UntilClose,
}

/// Longest response head the tracker will hold while looking for `\r\n\r\n`.
///
/// Only a guard against a stream that never terminates; an oversized head is reported as
/// [`Progress::Unknown`] rather than buffered forever.
const MAX_RESPONSE_HEAD: usize = 32 * 1024;

impl ResponseTracker {
    pub fn new() -> Self {
        Self {
            state: State::Head { buf: Vec::new() },
            broken: false,
            completed_at: None,
        }
    }

    /// Offset one past the last byte of the response that just completed in the most recent
    /// [`ResponseTracker::observe`], or `None` when that call did not complete a response.
    ///
    /// A single read can carry the end of one response and the start of the next; this is the boundary
    /// between them.
    pub fn completed_at(&self) -> Option<usize> {
        self.completed_at
    }

    /// True when this stream can no longer be trusted to report response boundaries.
    ///
    /// The caller uses it to stop treating a `Completed` as meaningful; the relay does not need to,
    /// because it only synthesizes a response when it knows nothing is in flight.
    pub fn is_broken(&self) -> bool {
        self.broken
    }

    /// Feed server→client bytes. `rule` says whether the response to the request this belongs to
    /// may have a body at all.
    pub fn observe(&mut self, data: &[u8], rule: BodyRule) -> Progress {
        self.completed_at = None;
        if self.broken {
            return Progress::Unknown;
        }
        let mut index = 0usize;
        let mut completed = false;
        loop {
            match &mut self.state {
                State::Head { buf } => {
                    if index >= data.len() {
                        if completed && self.completed_at.is_none() {
                            self.completed_at = Some(index);
                        }
                        return finish(completed, false);
                    }
                    let byte = data[index];
                    index += 1;
                    buf.push(byte);
                    // A head ends at `\r\n\r\n`; tolerate bare `\n\n` because a sloppy origin is not
                    // a reason to lose the connection's framing.
                    let ended = buf.ends_with(b"\r\n\r\n") || buf.ends_with(b"\n\n");
                    if !ended {
                        if buf.len() > MAX_RESPONSE_HEAD {
                            self.broken = true;
                            return Progress::Unknown;
                        }
                        continue;
                    }
                    let head = std::mem::take(buf);
                    match head_body_state(&head, rule) {
                        Ok(Some(state)) => self.state = state,
                        // No body: this response is done, and the next one may follow immediately.
                        Ok(None) => {
                            completed = true;
                            if self.completed_at.is_none() {
                                self.completed_at = Some(index);
                            }
                            self.state = State::Head { buf: Vec::new() };
                        }
                        Err(()) => {
                            self.broken = true;
                            return Progress::Unknown;
                        }
                    }
                }
                State::Length(remaining) => {
                    if index >= data.len() {
                        return finish(completed, false);
                    }
                    let take = (*remaining).min(data.len() - index);
                    index += take;
                    *remaining -= take;
                    if *remaining == 0 {
                        completed = true;
                        if self.completed_at.is_none() {
                            self.completed_at = Some(index);
                        }
                        self.state = State::Head { buf: Vec::new() };
                    }
                }
                State::Chunked(scanner) => {
                    if index >= data.len() {
                        return finish(completed, false);
                    }
                    match scanner.feed(&data[index..]) {
                        ChunkProgress::More(consumed) | ChunkProgress::Done(consumed) => {
                            index += consumed;
                            if scanner.is_done() {
                                completed = true;
                                if self.completed_at.is_none() {
                                    self.completed_at = Some(index);
                                }
                                self.state = State::Head { buf: Vec::new() };
                            }
                        }
                        ChunkProgress::Malformed(_) => {
                            self.broken = true;
                            return Progress::Unknown;
                        }
                    }
                }
                State::UntilClose => {
                    // Consumes everything and never completes; the connection's close is the end.
                    if completed && self.completed_at.is_none() {
                        self.completed_at = Some(index);
                    }
                    return Progress::InFlight;
                }
            }
        }
    }
}

impl Default for ResponseTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn finish(completed: bool, broken: bool) -> Progress {
    match (completed, broken) {
        (_, true) => Progress::Unknown,
        (true, false) => Progress::Completed,
        (false, false) => Progress::InFlight,
    }
}

/// Decide the body framing of one response head. `Ok(None)` means "no body, complete".
fn head_body_state(head: &[u8], rule: BodyRule) -> Result<Option<State>, ()> {
    let mut lines = head.split(|byte| *byte == b'\n');
    let status_line = lines.next().ok_or(())?;
    let status = parse_status(status_line).ok_or(())?;

    // Interim responses are not the response to the request; keep waiting for the real one.
    if (100..200).contains(&status) {
        return Ok(Some(State::Head { buf: Vec::new() }));
    }
    // A final response to `HEAD`/`CONNECT` has no body whatever the headers say. An interim HEAD
    // response above must not retire the request before its final status and headers arrive.
    if rule == BodyRule::Never {
        return Ok(None);
    }
    // §6.3 item 2: 204 and 304 never carry a body.
    if status == 204 || status == 304 {
        return Ok(None);
    }

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut saw_transfer_encoding = false;
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = &line[..colon];
        let value = trim(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"content-length") {
            let parsed = parse_decimal(value).ok_or(())?;
            match content_length {
                None => content_length = Some(parsed),
                // Two differing lengths on a response is as ambiguous as on a request.
                Some(existing) if existing == parsed => {}
                Some(_) => return Err(()),
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            saw_transfer_encoding = true;
            if contains_ignore_ascii_case(value, b"chunked") {
                chunked = true;
            }
        }
    }

    if chunked {
        return Ok(Some(State::Chunked(ChunkedScanner::new())));
    }
    if saw_transfer_encoding {
        // A coding we cannot frame: the end is unknowable.
        return Err(());
    }
    match content_length {
        Some(0) => Ok(None),
        Some(len) => Ok(Some(State::Length(len))),
        None => Ok(Some(State::UntilClose)),
    }
}

/// Parse the status code out of `HTTP/1.1 200 OK`.
fn parse_status(line: &[u8]) -> Option<u16> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line.splitn(3, |byte| *byte == b' ');
    let version = parts.next()?;
    if !version.starts_with(b"HTTP/") {
        return None;
    }
    let code = trim(parts.next()?);
    if code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(code).ok()?.parse().ok()
}

fn trim(mut value: &[u8]) -> &[u8] {
    while let Some((first, rest)) = value.split_first() {
        if first.is_ascii_whitespace() {
            value = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = value.split_last() {
        if last.is_ascii_whitespace() {
            value = rest;
        } else {
            break;
        }
    }
    value
}

fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn parse_decimal(value: &[u8]) -> Option<usize> {
    let value = trim(value);
    if value.is_empty() || value.len() > 19 || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_content_length_response_completes_after_exactly_that_many_bytes() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        let mut tracker = ResponseTracker::new();
        assert_eq!(tracker.observe(head, BodyRule::Framed), Progress::InFlight);
        assert_eq!(tracker.observe(b"hel", BodyRule::Framed), Progress::InFlight);
        assert_eq!(tracker.observe(b"lo", BodyRule::Framed), Progress::Completed);
        // The next response is awaited independently: the tracker never claims a completion it
        // has not seen.
        assert_eq!(tracker.observe(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", BodyRule::Framed), Progress::Completed);
    }

    #[test]
    fn a_body_split_across_reads_is_still_counted() {
        let mut tracker = ResponseTracker::new();
        tracker.observe(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n", BodyRule::Framed);
        assert_eq!(tracker.observe(b"01234", BodyRule::Framed), Progress::InFlight);
        assert_eq!(tracker.observe(b"56789", BodyRule::Framed), Progress::Completed);
    }

    #[test]
    fn head_and_body_in_one_read_completes_immediately() {
        let mut tracker = ResponseTracker::new();
        assert_eq!(
            tracker.observe(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi", BodyRule::Framed),
            Progress::Completed
        );
    }

    #[test]
    fn a_chunked_response_completes_at_the_terminal_chunk() {
        let mut tracker = ResponseTracker::new();
        tracker.observe(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", BodyRule::Framed);
        assert_eq!(tracker.observe(b"5\r\nhello\r\n", BodyRule::Framed), Progress::InFlight);
        assert_eq!(tracker.observe(b"0\r\n\r\n", BodyRule::Framed), Progress::Completed);
    }

    #[test]
    fn bodiless_statuses_complete_at_the_head() {
        for response in [
            &b"HTTP/1.1 204 No Content\r\n\r\n"[..],
            &b"HTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\n"[..],
        ] {
            let mut tracker = ResponseTracker::new();
            assert_eq!(
                tracker.observe(response, BodyRule::Framed),
                Progress::Completed,
                "{}",
                String::from_utf8_lossy(response)
            );
        }
    }

    #[test]
    fn a_head_response_has_no_body_whatever_the_headers_say() {
        // A `HEAD` gets the GET headers back, including `Content-Length`, but no body follows.
        let mut tracker = ResponseTracker::new();
        assert_eq!(
            tracker.observe(
                b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n",
                BodyRule::Never
            ),
            Progress::Completed
        );
    }

    #[test]
    fn an_interim_response_does_not_end_the_response() {
        // `100 Continue` is followed by the real response on the same connection: reporting a
        // completion for the interim one would let a synthetic response be spliced into the real
        // one's place.
        let mut tracker = ResponseTracker::new();
        assert_eq!(
            tracker.observe(b"HTTP/1.1 100 Continue\r\n\r\n", BodyRule::Framed),
            Progress::InFlight
        );
        assert_eq!(
            tracker.observe(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", BodyRule::Framed),
            Progress::Completed
        );
    }

    #[test]
    fn two_responses_in_one_read_complete() {
        let mut tracker = ResponseTracker::new();
        let both = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na\
                     HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb";
        // Even though two responses arrived, one completion is reported per read; the relay only
        // needs "is anything still in flight", and the second head was consumed correctly.
        assert_eq!(tracker.observe(both, BodyRule::Framed), Progress::Completed);
    }

    #[test]
    fn an_unframed_response_runs_until_the_connection_closes() {
        let mut tracker = ResponseTracker::new();
        assert_eq!(
            tracker.observe(b"HTTP/1.1 200 OK\r\n\r\nbody bytes", BodyRule::Framed),
            Progress::InFlight
        );
        // Only the connection's close ends it, and the relay handles that itself.
        assert_eq!(tracker.observe(b"more bytes", BodyRule::Framed), Progress::InFlight);
    }

    #[test]
    fn garbage_breaks_the_tracker_instead_of_guessing() {
        let mut tracker = ResponseTracker::new();
        assert_eq!(
            tracker.observe(b"not http at all\r\n\r\n", BodyRule::Framed),
            Progress::Unknown
        );
        assert!(tracker.is_broken());
        // Once broken it stays broken and never reports completion.
        assert_eq!(
            tracker.observe(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", BodyRule::Framed),
            Progress::Unknown
        );
    }

    #[test]
    fn an_absurdly_long_head_breaks_the_tracker() {
        let mut tracker = ResponseTracker::new();
        let mut junk = b"HTTP/1.1 200 OK\r\n".to_vec();
        junk.extend(std::iter::repeat_n(b'X', MAX_RESPONSE_HEAD + 8));
        assert_eq!(tracker.observe(&junk, BodyRule::Framed), Progress::Unknown);
        assert!(tracker.is_broken());
    }

    #[test]
    fn conflicting_framing_breaks_the_tracker() {
        let mut tracker = ResponseTracker::new();
        assert_eq!(
            tracker.observe(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
                BodyRule::Framed
            ),
            Progress::Unknown
        );
        let mut tracker = ResponseTracker::new();
        assert_eq!(
            tracker.observe(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", BodyRule::Framed),
            Progress::Unknown
        );
    }

    #[test]
    fn a_bare_lf_head_is_tolerated() {
        let mut tracker = ResponseTracker::new();
        assert_eq!(
            tracker.observe(b"HTTP/1.1 200 OK\nContent-Length: 0\n\n", BodyRule::Framed),
            Progress::Completed
        );
    }

    #[test]
    fn a_reset_mid_head_breaks_the_tracker() {
        // A truncated head can never be finished, so the boundary is unknowable.
        let mut tracker = ResponseTracker::new();
        assert_eq!(
            tracker.observe(b"HTTP/1.1 200 OK\r\nContent-Le", BodyRule::Framed),
            Progress::InFlight
        );
        let mut junk = b"HTTP/1.1 200 OK\r\n".to_vec();
        junk.extend(std::iter::repeat_n(b'X', MAX_RESPONSE_HEAD + 8));
        assert_eq!(tracker.observe(&junk, BodyRule::Framed), Progress::Unknown);
        assert!(tracker.is_broken());
    }

    #[test]
    fn status_codes_are_parsed_strictly() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status(b"HTTP/1.0 404 Not Found"), Some(404));
        assert_eq!(parse_status(b"HTTP/1.1 20 OK"), None);
        assert_eq!(parse_status(b"HTTP/1.1 abc OK"), None);
        assert_eq!(parse_status(b"ICY 200 OK"), None);
        assert_eq!(parse_status(b"HTTP/1.1"), None);
    }

    #[test]
    fn content_length_values_are_digits_only() {
        assert_eq!(parse_decimal(b" 42 "), Some(42));
        assert_eq!(parse_decimal(b"0"), Some(0));
        assert_eq!(parse_decimal(b"+5"), None, "a sign is not a decimal number");
        assert_eq!(parse_decimal(b"-5"), None);
        assert_eq!(parse_decimal(b"5x"), None);
        assert_eq!(parse_decimal(b""), None);
        assert_eq!(parse_decimal(b"0000000000000000000005"), None, "far too many digits");
    }
}

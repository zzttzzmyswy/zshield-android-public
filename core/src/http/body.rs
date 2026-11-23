//! `Transfer-Encoding: chunked` framing (`RFC 9112` §7.1), shared by both directions.
//!
//! The tunnel needs the same scanner twice: to know how much of a **request** body to forward, and
//! to know when an origin's **response** has ended so a synthetic response is not spliced into it.
//! The framing is identical in both directions, so it lives here rather than being written twice.
//!
//! The scanner only answers "how many of these bytes are body, and did the body end" — the bytes
//! themselves are forwarded untouched, so no chunk is buffered or reassembled.

/// Longest chunk-size line accepted, extensions included (`RFC 9112` §7.1.1).
///
/// Only a bound against an endless line, not a semantic limit: a hex size is at most 16 characters,
/// but extensions (`;name=value`) are arbitrary, so the limit is the same order as a request head
/// (review item 3).
pub const MAX_CHUNK_SIZE_LINE: usize = 4 * 1024;

/// Result of feeding bytes to a [`ChunkedScanner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkProgress {
    /// Not at the end of the body; `usize` bytes belong to it.
    More(usize),
    /// The body ended after `usize` bytes.
    Done(usize),
    /// The framing is broken after `usize` bytes; the caller must stop filtering.
    Malformed(usize),
}

/// Incremental scanner for `Transfer-Encoding: chunked` (RFC 9112 §7.1).
///
/// It only has to answer "how many of these bytes are body, and did the body end" — the bytes
/// themselves are forwarded untouched, so no chunk is buffered or reassembled.
pub struct ChunkedScanner {
    state: ChunkState,
}

impl std::fmt::Debug for ChunkedScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkedScanner").finish_non_exhaustive()
    }
}

enum ChunkState {
    /// Reading a chunk-size line.
    Size { line: Vec<u8> },
    /// Inside chunk data: this many bytes remain.
    Data(usize),
    /// After chunk data, expecting the CRLF that follows: 0 = expect CR, 1 = expect LF.
    DataCrlf(u8),
    /// After the last chunk, consuming trailer lines until an empty one.
    Trailer { line_len: usize },
    Done,
}

impl Default for ChunkedScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkedScanner {
    pub fn new() -> Self {
        Self {
            state: ChunkState::Size { line: Vec::new() },
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, ChunkState::Done)
    }

    /// Consume `buf`, returning how many bytes belong to the body and whether it ended.
    pub fn feed(&mut self, buf: &[u8]) -> ChunkProgress {
        let mut index = 0usize;
        loop {
            match &mut self.state {
                ChunkState::Data(remaining) => {
                    if index >= buf.len() {
                        return ChunkProgress::More(index);
                    }
                    let take = (*remaining).min(buf.len() - index);
                    index += take;
                    *remaining -= take;
                    if *remaining == 0 {
                        self.state = ChunkState::DataCrlf(0);
                    }
                }
                ChunkState::DataCrlf(expected) => {
                    if index >= buf.len() {
                        return ChunkProgress::More(index);
                    }
                    let want = if *expected == 0 { b'\r' } else { b'\n' };
                    if buf[index] != want {
                        return ChunkProgress::Malformed(index);
                    }
                    index += 1;
                    if *expected == 0 {
                        *expected = 1;
                    } else {
                        self.state = ChunkState::Size { line: Vec::new() };
                    }
                }
                ChunkState::Size { line } => {
                    if index >= buf.len() {
                        return ChunkProgress::More(index);
                    }
                    let byte = buf[index];
                    index += 1;
                    if byte == b'\n' {
                        // A size line may carry `;ext=value` extensions after the hex.
                        let text = String::from_utf8_lossy(line);
                        let hex = text.trim().split(';').next().unwrap_or("").trim().to_string();
                        let Ok(size) = usize::from_str_radix(&hex, 16) else {
                            return ChunkProgress::Malformed(index);
                        };
                        self.state = if size == 0 {
                            ChunkState::Trailer { line_len: 0 }
                        } else {
                            ChunkState::Data(size)
                        };
                    } else if byte == b'\r' {
                        // Skipped; the `\n` ends the line.
                    } else if line.len() >= MAX_CHUNK_SIZE_LINE {
                        // RFC 9112 §7.1.1 allows arbitrary chunk extensions (`;name=value`), so the
                        // bound has to be the same order as a request head rather than a hex value
                        // (review item 3). This only guards against an endless line.
                        return ChunkProgress::Malformed(index);
                    } else {
                        line.push(byte);
                    }
                }
                ChunkState::Trailer { line_len } => {
                    if index >= buf.len() {
                        return ChunkProgress::More(index);
                    }
                    let byte = buf[index];
                    index += 1;
                    if byte == b'\n' {
                        if *line_len == 0 {
                            self.state = ChunkState::Done;
                            return ChunkProgress::Done(index);
                        }
                        *line_len = 0;
                    } else if byte != b'\r' {
                        *line_len += 1;
                        if *line_len > 8192 {
                            return ChunkProgress::Malformed(index);
                        }
                    }
                }
                ChunkState::Done => return ChunkProgress::Done(index),
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(body: &[u8]) -> (ChunkProgress, bool) {
        let mut scanner = ChunkedScanner::new();
        let progress = scanner.feed(body);
        (progress, scanner.is_done())
    }

    #[test]
    fn chunked_framing_is_scanned_incrementally() {
        let body = b"5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n";
        let (progress, done) = feed_all(body);
        assert_eq!(progress, ChunkProgress::Done(body.len()));
        assert!(done);
    }

    #[test]
    fn chunked_split_across_reads_is_still_tracked() {
        let body = b"5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n";
        for split in 1..body.len() {
            let mut scanner = ChunkedScanner::new();
            match scanner.feed(&body[..split]) {
                ChunkProgress::More(n) => assert_eq!(n, split, "every body byte must be counted"),
                other => panic!("split at {split} finished early: {other:?}"),
            }
            let rest = &body[split..];
            assert_eq!(
                scanner.feed(rest),
                ChunkProgress::Done(rest.len()),
                "split at {split} did not complete"
            );
            assert!(scanner.is_done());
        }
    }

    #[test]
    fn chunk_extensions_and_trailers_are_tolerated() {
        let body = b"4;ext=1\r\nwxyz\r\n0\r\nX-Checksum: 1\r\n\r\n";
        let (progress, done) = feed_all(body);
        assert_eq!(progress, ChunkProgress::Done(body.len()));
        assert!(done);
    }

    #[test]
    fn a_long_chunk_extension_is_legal() {
        // `RFC 9112` §7.1.1 lets a chunk carry extensions of any length; a 32-byte cap on the size
        // line rejected legal requests (review item 3). A 500-byte extension must pass.
        let mut body = b"4;".to_vec();
        body.extend(std::iter::repeat_n(b'x', 500));
        body.extend_from_slice(b"=y\r\nwxyz\r\n0\r\n\r\n");
        let (progress, done) = feed_all(&body);
        assert_eq!(
            progress,
            ChunkProgress::Done(body.len()),
            "a 500-byte chunk extension must not be treated as malformed"
        );
        assert!(done);
    }

    #[test]
    fn an_endless_size_line_is_still_rejected() {
        // The bound still exists, it is just no longer a hex-length bound.
        let mut body = b"4;".to_vec();
        body.extend(std::iter::repeat_n(b'x', MAX_CHUNK_SIZE_LINE + 8));
        body.extend_from_slice(b"\r\n");
        assert!(matches!(feed_all(&body).0, ChunkProgress::Malformed(_)));
    }

    #[test]
    fn broken_chunk_framing_is_reported_not_guessed() {
        assert!(matches!(
            feed_all(b"3\r\nabcX\r\n0\r\n\r\n").0,
            ChunkProgress::Malformed(_)
        ));
        assert!(matches!(
            feed_all(b"zz\r\nabc\r\n").0,
            ChunkProgress::Malformed(_)
        ));
    }

    #[test]
    fn an_empty_chunked_body_ends_immediately() {
        let (progress, done) = feed_all(b"0\r\n\r\n");
        assert_eq!(progress, ChunkProgress::Done(5));
        assert!(done);
    }
}

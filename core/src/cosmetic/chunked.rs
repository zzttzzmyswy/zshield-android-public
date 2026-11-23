//! Stripping the origin's `Transfer-Encoding: chunked` before a body is rewritten.
//!
//! A rewritten body is re-chunked locally ([`crate::cosmetic::head::OutFraming::Chunked`]), so the
//! origin's own chunk framing has to come off first. Without this, the gzip decoder would be fed
//! `1a5\r\n<gzip bytes>\r\n`, which is not a gzip member, and every compressed document would be
//! reported as corrupt.
//!
//! # Why not [`crate::http::body::ChunkedScanner`]
//!
//! That scanner reports how many bytes it has *scanned*, which is what the relay needs to forward a
//! request body **including** its framing. Here the framing has to be removed, so the body bytes
//! themselves have to be identified and copied — a different question, with a different answer for
//! every chunk. The grammar is the same (RFC 9112 § 7.1); this is deliberately a second, small
//! implementation rather than a change to the shared one, because the request path's scanner is
//! load-bearing for M2b and must not gain an allocation per chunk.
//!
//! Trailers are dropped: they describe the origin's body, and the body this core sends is a different
//! one (different length, different coding) with its own framing.

/// Longest chunk-size line accepted, extensions included (RFC 9112 § 7.1.1).
///
/// Only a bound against an endless line: a hex size is at most 16 characters, but extensions are
/// arbitrary. Same order as the request direction's.
const MAX_SIZE_LINE: usize = 4 * 1024;

/// Strips chunk framing from a response body, incrementally.
pub struct Dechunker {
    state: State,
    /// Set once the terminal chunk has been consumed.
    done: bool,
    /// Set when the framing cannot be followed.
    malformed: bool,
}

enum State {
    /// Reading a chunk-size line.
    Size { line: Vec<u8> },
    /// Inside chunk data: this many bytes remain.
    Data { remaining: usize },
    /// After chunk data: expect `\r` then `\n` (`true` = expect CR).
    DataCrlf { expected_cr: bool },
    /// After the last chunk: consume trailer lines until an empty one.
    Trailer { line_len: usize },
    /// Done.
    End,
}

impl Dechunker {
    pub fn new() -> Self {
        Self {
            state: State::Size { line: Vec::new() },
            done: false,
            malformed: false,
        }
    }

    /// True once the terminal chunk has been consumed.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// True when the framing broke.
    pub fn is_malformed(&self) -> bool {
        self.malformed
    }

    /// Feed origin bytes, returning the body bytes they carried.
    ///
    /// The body bytes are returned even for a malformed feed, up to the point the framing broke: those
    /// bytes really are part of the document, and dropping them would truncate it.
    pub fn push(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        if self.done || self.malformed {
            return out;
        }
        let mut index = 0usize;
        while index < data.len() {
            match &mut self.state {
                State::Size { line } => {
                    let byte = data[index];
                    index += 1;
                    if byte == b'\n' {
                        let text = String::from_utf8_lossy(line);
                        let hex = text.trim().split(';').next().unwrap_or("").trim().to_string();
                        let Ok(size) = usize::from_str_radix(&hex, 16) else {
                            self.malformed = true;
                            return out;
                        };
                        line.clear();
                        self.state = if size == 0 {
                            State::Trailer { line_len: 0 }
                        } else {
                            State::Data { remaining: size }
                        };
                    } else if byte != b'\r' {
                        if line.len() >= MAX_SIZE_LINE {
                            self.malformed = true;
                            return out;
                        }
                        line.push(byte);
                    }
                }
                State::Data { remaining } => {
                    let take = (*remaining).min(data.len() - index);
                    out.extend_from_slice(&data[index..index + take]);
                    index += take;
                    *remaining -= take;
                    if *remaining == 0 {
                        self.state = State::DataCrlf { expected_cr: true };
                    }
                }
                State::DataCrlf { expected_cr } => {
                    let want = if *expected_cr { b'\r' } else { b'\n' };
                    if data[index] != want {
                        self.malformed = true;
                        return out;
                    }
                    index += 1;
                    if *expected_cr {
                        *expected_cr = false;
                    } else {
                        self.state = State::Size { line: Vec::new() };
                    }
                }
                State::Trailer { line_len } => {
                    let byte = data[index];
                    index += 1;
                    if byte == b'\n' {
                        if *line_len == 0 {
                            self.state = State::End;
                            self.done = true;
                            return out;
                        }
                        *line_len = 0;
                    } else if byte != b'\r' {
                        *line_len += 1;
                        if *line_len > 8192 {
                            self.malformed = true;
                            return out;
                        }
                    }
                }
                State::End => return out,
            }
        }
        out
    }
}

impl Default for Dechunker {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Dechunker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dechunker")
            .field("done", &self.done)
            .field("malformed", &self.malformed)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_framing_is_stripped_and_the_body_bytes_are_kept() {
        let framed = b"5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n";
        let mut dechunker = Dechunker::new();
        assert_eq!(dechunker.push(framed), b"helloabc".to_vec());
        assert!(dechunker.is_done());
        assert!(!dechunker.is_malformed());
    }

    #[test]
    fn every_split_point_dechunks_to_the_same_body() {
        let framed = b"5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n";
        for split in 1..framed.len() {
            let mut dechunker = Dechunker::new();
            let mut body = dechunker.push(&framed[..split]);
            body.extend_from_slice(&dechunker.push(&framed[split..]));
            assert_eq!(body, b"helloabc".to_vec(), "split at {split}");
            assert!(dechunker.is_done(), "split at {split} did not finish");
        }
    }

    #[test]
    fn one_byte_at_a_time_works() {
        let framed = b"5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n";
        let mut dechunker = Dechunker::new();
        let mut body = Vec::new();
        for byte in framed {
            body.extend_from_slice(&dechunker.push(&[*byte]));
        }
        assert_eq!(body, b"helloabc".to_vec());
        assert!(dechunker.is_done());
    }

    #[test]
    fn chunk_extensions_and_trailers_are_tolerated() {
        let framed = b"4;ext=1\r\nwxyz\r\n0\r\nX-Checksum: 1\r\n\r\n";
        let mut dechunker = Dechunker::new();
        assert_eq!(dechunker.push(framed), b"wxyz".to_vec());
        assert!(dechunker.is_done());
    }

    #[test]
    fn broken_framing_keeps_the_bytes_before_the_break() {
        let framed = b"3\r\nabcX\r\n";
        let mut dechunker = Dechunker::new();
        let body = dechunker.push(framed);
        assert_eq!(body, b"abc".to_vec(), "the body bytes before the break are real");
        assert!(dechunker.is_malformed());
        // Once broken it stops claiming body bytes.
        assert!(dechunker.push(b"more").is_empty());
    }

    #[test]
    fn an_empty_body_finishes_immediately() {
        let mut dechunker = Dechunker::new();
        assert!(dechunker.push(b"0\r\n\r\n").is_empty());
        assert!(dechunker.is_done());
    }

    #[test]
    fn a_body_that_is_not_chunked_at_all_is_reported_as_malformed() {
        let mut dechunker = Dechunker::new();
        // A size line with no hex digits in it: `\x1f\x8b…` never parses as a chunk size. The dechunker
        // only reports the break once the line ends, because until then the bytes could still be a
        // slow-arriving size.
        assert!(!dechunker.is_malformed());
        dechunker.push(b"not-a-size\r\n");
        assert!(dechunker.is_malformed());
    }

    #[test]
    fn an_endless_size_line_is_rejected() {
        let mut dechunker = Dechunker::new();
        let mut framed = b"4;".to_vec();
        framed.extend(std::iter::repeat_n(b'x', MAX_SIZE_LINE + 8));
        framed.extend_from_slice(b"\r\n");
        dechunker.push(&framed);
        assert!(dechunker.is_malformed());
    }

    #[test]
    fn a_large_body_split_across_feeds_is_reassembled() {
        let mut payload = Vec::new();
        for index in 0..500 {
            payload.extend_from_slice(format!("line {index}\n").as_bytes());
        }
        let mut framed = Vec::new();
        for chunk in payload.chunks(97) {
            framed.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            framed.extend_from_slice(chunk);
            framed.extend_from_slice(b"\r\n");
        }
        framed.extend_from_slice(b"0\r\n\r\n");

        let mut dechunker = Dechunker::new();
        let mut body = Vec::new();
        for chunk in framed.chunks(23) {
            body.extend_from_slice(&dechunker.push(chunk));
        }
        assert_eq!(body, payload);
        assert!(dechunker.is_done());
    }
}

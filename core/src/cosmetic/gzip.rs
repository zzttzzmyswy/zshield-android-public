//! A streaming gzip decoder: header, raw deflate, trailer — in that order.
//!
//! # Why not `flate2`'s own gzip support
//!
//! `flate2` decodes gzip through `Decompress::new_gzip`, which the pure-Rust `rust_backend` this crate
//! links does not provide (and which would pull the C library into the NDK build), or through a
//! `Read`-based `GzDecoder` that cannot be driven from the push-based loop the relay needs without a
//! thread or an unbounded buffer.
//!
//! A gzip member is a fixed 10-byte header, an optional set of fields, a **raw deflate stream**, and an
//! 8-byte trailer (CRC-32 and length). So this module parses the header itself and hands the payload to
//! `Decompress::new(false)` — raw deflate — which the backend does support. The trailer is skipped rather
//! than verified: a CRC mismatch would only turn a page that would have rendered into an error, and the
//! origin's transport already carried the bytes.
//!
//! # What is not supported
//!
//! Concatenated members. They are legal, but no origin sends them for HTML; the first member is decoded
//! and the bytes after it are reported as [`GzipProgress::Finished`] for the caller to pass through.

/// How many decompressed bytes one round produces.
///
/// Small enough that a decompression bomb costs at most this much memory per read rather than the whole
/// expansion, and large enough that the per-chunk bookkeeping is negligible next to a 32 KiB write.
pub const OUTPUT_CHUNK: usize = 64 * 1024;

/// Largest gzip header this decoder will buffer.
///
/// The fixed part is 10 bytes; the optional name and comment fields are NUL-terminated and unbounded in
/// the format, so they need a bound. 4 KiB is far past what any origin sends and still small enough that
/// a malformed stream cannot make the tunnel hold anything significant.
pub const MAX_HEADER: usize = 4 * 1024;

/// What one [`GzipDecoder::push`] established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GzipProgress {
    /// More input is needed: the header is still arriving, or the deflate stream has no more whole
    /// blocks in what is buffered.
    NeedMore,
    /// The member ended at this offset into the input that was pushed; anything after it belongs to
    /// whatever follows the member and is the caller's to pass through.
    Finished(usize),
}

/// A streaming gzip member decoder.
///
/// Two entry points, because expansion is bounded: [`GzipDecoder::push`] takes input and
/// [`GzipDecoder::drain`] produces at most [`OUTPUT_CHUNK`] bytes per call. The caller feeds, then drains
/// in a loop, then feeds again — so a 32 KiB read that expands to 32 MiB costs one chunk of memory at a
/// time instead of all of it.
pub struct GzipDecoder {
    state: State,
    /// Compressed bytes not yet consumed.
    pending: Vec<u8>,
    /// Decoded bytes of the current round, waiting for [`GzipDecoder::take`].
    out: Vec<u8>,
    /// Total compressed bytes consumed, so `Finished` can report an offset into the caller's input.
    consumed: usize,
    /// The stream is not a gzip member this decoder can decode, or is corrupt.
    failed: bool,
    /// The last round filled its output before the input ran out, so more can still be produced from
    /// what is buffered.
    round_pending: bool,
}

impl std::fmt::Debug for GzipDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GzipDecoder")
            .field("done", &self.is_done())
            .field("pending", &self.pending.len())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

enum State {
    /// Reading the fixed header and the optional fields.
    Header,
    /// Inside the deflate payload.
    Deflate { inner: flate2::Decompress },
    /// Deflate ended; this many trailer bytes are still to be dropped.
    Trailer { remaining: usize },
    /// The member ended.
    Done,
}

impl GzipDecoder {
    pub fn new() -> Self {
        Self {
            state: State::Header,
            pending: Vec::new(),
            out: Vec::new(),
            consumed: 0,
            failed: false,
            round_pending: false,
        }
    }

    /// True when the stream is not a gzip member this decoder can decode, or is corrupt.
    pub fn failed(&self) -> bool {
        self.failed
    }

    /// True when the member has ended.
    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// Compressed bytes buffered but not yet expanded.
    pub fn buffered_input(&self) -> usize {
        self.pending.len()
    }

    /// True while more output can still be produced from the input already buffered.
    pub fn has_pending_output(&self) -> bool {
        !self.out.is_empty() || self.round_pending
    }

    /// Feed compressed bytes.
    ///
    /// The returned offset is relative to `data` and is only meaningful for
    /// [`GzipProgress::Finished`]. Output from this input is produced by [`GzipDecoder::drain`], at most
    /// [`OUTPUT_CHUNK`] bytes at a time.
    pub fn push(&mut self, data: &[u8]) -> GzipProgress {
        let start = self.consumed;
        self.pending.extend_from_slice(data);
        if self.failed {
            return GzipProgress::NeedMore;
        }
        // The header is bounded and tiny, so it is resolved eagerly; the deflate payload is not.
        let mut guard = 0usize;
        while matches!(self.state, State::Header) && !self.failed {
            guard += 1;
            if guard > 4 {
                break;
            }
            match header_len(&self.pending) {
                HeaderLength::Incomplete => break,
                HeaderLength::Invalid => {
                    self.failed = true;
                    break;
                }
                HeaderLength::Complete(length) => {
                    self.pending.drain(..length);
                    self.consumed += length;
                    self.state = State::Deflate {
                        inner: flate2::Decompress::new(false),
                    };
                }
            }
        }
        if matches!(self.state, State::Done) {
            return GzipProgress::Finished(self.consumed - start);
        }
        // One bounded round now, so a caller that only ever pushes still makes progress; `drain`
        // produces the rest.
        self.run(OUTPUT_CHUNK);
        if matches!(self.state, State::Done) {
            GzipProgress::Finished(self.consumed - start)
        } else {
            GzipProgress::NeedMore
        }
    }

    /// Produce the next [`OUTPUT_CHUNK`] of decompressed bytes, or `None` when more input is needed.
    pub fn drain(&mut self) -> Option<Vec<u8>> {
        if !self.out.is_empty() {
            return Some(self.take());
        }
        if !self.round_pending {
            return None;
        }
        self.round_pending = false;
        self.run(OUTPUT_CHUNK);
        if self.out.is_empty() {
            None
        } else {
            Some(self.take())
        }
    }

    /// Expand at most `budget` bytes of output from what is buffered.
    ///
    /// Sets [`GzipDecoder::round_pending`] when the budget ran out before the input did: the caller then
    /// asks for another round instead of feeding more, which is what keeps the buffered output bounded.
    fn run(&mut self, budget: usize) {
        if self.failed || self.pending.is_empty() {
            return;
        }
        // `decompress_vec` expands into the vector's **spare capacity**, so the budget has to be applied
        // by reserving exactly that much per call and stopping as soon as it is full. Reserving a large
        // capacity and checking afterwards would let one call expand the whole bomb.
        loop {
            match &mut self.state {
                State::Deflate { inner } => {
                    if self.pending.is_empty() {
                        return;
                    }
                    // Exactly the remaining budget of spare capacity, so this call cannot overshoot it.
                    let room = budget.saturating_sub(self.out.len());
                    if room == 0 {
                        self.round_pending = true;
                        return;
                    }
                    self.out.reserve_exact(room);
                    let before_in = inner.total_in();
                    let before_out = inner.total_out();
                    let status =
                        inner.decompress_vec(&self.pending, &mut self.out, flate2::FlushDecompress::None);
                    let taken = (inner.total_in() - before_in) as usize;
                    let produced = inner.total_out() - before_out;
                    self.pending.drain(..taken);
                    self.consumed += taken;
                    match status {
                        Ok(flate2::Status::StreamEnd) => {
                            self.state = State::Trailer { remaining: 8 };
                        }
                        Ok(flate2::Status::Ok) | Ok(flate2::Status::BufError) => {
                            if taken == 0 && produced == 0 {
                                return;
                            }
                        }
                        Err(_) => {
                            self.failed = true;
                            return;
                        }
                    }
                    // The round's budget is what bounds memory: stop as soon as it is reached, even
                    // though the buffered input could produce more.
                    if self.out.len() >= budget {
                        self.round_pending = !self.pending.is_empty();
                        return;
                    }
                }
                State::Trailer { remaining } => {
                    let drop = (*remaining).min(self.pending.len());
                    self.pending.drain(..drop);
                    self.consumed += drop;
                    *remaining -= drop;
                    if *remaining == 0 {
                        self.state = State::Done;
                        return;
                    }
                    // The trailer is incomplete: wait for more input.
                    return;
                }
                // `Done` keeps any trailing bytes in `pending` for the caller to read; `Header` was
                // resolved by `push`.
                State::Done | State::Header => return,
            }
        }
    }

    /// Take the decoded bytes of the current round.
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// The compressed bytes that followed the member, if any.
    ///
    /// Only meaningful once [`GzipDecoder::is_done`]. A second gzip member is legal but no origin sends
    /// one for HTML; the caller counts these bytes and drops them rather than emitting them unframed.
    pub fn trailing(&self) -> &[u8] {
        if self.is_done() {
            &self.pending
        } else {
            &[]
        }
    }
}

impl Default for GzipDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// How much of `buf` the gzip header takes.
enum HeaderLength {
    Incomplete,
    Invalid,
    Complete(usize),
}

/// Parse the gzip header at the start of `buf` (RFC 1952 § 2.3).
fn header_len(buf: &[u8]) -> HeaderLength {
    if buf.len() < 10 {
        return HeaderLength::Incomplete;
    }
    // Magic, and `CM = 8` (deflate) is the only method that exists.
    if buf[0] != 0x1f || buf[1] != 0x8b || buf[2] != 8 {
        return HeaderLength::Invalid;
    }
    let flags = buf[3];
    // Reserved bits must be zero.
    if flags & 0xE0 != 0 {
        return HeaderLength::Invalid;
    }
    let mut offset = 10usize;
    if flags & 0x04 != 0 {
        // FEXTRA: a 2-byte little-endian length followed by that many bytes.
        if buf.len() < offset + 2 {
            return HeaderLength::Incomplete;
        }
        let extra = u16::from_le_bytes([buf[offset], buf[offset + 1]]) as usize;
        offset += 2 + extra;
        if buf.len() < offset {
            return HeaderLength::Incomplete;
        }
    }
    for flag in [0x08u8, 0x10] {
        // FNAME, FCOMMENT: NUL-terminated.
        if flags & flag != 0 {
            match buf[offset..].iter().position(|byte| *byte == 0) {
                Some(end) => offset += end + 1,
                None => {
                    return if buf.len() > MAX_HEADER {
                        HeaderLength::Invalid
                    } else {
                        HeaderLength::Incomplete
                    }
                }
            }
        }
    }
    if flags & 0x02 != 0 {
        // FHCRC: two bytes.
        offset += 2;
        if buf.len() < offset {
            return HeaderLength::Incomplete;
        }
    }
    if offset > MAX_HEADER {
        return HeaderLength::Invalid;
    }
    HeaderLength::Complete(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).expect("compress");
        encoder.finish().expect("finish")
    }

    fn decode_in(chunks: &[&[u8]]) -> Vec<u8> {
        let mut decoder = GzipDecoder::new();
        let mut out = Vec::new();
        for chunk in chunks {
            decoder.push(chunk);
            out.extend(decoder.take());
        }
        assert!(!decoder.failed(), "the stream must decode");
        out
    }

    #[test]
    fn a_gzip_member_decodes_to_its_payload() {
        let payload = b"<!doctype html><html><head></head><body>hello</body></html>";
        assert_eq!(decode_in(&[&gzip(payload)]), payload.to_vec());
    }

    #[test]
    fn every_split_of_the_compressed_stream_decodes_the_same_way() {
        let payload = b"<!doctype html><html><head></head><body>every split</body></html>";
        let compressed = gzip(payload);
        for split in 1..compressed.len() {
            let decoded = decode_in(&[&compressed[..split], &compressed[split..]]);
            assert_eq!(decoded, payload.to_vec(), "split at {split}");
        }
        // And one byte at a time.
        let chunks: Vec<&[u8]> = compressed.chunks(1).collect();
        assert_eq!(decode_in(&chunks), payload.to_vec());
    }

    #[test]
    fn a_large_payload_decodes_across_many_feeds() {
        let mut payload = Vec::new();
        for index in 0..4000 {
            payload.extend_from_slice(format!("<div class=\"row-{index}\">row {index}</div>\n").as_bytes());
        }
        let compressed = gzip(&payload);
        let chunks: Vec<&[u8]> = compressed.chunks(997).collect();
        assert_eq!(decode_in(&chunks), payload);
    }

    #[test]
    fn the_header_length_accounts_for_every_optional_field() {
        // No optional flags: 10 bytes.
        let mut header = vec![0x1f, 0x8b, 8, 0];
        header.extend_from_slice(&[0, 0, 0, 0, 0, 0xff]);
        assert!(matches!(header_len(&header), HeaderLength::Complete(10)));

        // FEXTRA with 3 bytes.
        let mut with_extra = vec![0x1f, 0x8b, 8, 0x04];
        with_extra.extend_from_slice(&[0, 0, 0, 0, 0, 0xff]);
        with_extra.extend_from_slice(&3u16.to_le_bytes());
        with_extra.extend_from_slice(b"abc");
        assert!(matches!(header_len(&with_extra), HeaderLength::Complete(15)));

        // FNAME: `name\0`.
        let mut with_name = vec![0x1f, 0x8b, 8, 0x08];
        with_name.extend_from_slice(&[0, 0, 0, 0, 0, 0xff]);
        with_name.extend_from_slice(b"page.html\0");
        assert!(matches!(header_len(&with_name), HeaderLength::Complete(20)));

        // FHCRC.
        let mut with_crc = vec![0x1f, 0x8b, 8, 0x02];
        with_crc.extend_from_slice(&[0, 0, 0, 0, 0, 0xff]);
        with_crc.extend_from_slice(&[0, 0]);
        assert!(matches!(header_len(&with_crc), HeaderLength::Complete(12)));
    }

    #[test]
    fn a_stream_that_is_not_gzip_is_reported_not_guessed() {
        let mut decoder = GzipDecoder::new();
        decoder.push(b"<!doctype html>");
        assert!(decoder.failed());
        // A wrong compression method is equally refused.
        let mut decoder = GzipDecoder::new();
        decoder.push(&[0x1f, 0x8b, 7, 0, 0, 0, 0, 0, 0, 0xff]);
        assert!(decoder.failed());
    }

    #[test]
    fn a_corrupt_deflate_payload_is_reported() {
        let payload = b"<!doctype html><html><head></head><body>corrupt me</body></html>";
        let mut compressed = gzip(payload);
        // Damage the start of the deflate payload, leaving the gzip header intact.
        for byte in &mut compressed[10..14] {
            *byte = 0xFF;
        }
        let mut decoder = GzipDecoder::new();
        decoder.push(&compressed);
        assert!(
            decoder.failed(),
            "corruption must be reported, never decoded into silently wrong output"
        );
    }

    #[test]
    fn bytes_after_the_member_are_reported_not_consumed() {
        let payload = b"<html><head></head><body>x</body></html>";
        let mut compressed = gzip(payload);
        let member_len = compressed.len();
        compressed.extend_from_slice(b"trailing");
        let mut decoder = GzipDecoder::new();
        let progress = decoder.push(&compressed);
        assert_eq!(progress, GzipProgress::Finished(member_len));
        assert_eq!(decoder.take(), payload.to_vec());
    }
}

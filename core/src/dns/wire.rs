//! Minimal DNS wire-format (RFC 1035) parsing and message construction.
//!
//! Only what M0 needs: parse a query, walk answer records to find CNAME chains, and build
//! synthetic replies. Unknown record types are preserved as opaque RDATA where it matters
//! (OPT/pseudo records are dropped on cache), everything else keeps its raw bytes.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_HTTPS: u16 = 65;

pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_REFUSED: u8 = 5;

const HEADER_LEN: usize = 12;
/// Compression pointers must point strictly backwards; more jumps than this is a loop.
const MAX_POINTER_JUMPS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    Truncated,
    BadPointer,
    BadLabel,
    BadUtf8,
    NoQuestion,
    TooLarge,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            DnsError::Truncated => "message truncated",
            DnsError::BadPointer => "bad compression pointer",
            DnsError::BadLabel => "malformed label",
            DnsError::BadUtf8 => "name is not valid UTF-8",
            DnsError::NoQuestion => "message has no question",
            DnsError::TooLarge => "message too large",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for DnsError {}

/// A parsed question section entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Lowercased, without the trailing dot. The root is the empty string.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// One parsed resource record. `rdata` is the decompressed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl Record {
    /// The target of a CNAME record, if this is one and the payload decodes.
    pub fn cname_target(&self) -> Option<String> {
        if self.rtype != TYPE_CNAME {
            return None;
        }
        read_name(&self.rdata, 0).ok().map(|(name, _)| name)
    }

    /// The IPv4 address of an A record.
    pub fn a_addr(&self) -> Option<Ipv4Addr> {
        if self.rtype != TYPE_A || self.rdata.len() != 4 {
            return None;
        }
        Some(Ipv4Addr::new(
            self.rdata[0],
            self.rdata[1],
            self.rdata[2],
            self.rdata[3],
        ))
    }

    /// The IPv6 address of an AAAA record.
    pub fn aaaa_addr(&self) -> Option<Ipv6Addr> {
        if self.rtype != TYPE_AAAA || self.rdata.len() != 16 {
            return None;
        }
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&self.rdata);
        Some(Ipv6Addr::from(octets))
    }
}

/// A parsed DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl Message {
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000f) as u8
    }

    pub fn is_truncated(&self) -> bool {
        self.flags & 0x0200 != 0
    }

    pub fn question(&self) -> Option<&Question> {
        self.questions.first()
    }

    /// Parse a complete message.
    pub fn parse(buf: &[u8]) -> Result<Self, DnsError> {
        if buf.len() < HEADER_LEN {
            return Err(DnsError::Truncated);
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
        let nscount = u16::from_be_bytes([buf[8], buf[9]]) as usize;
        let arcount = u16::from_be_bytes([buf[10], buf[11]]) as usize;

        let mut pos = HEADER_LEN;
        let mut questions = Vec::with_capacity(qdcount);
        for _ in 0..qdcount {
            let (name, next) = read_name(buf, pos)?;
            pos = next;
            if pos + 4 > buf.len() {
                return Err(DnsError::Truncated);
            }
            questions.push(Question {
                name,
                qtype: u16::from_be_bytes([buf[pos], buf[pos + 1]]),
                qclass: u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]),
            });
            pos += 4;
        }

        let mut answers = Vec::with_capacity(ancount);
        let mut authorities = Vec::with_capacity(nscount);
        let mut additionals = Vec::with_capacity(arcount);
        for (idx, count) in [ancount, nscount, arcount].into_iter().enumerate() {
            let sink = match idx {
                0 => &mut answers,
                1 => &mut authorities,
                _ => &mut additionals,
            };
            for _ in 0..count {
                let (record, next) = read_record(buf, pos)?;
                pos = next;
                sink.push(record);
            }
        }

        Ok(Self {
            id,
            flags,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    /// Every name that appears in a CNAME chain in the answer section, in order.
    ///
    /// This is what makes CNAME cloaking detectable: an ad host can be hidden behind
    /// `metrics.example.com CNAME tracker.doubleclick.net`, and the query name alone would
    /// never match the rule.
    pub fn cname_chain(&self) -> Vec<String> {
        let mut out = Vec::new();
        for record in &self.answers {
            if let Some(target) = record.cname_target() {
                if !target.is_empty() && !out.contains(&target) {
                    out.push(target);
                }
            }
        }
        out
    }

    /// The smallest TTL across answer records, if there are any.
    pub fn min_answer_ttl(&self) -> Option<u32> {
        self.answers.iter().map(|r| r.ttl).min()
    }
}

/// Read a (possibly compressed) domain name starting at `pos`.
///
/// Returns the lowercased dotted name without a trailing dot plus the offset just past the
/// name in the *original* position (i.e. after the first pointer, if any).
pub fn read_name(buf: &[u8], pos: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut cursor = pos;
    let mut next_after = None;
    let mut jumps = 0usize;
    let mut last_pointer = usize::MAX;

    loop {
        let len = *buf.get(cursor).ok_or(DnsError::Truncated)?;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    let end = cursor + 1;
                    return Ok((
                        join_labels(&labels)?,
                        next_after.unwrap_or(end).min(buf.len()),
                    ));
                }
                let start = cursor + 1;
                let end = start + len as usize;
                if end > buf.len() {
                    return Err(DnsError::Truncated);
                }
                labels.push(&buf[start..end]);
                cursor = end;
            }
            0xc0 => {
                let lo = *buf.get(cursor + 1).ok_or(DnsError::Truncated)?;
                let target = (((len & 0x3f) as usize) << 8) | lo as usize;
                if next_after.is_none() {
                    next_after = Some(cursor + 2);
                }
                // A pointer must move strictly backwards, otherwise a crafted message can make
                // us spin; this also bounds the work per name.
                if target >= cursor || target >= last_pointer {
                    return Err(DnsError::BadPointer);
                }
                last_pointer = target;
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(DnsError::BadPointer);
                }
                cursor = target;
            }
            _ => return Err(DnsError::BadLabel),
        }
    }
}

fn join_labels(labels: &[&[u8]]) -> Result<String, DnsError> {
    if labels.is_empty() {
        return Ok(String::new());
    }
    let mut out = String::new();
    for (idx, label) in labels.iter().enumerate() {
        if idx > 0 {
            out.push('.');
        }
        let s = std::str::from_utf8(label).map_err(|_| DnsError::BadUtf8)?;
        out.push_str(&s.to_ascii_lowercase());
    }
    Ok(out)
}

fn read_record(buf: &[u8], pos: usize) -> Result<(Record, usize), DnsError> {
    let (name, mut cursor) = read_name(buf, pos)?;
    if cursor + 10 > buf.len() {
        return Err(DnsError::Truncated);
    }
    let rtype = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
    let rclass = u16::from_be_bytes([buf[cursor + 2], buf[cursor + 3]]);
    let ttl = u32::from_be_bytes([
        buf[cursor + 4],
        buf[cursor + 5],
        buf[cursor + 6],
        buf[cursor + 7],
    ]);
    let rdlen = u16::from_be_bytes([buf[cursor + 8], buf[cursor + 9]]) as usize;
    cursor += 10;
    let rdata_end = cursor
        .checked_add(rdlen)
        .ok_or(DnsError::Truncated)?;
    if rdata_end > buf.len() {
        return Err(DnsError::Truncated);
    }
    let raw = &buf[cursor..rdata_end];

    // Names inside RDATA may be compressed against the whole message, so they are expanded
    // here and stored decompressed; that keeps cached records position-independent.
    let rdata = match rtype {
        TYPE_CNAME | TYPE_NS | TYPE_PTR => {
            let (target, _) = read_name(buf, cursor)?;
            encode_name(&target).map_err(|_| DnsError::TooLarge)?
        }
        _ => raw.to_vec(),
    };

    Ok((
        Record {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        },
        rdata_end,
    ))
}

/// Encode a dotted name (without trailing dot) into uncompressed wire form.
pub fn encode_name(name: &str) -> Result<Vec<u8>, DnsError> {
    let trimmed = name.trim_end_matches('.');
    let mut out = Vec::with_capacity(trimmed.len() + 2);
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(DnsError::BadLabel);
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    Ok(out)
}

/// Build a response to `query` carrying `rcode` and no records (block/nxdomain/refused).
pub fn build_rcode_response(query: &Message, rcode: u8) -> Vec<u8> {
    build_response(query, rcode, &[], &[])
}

/// Build a response whose answer section holds `answers`.
///
/// `answers` are expected to be uncompressed records (as produced by `Record` parsing).
pub fn build_response(
    query: &Message,
    rcode: u8,
    answers: &[Record],
    authorities: &[Record],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&query.id.to_be_bytes());
    // QR=1, keep OPCODE from the query, RD from the query, set RA.
    let mut flags = 0x8000u16 | (query.flags & 0x7900) | 0x0080;
    flags |= u16::from(rcode & 0x000f);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&(query.questions.len() as u16).to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&(authorities.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // no additionals (no OPT/EDNS in M0)

    for question in &query.questions {
        match encode_name(&question.name) {
            Ok(mut bytes) => out.append(&mut bytes),
            Err(_) => {
                // A name we cannot re-encode must not produce a broken message.
                return build_rcode_response(query, RCODE_FORMERR);
            }
        }
        out.extend_from_slice(&question.qtype.to_be_bytes());
        out.extend_from_slice(&question.qclass.to_be_bytes());
    }

    for record in answers.iter().chain(authorities.iter()) {
        match encode_name(&record.name) {
            Ok(mut bytes) => out.append(&mut bytes),
            Err(_) => continue,
        }
        out.extend_from_slice(&record.rtype.to_be_bytes());
        out.extend_from_slice(&record.rclass.to_be_bytes());
        out.extend_from_slice(&record.ttl.to_be_bytes());
        let len = record.rdata.len().min(u16::MAX as usize) as u16;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&record.rdata[..len as usize]);
    }

    out
}

/// An `A` or `AAAA` record for a blocked name.
pub fn zero_ip_record(name: &str, qtype: u16, ttl: u32) -> Option<Record> {
    let (rtype, rdata) = match qtype {
        TYPE_A => (TYPE_A, Ipv4Addr::UNSPECIFIED.octets().to_vec()),
        TYPE_AAAA => (TYPE_AAAA, Ipv6Addr::UNSPECIFIED.octets().to_vec()),
        _ => return None,
    };
    Some(Record {
        name: name.to_string(),
        rtype,
        rclass: CLASS_IN,
        ttl,
        rdata,
    })
}

/// The query name a filter should match on, lowercased.
pub fn normalize_query_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a raw query for `top.zztweb.zshield` style tests.
    pub fn raw_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&encode_name(name).unwrap());
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out
    }

    fn rr(name: &str, rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&encode_name(name).unwrap());
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    #[test]
    fn parses_a_simple_query() {
        let raw = raw_query(0x1234, "www.baidu.com", TYPE_A);
        let msg = Message::parse(&raw).expect("parse");
        assert_eq!(msg.id, 0x1234);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.question().unwrap().name, "www.baidu.com");
        assert_eq!(msg.question().unwrap().qtype, TYPE_A);
        assert!(msg.answers.is_empty());
    }

    #[test]
    fn rejects_truncated_and_malformed_messages() {
        assert_eq!(Message::parse(&[0u8; 5]).unwrap_err(), DnsError::Truncated);
        // Header claims one question but there is no body.
        let mut raw = raw_query(1, "a.com", TYPE_A);
        raw.truncate(HEADER_LEN);
        assert_eq!(Message::parse(&raw).unwrap_err(), DnsError::Truncated);
        // Compression pointer that points forwards is invalid.
        let mut bad = raw_query(1, "a.com", TYPE_A);
        bad[HEADER_LEN] = 0xc0;
        bad[HEADER_LEN + 1] = 0x40;
        assert!(Message::parse(&bad).is_err());
    }

    #[test]
    fn walks_cname_chain() {
        let mut raw = raw_query(7, "metrics.example.com", TYPE_A);
        raw[6] = 0;
        raw[7] = 4; // ancount = 4
        // two CNAMEs then an A record, plus one unrelated A
        let cname1 = rr(
            "metrics.example.com",
            TYPE_CNAME,
            120,
            &encode_name("tracker.doubleclick.net").unwrap(),
        );
        let cname2 = rr(
            "tracker.doubleclick.net",
            TYPE_CNAME,
            120,
            &encode_name("edge.ads.example.net").unwrap(),
        );
        let a = rr("edge.ads.example.net", TYPE_A, 60, &[1, 2, 3, 4]);
        let other = rr("other.example.com", TYPE_CNAME, 60, &encode_name("safe.example.org").unwrap());
        raw.extend_from_slice(&cname1);
        raw.extend_from_slice(&cname2);
        raw.extend_from_slice(&a);
        raw.extend_from_slice(&other);

        let msg = Message::parse(&raw).expect("parse");
        assert_eq!(
            msg.cname_chain(),
            vec![
                "tracker.doubleclick.net".to_string(),
                "edge.ads.example.net".to_string(),
                "safe.example.org".to_string()
            ]
        );
        assert_eq!(msg.min_answer_ttl(), Some(60));
        assert_eq!(msg.answers[2].a_addr(), Some(Ipv4Addr::new(1, 2, 3, 4)));
        // Parsing again must give the same picture (records stored decompressed).
        assert_eq!(Message::parse(&raw).expect("reparse"), msg);
    }

    #[test]
    fn handles_compressed_names_in_answers() {
        // Question name at offset 12; answer name is a pointer back to it.
        let mut raw = raw_query(9, "a.example.com", TYPE_CNAME);
        raw[6] = 0;
        raw[7] = 1;
        raw.extend_from_slice(&[0xc0, 0x0c]);
        raw.extend_from_slice(&TYPE_CNAME.to_be_bytes());
        raw.extend_from_slice(&CLASS_IN.to_be_bytes());
        raw.extend_from_slice(&300u32.to_be_bytes());
        // RDATA: a name that itself compresses to the question ("a.example.com") - reuse the
        // same pointer style by pointing at offset 14 ("example.com").
        let rdata = vec![0xc0, 0x0e];
        raw.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        raw.extend_from_slice(&rdata);

        let msg = Message::parse(&raw).expect("parse");
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].name, "a.example.com");
        assert_eq!(msg.answers[0].cname_target().unwrap(), "example.com");
    }

    #[test]
    fn builds_zero_ip_answers() {
        let raw = raw_query(0x4242, "doubleclick.net", TYPE_A);
        let query = Message::parse(&raw).expect("parse");
        let answer = zero_ip_record("doubleclick.net", TYPE_A, 1).expect("record");
        let resp = build_response(&query, RCODE_NOERROR, &[answer], &[]);
        let parsed = Message::parse(&resp).expect("parse response");
        assert_eq!(parsed.id, 0x4242);
        assert_eq!(parsed.rcode(), RCODE_NOERROR);
        assert_eq!(parsed.questions, query.questions);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].a_addr(), Some(Ipv4Addr::UNSPECIFIED));
        // QR bit set + RA set.
        assert_eq!(parsed.flags & 0x8000, 0x8000);
        assert_eq!(parsed.flags & 0x0080, 0x0080);

        let raw6 = raw_query(1, "doubleclick.net", TYPE_AAAA);
        let query6 = Message::parse(&raw6).expect("parse");
        let answer6 = zero_ip_record("doubleclick.net", TYPE_AAAA, 1).expect("record");
        let resp6 = build_response(&query6, RCODE_NOERROR, &[answer6], &[]);
        let parsed6 = Message::parse(&resp6).expect("parse response");
        assert_eq!(parsed6.answers[0].aaaa_addr(), Some(Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn builds_nxdomain_without_answers() {
        let raw = raw_query(2, "zshield-block-test.com", TYPE_A);
        let query = Message::parse(&raw).expect("parse");
        let resp = build_rcode_response(&query, RCODE_NXDOMAIN);
        let parsed = Message::parse(&resp).expect("parse response");
        assert_eq!(parsed.rcode(), RCODE_NXDOMAIN);
        assert!(parsed.answers.is_empty());
        assert_eq!(parsed.question().unwrap().name, "zshield-block-test.com");
    }

    #[test]
    fn name_encoding_round_trips() {
        for name in ["", "a.com", "www.baidu.com", "x.y.z.example.co.uk"] {
            let enc = encode_name(name).expect("encode");
            let (decoded, consumed) = read_name(&enc, 0).expect("decode");
            assert_eq!(decoded, name);
            assert_eq!(consumed, enc.len());
        }
        assert_eq!(encode_name(&"a".repeat(64)).unwrap_err(), DnsError::BadLabel);
    }

    #[test]
    fn rejects_pointer_loops() {
        // Name that points at itself: the pointer does not move backwards, so it is rejected
        // outright rather than followed.
        let buf = [0xc0, 0x00];
        assert_eq!(read_name(&buf, 0).unwrap_err(), DnsError::BadPointer);
        // Two pointers pointing at each other (forward + backward) must terminate with an error.
        let buf = [0xc0, 0x02, 0xc0, 0x00];
        assert!(read_name(&buf, 2).is_err());
    }
}

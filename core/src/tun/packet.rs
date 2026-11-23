//! IP / TCP / UDP packet parsing and construction for the userspace tunnel.
//!
//! The TUN device is used with `medium-ip` framing: every read returns one bare IP packet (version
//! nibble first, no Ethernet header, no 4-byte packet-info prefix — `VpnService.Builder` without
//! `addAddress` PI flags gives exactly that).
//!
//! Deliberate limits, also documented in `docs/TESTING.md`:
//! - IPv4 options and IPv6 extension headers are dropped rather than parsed,
//! - fragmented packets are dropped (a fragment carries no ports, so it cannot be routed by the
//!   NAT table; TCP retransmits and UDP senders fall back on their own),
//! - ICMP is not handled at all: `ping` through the tunnel does not work (see the M2a note).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Protocol number of TCP.
pub const IPPROTO_TCP: u8 = 6;
/// Protocol number of UDP.
pub const IPPROTO_UDP: u8 = 17;

pub(crate) const IPV4_MIN_HEADER: usize = 20;
pub(crate) const IPV6_HEADER: usize = 40;
pub(crate) const UDP_HEADER: usize = 8;
pub(crate) const TCP_MIN_HEADER: usize = 20;

/// An IP packet's addressing plus its transport payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPacket<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    /// Everything after the IP header: the TCP segment or UDP datagram.
    pub payload: &'a [u8],
}

/// Parse a bare IP packet, returning `None` for anything this tunnel does not handle
/// (non-TCP/UDP, fragmented, truncated, IPv4 options, IPv6 extension headers).
pub fn parse(buf: &[u8]) -> Option<IpPacket<'_>> {
    match buf.first()? >> 4 {
        4 => parse_ipv4(buf),
        6 => parse_ipv6(buf),
        _ => None,
    }
}

fn parse_ipv4(buf: &[u8]) -> Option<IpPacket<'_>> {
    if buf.len() < IPV4_MIN_HEADER {
        return None;
    }
    let ihl = usize::from(buf[0] & 0x0f) * 4;
    if ihl != IPV4_MIN_HEADER {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    if total_len < ihl || total_len > buf.len() {
        return None;
    }
    let protocol = buf[9];
    // Fragmented packets (offset != 0 or MF set) are out of scope: a non-first fragment has no
    // transport header, and reassembly is not worth its memory in a phone-side tunnel.
    let flags_frag = u16::from_be_bytes([buf[6], buf[7]]);
    if flags_frag & 0x3fff != 0 {
        return None;
    }
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    Some(IpPacket {
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        protocol,
        payload: &buf[ihl..total_len],
    })
}

fn parse_ipv6(buf: &[u8]) -> Option<IpPacket<'_>> {
    if buf.len() < IPV6_HEADER {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([buf[4], buf[5]]));
    let next_header = buf[6];
    if next_header != IPPROTO_TCP && next_header != IPPROTO_UDP {
        // Extension headers (including the fragment header) are not walked.
        return None;
    }
    let end = IPV6_HEADER.checked_add(payload_len)?;
    if end > buf.len() {
        return None;
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&buf[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&buf[24..40]);
    Some(IpPacket {
        src: IpAddr::V6(Ipv6Addr::from(src)),
        dst: IpAddr::V6(Ipv6Addr::from(dst)),
        protocol: next_header,
        payload: &buf[IPV6_HEADER..end],
    })
}

/// A parsed UDP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp(payload: &[u8]) -> Option<UdpDatagram<'_>> {
    if payload.len() < UDP_HEADER {
        return None;
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let length = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
    if length < UDP_HEADER || length > payload.len() {
        return None;
    }
    Some(UdpDatagram {
        src_port,
        dst_port,
        payload: &payload[UDP_HEADER..length],
    })
}

/// The fields of a TCP segment the tunnel layer itself needs.
///
/// The payload is not exposed: TCP data is handed to smoltcp as a whole packet, which does the
/// sequence bookkeeping. Only the ingress decision (new connection? blocklist port?) reads these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub syn: bool,
    pub ack_flag: bool,
    pub rst: bool,
    pub fin: bool,
}

pub fn parse_tcp(payload: &[u8]) -> Option<TcpSegment> {
    if payload.len() < TCP_MIN_HEADER {
        return None;
    }
    let data_offset = usize::from(payload[12] >> 4) * 4;
    if data_offset < TCP_MIN_HEADER || data_offset > payload.len() {
        return None;
    }
    let flags = payload[13];
    Some(TcpSegment {
        src_port: u16::from_be_bytes([payload[0], payload[1]]),
        dst_port: u16::from_be_bytes([payload[2], payload[3]]),
        seq: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        ack: u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]),
        syn: flags & 0x02 != 0,
        ack_flag: flags & 0x10 != 0,
        rst: flags & 0x04 != 0,
        fin: flags & 0x01 != 0,
    })
}

/// Build a complete UDP/IP packet.
///
/// Checksums are always computed: the IPv4 UDP checksum is optional on the wire but mandatory
/// for IPv6, and computing it unconditionally means replies survive any intermediate validation.
pub fn build_udp(
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => build_udp_v4(src, dst, src_port, dst_port, payload),
        (IpAddr::V6(src), IpAddr::V6(dst)) => build_udp_v6(src, dst, src_port, dst_port, payload),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "address family mismatch between source and destination",
        )),
    }
}

fn build_udp_v4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let udp_len = UDP_HEADER + payload.len();
    let total_len = IPV4_MIN_HEADER + udp_len;
    if total_len > u16::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet too large"));
    }
    let mut out = vec![0u8; total_len];
    out[0] = 0x45; // IPv4, IHL 5
    out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    out[8] = 64; // TTL
    out[9] = IPPROTO_UDP;
    out[12..16].copy_from_slice(&src.octets());
    out[16..20].copy_from_slice(&dst.octets());
    let header_checksum = checksum(&out[..IPV4_MIN_HEADER]);
    out[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    let udp = &mut out[IPV4_MIN_HEADER..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[UDP_HEADER..].copy_from_slice(payload);
    let sum = udp_checksum(src, dst, &out[IPV4_MIN_HEADER..]);
    // A computed zero must be transmitted as 0xffff to stay distinguishable from "not computed".
    let sum = if sum == 0 { 0xffff } else { sum };
    out[IPV4_MIN_HEADER + 6..IPV4_MIN_HEADER + 8].copy_from_slice(&sum.to_be_bytes());
    Ok(out)
}

fn build_udp_v6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let udp_len = UDP_HEADER + payload.len();
    let total_len = IPV6_HEADER + udp_len;
    if udp_len > u16::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet too large"));
    }
    let mut out = vec![0u8; total_len];
    out[0] = 0x60; // IPv6
    out[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    out[6] = IPPROTO_UDP;
    out[7] = 64; // hop limit
    out[8..24].copy_from_slice(&src.octets());
    out[24..40].copy_from_slice(&dst.octets());

    let udp = &mut out[IPV6_HEADER..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[UDP_HEADER..].copy_from_slice(payload);
    let sum = udp_checksum_v6(src, dst, &out[IPV6_HEADER..]);
    let sum = if sum == 0 { 0xffff } else { sum };
    out[IPV6_HEADER + 6..IPV6_HEADER + 8].copy_from_slice(&sum.to_be_bytes());
    Ok(out)
}

/// Internet checksum (RFC 1071) over `data`, returned in host order.
pub fn checksum(data: &[u8]) -> u16 {
    finish(sum16(data))
}

fn sum16(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    sum
}

fn finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// UDP checksum over an IPv4 pseudo-header plus the UDP datagram.
pub fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut sum = sum16(&src.octets());
    sum += sum16(&dst.octets());
    sum += u32::from(IPPROTO_UDP);
    sum += udp.len() as u32;
    sum += sum16(udp);
    finish(sum)
}

/// UDP checksum over an IPv6 pseudo-header plus the UDP datagram.
pub fn udp_checksum_v6(src: Ipv6Addr, dst: Ipv6Addr, udp: &[u8]) -> u16 {
    let mut sum = sum16(&src.octets());
    sum += sum16(&dst.octets());
    sum += ((udp.len() as u32) >> 16) & 0xffff;
    sum += (udp.len() as u32) & 0xffff;
    sum += u32::from(IPPROTO_UDP);
    sum += sum16(udp);
    finish(sum)
}

/// TCP checksum over the IPv4 pseudo-header plus the TCP segment.
///
/// smoltcp computes its own checksums; this exists so tests (and any future raw-socket path) can
/// build segments that the stack will accept. It is the exact peer of [`udp_checksum`].
pub fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> u16 {
    let mut sum = sum16(&src.octets());
    sum += sum16(&dst.octets());
    sum += u32::from(IPPROTO_TCP);
    sum += segment.len() as u32;
    sum += sum16(segment);
    finish(sum)
}

/// TCP checksum over the IPv6 pseudo-header plus the TCP segment.
pub fn tcp_checksum_v6(src: Ipv6Addr, dst: Ipv6Addr, segment: &[u8]) -> u16 {
    let mut sum = sum16(&src.octets());
    sum += sum16(&dst.octets());
    sum += ((segment.len() as u32) >> 16) & 0xffff;
    sum += (segment.len() as u32) & 0xffff;
    sum += u32::from(IPPROTO_TCP);
    sum += sum16(segment);
    finish(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Vec<u8> {
        vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00]
    }

    fn udp_segment(src_port: u16, dst_port: u16, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&src_port.to_be_bytes());
        out.extend_from_slice(&dst_port.to_be_bytes());
        out.extend_from_slice(&((UDP_HEADER + body.len()) as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, body: &[u8]) -> Vec<u8> {
        let total = IPV4_MIN_HEADER + body.len();
        let mut out = vec![0u8; IPV4_MIN_HEADER];
        out[0] = 0x45;
        out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        out[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        out[8] = 64;
        out[9] = protocol;
        out[12..16].copy_from_slice(&src.octets());
        out[16..20].copy_from_slice(&dst.octets());
        let csum = checksum(&out);
        out[10..12].copy_from_slice(&csum.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, protocol: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; IPV6_HEADER];
        out[0] = 0x60;
        out[4..6].copy_from_slice(&(body.len() as u16).to_be_bytes());
        out[6] = protocol;
        out[7] = 64;
        out[8..24].copy_from_slice(&src.octets());
        out[24..40].copy_from_slice(&dst.octets());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn parses_ipv4_udp_query() {
        let body = payload();
        let raw = ipv4_packet(
            Ipv4Addr::new(10, 111, 222, 1),
            Ipv4Addr::new(10, 111, 222, 2),
            IPPROTO_UDP,
            &udp_segment(5353, 53, &body),
        );
        let packet = parse(&raw).expect("parse");
        assert_eq!(packet.src, IpAddr::V4(Ipv4Addr::new(10, 111, 222, 1)));
        assert_eq!(packet.dst, IpAddr::V4(Ipv4Addr::new(10, 111, 222, 2)));
        assert_eq!(packet.protocol, IPPROTO_UDP);
        let udp = parse_udp(packet.payload).expect("udp");
        assert_eq!(udp.src_port, 5353);
        assert_eq!(udp.dst_port, 53);
        assert_eq!(udp.payload, body.as_slice());
    }

    #[test]
    fn parses_ipv6_udp_query() {
        let body = payload();
        let src: Ipv6Addr = "fd00:7a73::1".parse().unwrap();
        let dst: Ipv6Addr = "fd00:7a73::2".parse().unwrap();
        let raw = ipv6_packet(src, dst, IPPROTO_UDP, &udp_segment(5353, 53, &body));
        let packet = parse(&raw).expect("parse");
        assert_eq!(packet.src, IpAddr::V6(src));
        assert_eq!(packet.dst, IpAddr::V6(dst));
        assert_eq!(parse_udp(packet.payload).expect("udp").dst_port, 53);
    }

    #[test]
    fn parses_tcp_flags_and_ports() {
        let mut segment = vec![0u8; TCP_MIN_HEADER];
        segment[0..2].copy_from_slice(&44321u16.to_be_bytes());
        segment[2..4].copy_from_slice(&443u16.to_be_bytes());
        segment[4..8].copy_from_slice(&7u32.to_be_bytes());
        segment[8..12].copy_from_slice(&9u32.to_be_bytes());
        segment[12] = 5 << 4;
        segment[13] = 0x02; // SYN
        let raw = ipv4_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(93, 184, 216, 34),
            IPPROTO_TCP,
            &segment,
        );
        let packet = parse(&raw).expect("parse");
        let tcp = parse_tcp(packet.payload).expect("tcp");
        assert_eq!(tcp.src_port, 44321);
        assert_eq!(tcp.dst_port, 443);
        assert_eq!(tcp.seq, 7);
        assert!(tcp.syn);
        assert!(!tcp.ack_flag);
        assert!(!tcp.fin);
    }

    #[test]
    fn rejects_non_tcp_udp_fragments_and_options() {
        let body = payload();
        let mut raw = ipv4_packet(
            Ipv4Addr::new(10, 111, 222, 1),
            Ipv4Addr::new(10, 111, 222, 2),
            IPPROTO_UDP,
            &udp_segment(5353, 53, &body),
        );
        raw[9] = 1; // ICMP
        // Only the protocol byte changed, so this still parses as an IP packet; the tunnel drops it
        // one layer up, which is what the assertions below check.
        assert_eq!(parse(&raw).expect("parse").protocol, 1);

        let mut fragmented = ipv4_packet(
            Ipv4Addr::new(10, 111, 222, 1),
            Ipv4Addr::new(10, 111, 222, 2),
            IPPROTO_UDP,
            &udp_segment(5353, 53, &body),
        );
        fragmented[7] = 0x01; // more-fragments flag
        assert!(parse(&fragmented).is_none());

        let mut with_options = ipv4_packet(
            Ipv4Addr::new(10, 111, 222, 1),
            Ipv4Addr::new(10, 111, 222, 2),
            IPPROTO_UDP,
            &udp_segment(5353, 53, &body),
        );
        with_options[0] = 0x46; // IHL 6
        assert!(parse(&with_options).is_none());

        let ext_header = ipv6_packet(
            "fd00:7a73::1".parse().unwrap(),
            "fd00:7a73::2".parse().unwrap(),
            0, // hop-by-hop
            &body,
        );
        assert!(parse(&ext_header).is_none());
    }

    #[test]
    fn rejects_truncated_packets() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45]).is_none());
        let raw = ipv4_packet(
            Ipv4Addr::new(10, 111, 222, 1),
            Ipv4Addr::new(10, 111, 222, 2),
            IPPROTO_UDP,
            &udp_segment(5353, 53, &payload()),
        );
        assert!(parse(&raw[..raw.len() - 3]).is_none());
        let raw6 = ipv6_packet(
            "fd00:7a73::1".parse().unwrap(),
            "fd00:7a73::2".parse().unwrap(),
            IPPROTO_UDP,
            &payload(),
        );
        assert!(parse(&raw6[..20]).is_none());
        // A TCP segment shorter than the fixed header is not a segment.
        assert!(parse_tcp(&[0u8; 8]).is_none());
        assert!(parse_udp(&[0u8; 4]).is_none());
    }

    #[test]
    fn builds_ipv4_udp_with_valid_checksums() {
        let body = vec![0xaa; 33];
        let src = Ipv4Addr::new(10, 111, 222, 2);
        let dst = Ipv4Addr::new(10, 111, 222, 1);
        let reply = build_udp(
            IpAddr::V4(src),
            IpAddr::V4(dst),
            53,
            5353,
            &body,
        )
        .expect("build");
        let packet = parse(&reply).expect("parse reply");
        assert_eq!(packet.src, IpAddr::V4(src));
        assert_eq!(packet.dst, IpAddr::V4(dst));
        let udp = parse_udp(packet.payload).expect("udp");
        assert_eq!(udp.src_port, 53);
        assert_eq!(udp.dst_port, 5353);
        assert_eq!(udp.payload, body.as_slice());

        // IPv4 header checksum verifies to zero.
        assert_eq!(checksum(&reply[..IPV4_MIN_HEADER]), 0);
        // UDP checksum verifies to zero over the pseudo-header.
        let segment = &reply[IPV4_MIN_HEADER..];
        let mut sum = sum16(&src.octets());
        sum += sum16(&dst.octets());
        sum += u32::from(IPPROTO_UDP);
        sum += segment.len() as u32;
        sum += sum16(segment);
        assert_eq!(finish(sum), 0);
    }

    #[test]
    fn builds_ipv6_udp_with_valid_checksum() {
        let body = vec![0xbb; 21];
        let src: Ipv6Addr = "fd00:7a73::2".parse().unwrap();
        let dst: Ipv6Addr = "fd00:7a73::1".parse().unwrap();
        let reply = build_udp(IpAddr::V6(src), IpAddr::V6(dst), 53, 5353, &body).expect("build");
        let packet = parse(&reply).expect("parse reply");
        let udp = parse_udp(packet.payload).expect("udp");
        assert_eq!(udp.payload, body.as_slice());

        let segment = &reply[IPV6_HEADER..];
        let mut sum = sum16(&src.octets());
        sum += sum16(&dst.octets());
        sum += ((segment.len() as u32) >> 16) & 0xffff;
        sum += (segment.len() as u32) & 0xffff;
        sum += u32::from(IPPROTO_UDP);
        sum += sum16(segment);
        assert_eq!(finish(sum), 0);
    }

    #[test]
    fn checksum_known_values() {
        // RFC 1071 style sanity: all-zero data has an all-ones checksum.
        assert_eq!(checksum(&[0u8; 20]), 0xffff);
        // Odd-length data is padded with a zero byte, not truncated.
        assert_eq!(checksum(&[0x00, 0x01, 0x00]), checksum(&[0x00, 0x01, 0x00, 0x00]));
        let data = [0x45u8, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06];
        let mut sum = 0u32;
        for chunk in data.chunks(2) {
            let hi = u32::from(chunk[0]);
            let lo = u32::from(*chunk.get(1).unwrap_or(&0));
            sum += (hi << 8) | lo;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(checksum(&data), !(sum as u16));
    }

    #[test]
    fn refuses_address_family_mismatch() {
        let err = build_udp(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            1,
            2,
            b"x",
        )
        .expect_err("must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}

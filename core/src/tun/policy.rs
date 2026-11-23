//! Packet-level policy: which connections are dropped, which are hijacked, which are forwarded.
//!
//! The decisions are pure functions of the packet's addressing plus the loaded configuration, so
//! they are unit-testable without a socket or a TUN device. Keeping them here (rather than inline in
//! the forwarding loop) is also what makes the "任意 IP:53 都劫持" and "QUIC 一律丢弃" rules
//! verifiable one by one.

use std::collections::HashSet;
use std::net::IpAddr;

use crate::config::Mode;

/// Port of plain DNS.
pub const PORT_DNS: u16 = 53;
/// Port of DNS over TLS. Refused when encrypted-DNS bypass is blocked.
pub const PORT_DOT: u16 = 853;
/// Port of QUIC (HTTP/3). Dropped when `blockQuic` is on.
pub const PORT_QUIC: u16 = 443;

/// What to do with one datagram/segment seen on the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Hand the payload to the DNS engine and answer from it.
    HijackDns,
    /// Pass through untouched.
    Forward,
    /// Discard silently (counted).
    Drop(DropReason),
}

/// Why a packet was dropped, so the counters can say which rule fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// UDP/443 while `blockQuic` is on.
    Quic,
    /// TCP/853 while `blockEncryptedDnsBypass` is on.
    EncryptedDns,
    /// A TLS connection whose SNI is on the encrypted-DNS host list.
    EncryptedDnsHost,
    /// A TLS connection or HTTP request whose host the DNS filter blocks.
    DomainBlocked,
}

/// The parts of the runtime configuration the packet path needs.
#[derive(Debug, Clone)]
pub struct Policy {
    pub mode: Mode,
    pub block_quic: bool,
    pub block_encrypted_dns: bool,
    /// Known DoH/DoT hostnames, lowercased.
    pub encrypted_dns_hosts: HashSet<String>,
    /// Idle timeout of a TCP connection in the tunnel (the outbound socket's keepalive budget).
    pub tcp_idle_timeout: std::time::Duration,
    pub udp_idle_timeout: std::time::Duration,
    pub max_udp_flows: usize,
    /// Bytes of a client→server stream buffered to find the SNI/Host before deciding.
    pub sniff_bytes: usize,
    /// How long to wait for those bytes before forwarding anyway.
    pub sniff_timeout: std::time::Duration,
    pub mtu: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: Mode::Full,
            // Both on by default: they are what makes domain-level filtering work at all against a
            // browser that would otherwise use QUIC and encrypted DNS (docs/DESIGN.md decision 4).
            block_quic: true,
            block_encrypted_dns: true,
            encrypted_dns_hosts: HashSet::new(),
            tcp_idle_timeout: std::time::Duration::from_secs(2 * 60 * 60),
            udp_idle_timeout: std::time::Duration::from_secs(60),
            max_udp_flows: 1024,
            sniff_bytes: 4096,
            sniff_timeout: std::time::Duration::from_secs(3),
            mtu: 1500,
        }
    }
}

impl Policy {
    /// Decide what to do with one UDP datagram.
    ///
    /// In `dns_only` mode the tunnel only carries the virtual DNS addresses, so *any* UDP there is a
    /// DNS query and is hijacked; in `full` mode DNS is hijacked to **any** address on port 53, which
    /// is what catches clients that hardcode `8.8.8.8` (task card §3).
    pub fn udp_action(&self, dst: IpAddr, dst_port: u16) -> Action {
        if dst_port == PORT_DNS {
            // Both modes: a query addressed to port 53 is answered by us. In `dns_only` mode the only
            // routed traffic is DNS, so this is the same rule.
            let _ = dst;
            return Action::HijackDns;
        }
        if self.block_quic && dst_port == PORT_QUIC {
            return Action::Drop(DropReason::Quic);
        }
        Action::Forward
    }

    /// Decide what to do with a TCP segment *that opens a connection*.
    ///
    /// Only the SYN needs this: once a connection is accepted the forwarding path is decided by the
    /// connection's own state machine.
    pub fn tcp_connect_action(&self, dst_port: u16) -> Action {
        if self.block_encrypted_dns && dst_port == PORT_DOT {
            return Action::Drop(DropReason::EncryptedDns);
        }
        Action::Forward
    }

    /// A hostname-level judgement applied once the SNI / `Host` header has been read.
    pub fn host_action(&self, host: &str) -> Action {
        if self.block_encrypted_dns && self.is_encrypted_dns_host(host) {
            return Action::Drop(DropReason::EncryptedDnsHost);
        }
        Action::Forward
    }

    /// True when `host` (or a parent domain of it) is a known encrypted-DNS endpoint.
    ///
    /// Subdomain matching matters: `dns.google` is listed, and `dns.google.` / `x.dns.google` must
    /// not slip through.
    pub fn is_encrypted_dns_host(&self, host: &str) -> bool {
        if self.encrypted_dns_hosts.is_empty() {
            return false;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || host.parse::<IpAddr>().is_ok() {
            return false;
        }
        let mut candidate = host.as_str();
        loop {
            if self.encrypted_dns_hosts.contains(candidate) {
                return true;
            }
            match candidate.split_once('.') {
                Some((_, rest)) if !rest.is_empty() => candidate = rest,
                _ => return false,
            }
        }
    }

    /// Parse the `assets/rules/encrypted-dns-hosts.txt` format: one hostname per line, `#` comments.
    pub fn parse_encrypted_dns_hosts(text: &str) -> HashSet<String> {
        let mut out = HashSet::new();
        for line in text.lines() {
            // A `#` starts a comment anywhere on the line, so a hosts-file style
            // `<ip> <name>   # note` row parses too.
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let name = line.split_whitespace().last().unwrap_or(line);
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if name.is_empty() || name.parse::<IpAddr>().is_ok() {
                continue;
            }
            out.insert(name);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn policy() -> Policy {
        Policy {
            encrypted_dns_hosts: Policy::parse_encrypted_dns_hosts(
                "# public encrypted DNS endpoints\ndns.google\ndoh.pub\ncloudflare-dns.com\n",
            ),
            ..Policy::default()
        }
    }

    #[test]
    fn hijacks_dns_to_any_address() {
        let policy = policy();
        // The point of the rule: a client with 8.8.8.8 hardcoded is still filtered.
        for dst in [
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
            IpAddr::V6("2001:4860:4860::8888".parse().unwrap()),
            IpAddr::V4(Ipv4Addr::new(10, 111, 222, 2)),
            IpAddr::V6("fd00:7a73::2".parse().unwrap()),
        ] {
            assert_eq!(policy.udp_action(dst, PORT_DNS), Action::HijackDns);
        }
        // Other ports are not DNS.
        assert_eq!(
            policy.udp_action(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 5353),
            Action::Forward
        );
    }

    #[test]
    fn drops_quic_only_when_asked() {
        let mut policy = policy();
        assert_eq!(
            policy.udp_action(IpAddr::V4(Ipv4Addr::new(142, 250, 74, 4)), PORT_QUIC),
            Action::Drop(DropReason::Quic)
        );
        assert_eq!(
            policy.udp_action(IpAddr::V6(Ipv6Addr::LOCALHOST), PORT_QUIC),
            Action::Drop(DropReason::Quic)
        );
        policy.block_quic = false;
        assert_eq!(
            policy.udp_action(IpAddr::V4(Ipv4Addr::new(142, 250, 74, 4)), PORT_QUIC),
            Action::Forward
        );
    }

    #[test]
    fn drops_dot_and_doh_hosts_only_when_asked() {
        let mut policy = policy();
        assert_eq!(
            policy.tcp_connect_action(PORT_DOT),
            Action::Drop(DropReason::EncryptedDns)
        );
        assert_eq!(policy.host_action("dns.google"), Action::Drop(DropReason::EncryptedDnsHost));
        assert_eq!(
            policy.host_action("x.dns.google"),
            Action::Drop(DropReason::EncryptedDnsHost),
            "a subdomain of a listed endpoint is still that endpoint"
        );
        assert_eq!(policy.host_action("www.baidu.com"), Action::Forward);

        policy.block_encrypted_dns = false;
        assert_eq!(policy.tcp_connect_action(PORT_DOT), Action::Forward);
        assert_eq!(policy.host_action("dns.google"), Action::Forward);
    }

    #[test]
    fn encrypted_dns_list_parsing() {
        let hosts = Policy::parse_encrypted_dns_hosts(
            "\
# comment
dns.google
  1.1.1.1 cloudflare-dns.com   # trailing comment
DOH.PUB.
::1
",
        );
        assert!(hosts.contains("dns.google"));
        assert!(hosts.contains("cloudflare-dns.com"));
        assert!(hosts.contains("doh.pub"), "names are normalised to lowercase without a dot");
        assert!(!hosts.contains("1.1.1.1"), "addresses are not hostnames");
        assert!(!hosts.contains("::1"));
        assert_eq!(hosts.len(), 3);
    }

    #[test]
    fn ip_literals_are_never_hostname_matches() {
        let mut policy = policy();
        policy.encrypted_dns_hosts.insert("8.8.8.8".to_string());
        assert!(!policy.is_encrypted_dns_host("8.8.8.8"));
        assert!(!policy.is_encrypted_dns_host(""));
        assert!(policy.is_encrypted_dns_host("DNS.Google."));
    }
}

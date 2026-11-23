//! Runtime configuration passed from the Kotlin control plane as JSON.
//!
//! The field names here are the single source of truth for the wire format and are
//! documented in `docs/JNI.md`; the Kotlin mirror lives in
//! `app/src/main/java/top/zztweb/zshield/core/NativeConfig.kt`.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// How a blocked name is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockResponse {
    /// Answer `0.0.0.0` / `::` (default, same as AdGuard).
    #[default]
    ZeroIp,
    /// Answer with RCODE 3.
    Nxdomain,
    /// Answer with RCODE 5.
    Refused,
}

/// One upstream DNS server.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UpstreamConfig {
    /// DNS over HTTPS (RFC 8484, POST, HTTP/2).
    Doh {
        url: String,
        /// IP addresses used to reach the DoH host without relying on the (filtered) system resolver.
        #[serde(default)]
        bootstrap: Vec<String>,
    },
    /// Plaintext UDP, for debugging only.
    Udp { address: String },
}

impl UpstreamConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            UpstreamConfig::Doh { url, bootstrap } => {
                if !url.starts_with("https://") {
                    return Err(ConfigError::new(format!(
                        "DoH upstream must use https://, got {url}"
                    )));
                }
                let host = DohEndpoint::parse(url)?.host;
                if bootstrap.is_empty() {
                    // Without a bootstrap address we would have to resolve the DoH host through the
                    // system resolver, which is exactly what this app replaces.
                    return Err(ConfigError::new(format!(
                        "DoH upstream {url} needs at least one bootstrap IP address"
                    )));
                }
                for ip in bootstrap {
                    parse_ip(ip).map_err(|e| {
                        ConfigError::new(format!("DoH upstream {url} bootstrap {ip}: {e}"))
                    })?;
                }
                let _ = host;
                Ok(())
            }
            UpstreamConfig::Udp { address } => {
                parse_socket_addr(address)
                    .map_err(|e| ConfigError::new(format!("UDP upstream {address}: {e}")))?;
                Ok(())
            }
        }
    }
}

/// The parts of a DoH URL we need: host, port, path and the `Host` header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohEndpoint {
    pub authority: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl DohEndpoint {
    pub fn parse(url: &str) -> Result<Self, ConfigError> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| ConfigError::new(format!("not an https URL: {url}")))?;
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(ConfigError::new(format!("missing host in {url}")));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                let port = p
                    .parse::<u16>()
                    .map_err(|_| ConfigError::new(format!("bad port in {url}")))?;
                (h, port)
            }
            None => (authority, 443),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() {
            return Err(ConfigError::new(format!("missing host in {url}")));
        }
        Ok(Self {
            authority: if port == 443 {
                host.to_string()
            } else {
                format!("{host}:{port}")
            },
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }
}

/// Virtual DNS address routed into the tunnel, as a string.
pub const DEFAULT_DNS_V4: &str = "10.111.222.2";
/// Same, IPv6.
pub const DEFAULT_DNS_V6: &str = "fd00:7a73::2";
/// Default budget for one plaintext HTTP request head (M2b).
///
/// 8 KiB holds every real browser request with room to spare (the largest common case is a long
/// cookie set, a few kilobytes) while keeping a hostile client from making the tunnel buffer without
/// bound. Requests above it are relayed unfiltered rather than dropped.
pub const DEFAULT_HTTP_HEAD_BYTES: usize = 8 * 1024;

/// Default TUN MTU. 1500 is the path MTU of the overwhelming majority of mobile and Wi-Fi links, and
/// measurements on the Pixel 5 show no gain from 9000 (see `docs/PERF.md`): the tunnel is not the
/// bottleneck, the radio is.
pub const DEFAULT_MTU: usize = 1500;

/// How much of the network the tunnel carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Route `0.0.0.0/0` and `::/0`: everything goes through the userspace stack, so SNI/Host level
    /// blocking, QUIC dropping and per-connection policy all apply.
    #[default]
    Full,
    /// Route only the two virtual DNS addresses (the M0/M1 behaviour). Kept as the battery-friendly
    /// compatibility mode described in `docs/DESIGN.md` decision 4.
    DnsOnly,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Full => "full",
            Mode::DnsOnly => "dns_only",
        }
    }
}

/// Full engine configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Config {
    /// Upstream resolvers, tried in order. Empty means the default DoH pair.
    pub upstreams: Vec<UpstreamConfig>,
    /// How a blocked name is answered.
    pub block_response: BlockResponse,
    /// Absolute paths of rule files to load (assets already extracted by the app). Kept as the
    /// debugging fallback for when no precompiled artifact is available.
    pub rule_files: Vec<String>,
    /// Directory holding the precompiled artifacts (`dns.bin`, `engine.bin`). When set and the files
    /// load, the core never parses rule text — that is the fast path (fixed decision 6). When
    /// empty or unusable, `rule_files` is parsed instead.
    pub compiled_dir: String,
    /// Virtual DNS address routed into the tunnel (IPv4).
    pub dns_v4: String,
    /// Virtual DNS address routed into the tunnel (IPv6).
    pub dns_v6: String,
    /// Upper bound of cached answers.
    pub cache_max_entries: usize,
    /// Upper bound of a cache entry lifetime, in seconds.
    pub cache_max_ttl_secs: u64,
    /// Per-query upstream timeout, in milliseconds.
    pub query_timeout_ms: u64,
    /// Number of tokio worker threads.
    pub workers: usize,
    /// Tunnel mode: `full` (default) or `dns_only`.
    pub mode: Mode,
    /// TUN MTU. Must match what `VpnService.Builder.setMtu` was given.
    pub mtu: usize,
    /// Drop UDP/443 so browsers fall back from QUIC to TCP/TLS.
    pub block_quic: bool,
    /// Refuse TCP/853 and TLS connections to known public DoH/DoT hosts.
    pub block_encrypted_dns_bypass: bool,
    /// Absolute path of the encrypted-DNS host list (one hostname per line, `#` comments).
    pub encrypted_dns_hosts_file: String,
    /// Idle timeout of a forwarded TCP connection, in seconds.
    pub tcp_idle_timeout_secs: u64,
    /// Idle timeout of a UDP flow, in seconds.
    pub udp_idle_timeout_secs: u64,
    /// Upper bound of live UDP flows.
    pub max_udp_flows: usize,
    /// Bytes of a client stream buffered to find the SNI/`Host` before deciding.
    pub sniff_bytes: usize,
    /// How long to wait for those bytes, in milliseconds.
    pub sniff_timeout_ms: u64,
    /// Whether the network underneath the tunnel can carry IPv6.
    ///
    /// The Kotlin side decides this from the underlying (non-VPN) default network's
    /// [`android.net.LinkProperties`]: a global unicast IPv6 address **and** an IPv6 default route.
    /// When false the tunnel carries no IPv6 at all — no `::/0`, no IPv6 DNS address — so the core
    /// must not hand out AAAA records either, or a client that prefers IPv6 would connect into a
    /// tunnel that cannot reach the address family and never fall back to IPv4 (MYS-2710).
    pub ipv6: bool,
    /// Buffering budget for one plaintext HTTP request head, in bytes (M2b). A head larger than this
    /// is relayed verbatim instead of being filtered, so an endless header stream stays finite.
    pub http_head_bytes: usize,
    /// Whether HTTPS connections from selected applications are decrypted (M3a).
    ///
    /// The Kotlin side folds `CaState.installed` into this flag: decrypting with a CA the device has
    /// not installed produces nothing but handshake failures, so "on but not installed" is off.
    pub https_filtering: bool,
    /// uids of the applications whose HTTPS traffic is decrypted (browser list ∪ user selection).
    pub https_uids: Vec<u32>,
    /// Hostnames that must never be decrypted, plus their subdomains.
    pub https_excluded_hosts: Vec<String>,
    /// Absolute path of the excluded-hosts list, if the app extracted one. The inline
    /// [`Config::https_excluded_hosts`] entries are appended to it.
    pub https_excluded_hosts_file: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            block_response: BlockResponse::ZeroIp,
            rule_files: Vec::new(),
            compiled_dir: String::new(),
            dns_v4: DEFAULT_DNS_V4.to_string(),
            dns_v6: DEFAULT_DNS_V6.to_string(),
            cache_max_entries: 4096,
            cache_max_ttl_secs: 3600,
            query_timeout_ms: 5000,
            workers: 2,
            mode: Mode::Full,
            mtu: DEFAULT_MTU,
            block_quic: true,
            block_encrypted_dns_bypass: true,
            encrypted_dns_hosts_file: String::new(),
            tcp_idle_timeout_secs: 2 * 60 * 60,
            udp_idle_timeout_secs: 60,
            max_udp_flows: 1024,
            sniff_bytes: 4096,
            sniff_timeout_ms: 3000,
            ipv6: true,
            http_head_bytes: DEFAULT_HTTP_HEAD_BYTES,
            https_filtering: false,
            https_uids: Vec::new(),
            https_excluded_hosts: Vec::new(),
            https_excluded_hosts_file: String::new(),
        }
    }
}

/// The upstream pair from `docs/DESIGN.md` §5.
pub fn default_upstreams() -> Vec<UpstreamConfig> {
    vec![
        UpstreamConfig::Doh {
            url: "https://dns.alidns.com/dns-query".to_string(),
            bootstrap: vec!["223.5.5.5".to_string()],
        },
        UpstreamConfig::Doh {
            url: "https://doh.pub/dns-query".to_string(),
            bootstrap: vec!["1.12.12.12".to_string()],
        },
    ]
}

/// A validated configuration, ready to drive an engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedConfig {
    pub upstreams: Vec<UpstreamConfig>,
    pub block_response: BlockResponse,
    pub rule_files: Vec<String>,
    pub compiled_dir: String,
    pub dns_v4: IpAddr,
    pub dns_v6: IpAddr,
    pub cache_max_entries: usize,
    pub cache_max_ttl_secs: u64,
    pub query_timeout_ms: u64,
    pub workers: usize,
    pub mode: Mode,
    pub mtu: usize,
    pub block_quic: bool,
    pub block_encrypted_dns_bypass: bool,
    pub encrypted_dns_hosts_file: String,
    pub tcp_idle_timeout_secs: u64,
    pub udp_idle_timeout_secs: u64,
    pub max_udp_flows: usize,
    pub sniff_bytes: usize,
    pub sniff_timeout_ms: u64,
    /// Whether the underlying network can carry IPv6 (see [`Config::ipv6`]).
    pub ipv6: bool,
    pub http_head_bytes: usize,
    /// Whether HTTPS connections are decrypted (see [`Config::https_filtering`]).
    pub https_filtering: bool,
    /// uids whose HTTPS traffic is decrypted.
    pub https_uids: Vec<u32>,
    /// Hostnames never decrypted, lowercased, file and inline entries merged.
    pub https_excluded_hosts: Vec<String>,
}

impl ValidatedConfig {
    /// The packet-path policy this configuration implies.
    pub fn policy(&self, encrypted_dns_hosts: std::collections::HashSet<String>) -> crate::tun::policy::Policy {
        crate::tun::policy::Policy {
            mode: self.mode,
            block_quic: self.block_quic,
            block_encrypted_dns: self.block_encrypted_dns_bypass,
            encrypted_dns_hosts,
            tcp_idle_timeout: std::time::Duration::from_secs(self.tcp_idle_timeout_secs),
            udp_idle_timeout: std::time::Duration::from_secs(self.udp_idle_timeout_secs),
            max_udp_flows: self.max_udp_flows,
            sniff_bytes: self.sniff_bytes,
            sniff_timeout: std::time::Duration::from_millis(self.sniff_timeout_ms),
            mtu: self.mtu,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(String);

impl ConfigError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn parse_ip(raw: &str) -> Result<IpAddr, ConfigError> {
    raw.trim()
        .parse::<IpAddr>()
        .map_err(|_| ConfigError::new(format!("not an IP address: {raw}")))
}

fn parse_socket_addr(raw: &str) -> Result<std::net::SocketAddr, ConfigError> {
    raw.trim()
        .parse::<std::net::SocketAddr>()
        .map_err(|_| ConfigError::new(format!("not a socket address: {raw}")))
}

impl Config {
    /// Parse and validate a JSON document. `raw` is the `configJson` argument of `Native.start`.
    pub fn from_json(raw: &str) -> Result<ValidatedConfig, ConfigError> {
        let cfg: Config = serde_json::from_str(raw)
            .map_err(|e| ConfigError::new(format!("invalid config JSON: {e}")))?;
        cfg.validate()
    }

    pub fn validate(self) -> Result<ValidatedConfig, ConfigError> {
        let upstreams = if self.upstreams.is_empty() {
            default_upstreams()
        } else {
            self.upstreams
        };
        if upstreams.is_empty() {
            return Err(ConfigError::new("at least one upstream is required"));
        }
        for upstream in &upstreams {
            upstream.validate()?;
        }

        let dns_v4 = parse_ip(&self.dns_v4)
            .map_err(|e| ConfigError::new(format!("dnsV4: {e}")))?;
        let dns_v6 = parse_ip(&self.dns_v6)
            .map_err(|e| ConfigError::new(format!("dnsV6: {e}")))?;
        if !dns_v4.is_ipv4() {
            return Err(ConfigError::new("dnsV4 must be an IPv4 address"));
        }
        if !dns_v6.is_ipv6() {
            return Err(ConfigError::new("dnsV6 must be an IPv6 address"));
        }
        if self.cache_max_entries == 0 {
            return Err(ConfigError::new("cacheMaxEntries must be > 0"));
        }
        if self.cache_max_ttl_secs == 0 {
            return Err(ConfigError::new("cacheMaxTtlSecs must be > 0"));
        }
        if self.query_timeout_ms == 0 {
            return Err(ConfigError::new("queryTimeoutMs must be > 0"));
        }
        // IPv6 requires 1280 bytes and smoltcp caps at 9216 (jumbo frames are pointless on a phone);
        // the device advertises this MTU to TCP peers, so an out-of-range value is a configuration
        // error rather than something to clamp silently.
        if !(1280..=9216).contains(&self.mtu) {
            return Err(ConfigError::new(format!(
                "mtu must be between 1280 and 9216, got {}",
                self.mtu
            )));
        }
        if self.tcp_idle_timeout_secs == 0 {
            return Err(ConfigError::new("tcpIdleTimeoutSecs must be > 0"));
        }
        if self.udp_idle_timeout_secs == 0 {
            return Err(ConfigError::new("udpIdleTimeoutSecs must be > 0"));
        }
        if self.max_udp_flows == 0 {
            return Err(ConfigError::new("maxUdpFlows must be > 0"));
        }
        // The sniffer has to hold a whole ClientHello to read the SNI; anything below a sane
        // handshake size would make TLS filtering silently ineffective.
        if self.sniff_bytes < 512 {
            return Err(ConfigError::new(format!(
                "sniffBytes must be at least 512, got {}",
                self.sniff_bytes
            )));
        }
        if self.sniff_timeout_ms == 0 {
            return Err(ConfigError::new("sniffTimeoutMs must be > 0"));
        }
        // A head budget below the smallest realistic request would silently disable HTTP filtering;
        // one above the ceiling would let a client make the tunnel hold arbitrary memory.
        if !(1024..=crate::http::relay::MAX_HEAD_LIMIT).contains(&self.http_head_bytes) {
            return Err(ConfigError::new(format!(
                "httpHeadBytes must be between 1024 and {}, got {}",
                crate::http::relay::MAX_HEAD_LIMIT,
                self.http_head_bytes
            )));
        }

        Ok(ValidatedConfig {
            upstreams,
            block_response: self.block_response,
            rule_files: self.rule_files,
            compiled_dir: self.compiled_dir,
            dns_v4,
            dns_v6,
            cache_max_entries: self.cache_max_entries,
            cache_max_ttl_secs: self.cache_max_ttl_secs,
            query_timeout_ms: self.query_timeout_ms,
            workers: self.workers.max(1),
            mode: self.mode,
            mtu: self.mtu,
            block_quic: self.block_quic,
            block_encrypted_dns_bypass: self.block_encrypted_dns_bypass,
            encrypted_dns_hosts_file: self.encrypted_dns_hosts_file,
            tcp_idle_timeout_secs: self.tcp_idle_timeout_secs,
            udp_idle_timeout_secs: self.udp_idle_timeout_secs,
            max_udp_flows: self.max_udp_flows,
            sniff_bytes: self.sniff_bytes,
            sniff_timeout_ms: self.sniff_timeout_ms,
            ipv6: self.ipv6,
            http_head_bytes: self.http_head_bytes,
            https_filtering: self.https_filtering,
            https_uids: self.https_uids,
            https_excluded_hosts: merge_excluded_hosts(
                &self.https_excluded_hosts_file,
                &self.https_excluded_hosts,
            ),
        })
    }
}

/// Merge the on-disk exclusion list with the inline entries, one normalised list.
///
/// A missing file is reported and ignored: refusing to start the tunnel because an asset could not be
/// extracted would trade a filtering gap for no filtering at all, which is the worse failure. The
/// inline entries (the user's own exclusions) still apply.
fn merge_excluded_hosts(file: &str, inline: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if !file.trim().is_empty() {
        match std::fs::read_to_string(file) {
            Ok(text) => {
                for host in crate::https::policy::HttpsPolicy::parse_list(&text) {
                    if !out.contains(&host) {
                        out.push(host);
                    }
                }
            }
            Err(err) => {
                crate::log_msg(
                    "warn",
                    &format!("cannot read the HTTPS exclusion list {file}: {err}"),
                );
            }
        }
    }
    for host in crate::https::policy::HttpsPolicy::parse_list(&inline.join("\n")) {
        if !out.contains(&host) {
            out.push(host);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_uses_design_defaults() {
        let cfg = Config::from_json(r#"{"ruleFiles":["/tmp/a.txt"]}"#).expect("valid");
        assert_eq!(cfg.dns_v4.to_string(), "10.111.222.2");
        assert_eq!(cfg.dns_v6.to_string(), "fd00:7a73::2");
        assert_eq!(cfg.block_response, BlockResponse::ZeroIp);
        assert_eq!(cfg.upstreams.len(), 2);
        assert_eq!(cfg.rule_files, vec!["/tmp/a.txt".to_string()]);
        assert_eq!(cfg.cache_max_entries, 4096);
        assert_eq!(cfg.cache_max_ttl_secs, 3600);
        // M2a defaults: full tunnel, QUIC and encrypted-DNS bypass blocked.
        assert_eq!(cfg.mode, Mode::Full);
        assert_eq!(cfg.mtu, 1500);
        assert!(cfg.block_quic);
        assert!(cfg.block_encrypted_dns_bypass);
        assert_eq!(cfg.tcp_idle_timeout_secs, 7200);
        assert_eq!(cfg.udp_idle_timeout_secs, 60);
        assert_eq!(cfg.sniff_bytes, 4096);
        assert_eq!(cfg.sniff_timeout_ms, 3000);
        assert_eq!(cfg.http_head_bytes, DEFAULT_HTTP_HEAD_BYTES);
        // M3a: HTTPS filtering is off unless the control plane turns it on, and no uid is selected.
        assert!(!cfg.https_filtering);
        assert!(cfg.https_uids.is_empty());
        assert!(cfg.https_excluded_hosts.is_empty());
        // IPv6 stays on unless the control plane says the underlying network cannot carry it, so
        // a core built without the field (tests, older configs) keeps the M2a behaviour.
        assert!(cfg.ipv6);
    }

    #[test]
    fn ipv6_flag_is_read_from_the_control_plane() {
        assert!(!Config::from_json(r#"{"ipv6":false}"#).expect("valid").ipv6);
        assert!(Config::from_json(r#"{"ipv6":true}"#).expect("valid").ipv6);
        // Absent means the default, which is on.
        assert!(Config::from_json("{}").expect("valid").ipv6);
    }

    #[test]
    fn modes_round_trip() {
        // `dns_only` keeps the M0/M1 behaviour available; anything else is a configuration error
        // rather than a silent fallback, so a typo cannot leave the user unfiltered.
        let cfg = Config::from_json(r#"{"mode":"dns_only"}"#).expect("valid");
        assert_eq!(cfg.mode, Mode::DnsOnly);
        let cfg = Config::from_json(r#"{"mode":"full"}"#).expect("valid");
        assert_eq!(cfg.mode, Mode::Full);
        let err = Config::from_json(r#"{"mode":"transparent"}"#).expect_err("must fail");
        assert!(err.to_string().contains("invalid config JSON"), "{err}");
    }

    #[test]
    fn policy_mirrors_the_configuration() {
        let cfg = Config::from_json(
            r#"{"mode":"dns_only","blockQuic":false,"blockEncryptedDnsBypass":false,
                "udpIdleTimeoutSecs":30,"maxUdpFlows":64,"sniffBytes":1024,
                "sniffTimeoutMs":500,"mtu":1400}"#,
        )
        .expect("valid");
        let policy = cfg.policy(Default::default());
        assert_eq!(policy.mode, Mode::DnsOnly);
        assert!(!policy.block_quic);
        assert!(!policy.block_encrypted_dns);
        assert_eq!(policy.udp_idle_timeout, std::time::Duration::from_secs(30));
        assert_eq!(policy.max_udp_flows, 64);
        assert_eq!(policy.sniff_bytes, 1024);
        assert_eq!(policy.sniff_timeout, std::time::Duration::from_millis(500));
        assert_eq!(policy.mtu, 1400);
    }

    #[test]
    fn out_of_range_tunnel_settings_are_rejected() {
        let err = Config::from_json(r#"{"mtu":1000}"#).expect_err("must fail");
        assert!(err.to_string().contains("mtu"), "{err}");
        let err = Config::from_json(r#"{"mtu":10000}"#).expect_err("must fail");
        assert!(err.to_string().contains("mtu"), "{err}");
        let err = Config::from_json(r#"{"sniffBytes":10}"#).expect_err("must fail");
        assert!(err.to_string().contains("sniffBytes"), "{err}");
        let err = Config::from_json(r#"{"udpIdleTimeoutSecs":0}"#).expect_err("must fail");
        assert!(err.to_string().contains("udpIdleTimeoutSecs"), "{err}");
        let err = Config::from_json(r#"{"maxUdpFlows":0}"#).expect_err("must fail");
        assert!(err.to_string().contains("maxUdpFlows"), "{err}");
        let err = Config::from_json(r#"{"sniffTimeoutMs":0}"#).expect_err("must fail");
        assert!(err.to_string().contains("sniffTimeoutMs"), "{err}");
        let err = Config::from_json(r#"{"tcpIdleTimeoutSecs":0}"#).expect_err("must fail");
        assert!(err.to_string().contains("tcpIdleTimeoutSecs"), "{err}");
        let err = Config::from_json(r#"{"httpHeadBytes":512}"#).expect_err("must fail");
        assert!(err.to_string().contains("httpHeadBytes"), "{err}");
        let err = Config::from_json(r#"{"httpHeadBytes":1048576}"#).expect_err("must fail");
        assert!(err.to_string().contains("httpHeadBytes"), "{err}");
    }

    #[test]
    fn the_http_head_budget_is_configurable_within_its_limits() {
        // The bounds are inclusive, and both ends have to be accepted: a minimal budget for a
        // memory-constrained run and the ceiling for a debugging session.
        let cfg = Config::from_json(r#"{"httpHeadBytes":1024}"#).expect("valid");
        assert_eq!(cfg.http_head_bytes, 1024);
        let cfg = Config::from_json(r#"{"httpHeadBytes":65536}"#).expect("valid");
        assert_eq!(cfg.http_head_bytes, 65536);
    }

    #[test]
    fn https_settings_reach_the_validated_config() {
        let cfg = Config::from_json(
            r#"{"httpsFiltering":true,"httpsUids":[10123,10456],
                "httpsExcludedHosts":["Bank.Example.","pay.example","bank.example"]}"#,
        )
        .expect("valid");
        assert!(cfg.https_filtering);
        assert_eq!(cfg.https_uids, vec![10123, 10456]);
        assert_eq!(
            cfg.https_excluded_hosts,
            vec!["bank.example".to_string(), "pay.example".to_string()],
            "names are normalised and de-duplicated"
        );
    }

    #[test]
    fn the_exclusion_file_is_merged_with_the_inline_entries() {
        let dir = std::env::temp_dir().join(format!(
            "zshield-https-excluded-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let list = dir.join("excluded.txt");
        std::fs::write(&list, "# asset list\nalipay.com\n10.0.0.1 icbc.com.cn\n").expect("write");

        let json = serde_json::json!({
            "httpsExcludedHostsFile": list.to_string_lossy(),
            "httpsExcludedHosts": ["user.example", "alipay.com"],
        });
        let cfg = Config::from_json(&json.to_string()).expect("valid");
        assert_eq!(
            cfg.https_excluded_hosts,
            vec![
                "alipay.com".to_string(),
                "icbc.com.cn".to_string(),
                "user.example".to_string()
            ],
            "file entries first, then inline, deduplicated"
        );

        // A missing file is not fatal: the inline entries still apply.
        let json = serde_json::json!({
            "httpsExcludedHostsFile": dir.join("nope.txt").to_string_lossy(),
            "httpsExcludedHosts": ["user.example"],
        });
        let cfg = Config::from_json(&json.to_string()).expect("valid");
        assert_eq!(cfg.https_excluded_hosts, vec!["user.example".to_string()]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn full_config_round_trips() {
        let json = r#"{
            "upstreams": [
                {"type":"doh","url":"https://dns.alidns.com/dns-query","bootstrap":["223.5.5.5"]},
                {"type":"udp","address":"1.1.1.1:53"}
            ],
            "blockResponse":"nxdomain",
            "ruleFiles":["/a.txt","/b.txt"],
            "dnsV4":"10.0.0.2",
            "dnsV6":"fd00::2",
            "cacheMaxEntries":128,
            "cacheMaxTtlSecs":60,
            "queryTimeoutMs":1500,
            "workers":3
        }"#;
        let cfg = Config::from_json(json).expect("valid");
        assert_eq!(cfg.block_response, BlockResponse::Nxdomain);
        assert_eq!(cfg.cache_max_entries, 128);
        assert_eq!(cfg.cache_max_ttl_secs, 60);
        assert_eq!(cfg.query_timeout_ms, 1500);
        assert_eq!(cfg.workers, 3);
        assert_eq!(cfg.upstreams.len(), 2);
        assert!(matches!(cfg.upstreams[1], UpstreamConfig::Udp { .. }));
    }

    #[test]
    fn doh_without_bootstrap_is_rejected() {
        let json = r#"{"upstreams":[{"type":"doh","url":"https://dns.alidns.com/dns-query"}]}"#;
        let err = Config::from_json(json).expect_err("must fail");
        assert!(err.to_string().contains("bootstrap"), "{err}");
    }

    #[test]
    fn doh_plaintext_is_rejected() {
        let json = r#"{"upstreams":[{"type":"doh","url":"http://x/dns-query","bootstrap":["1.1.1.1"]}]}"#;
        let err = Config::from_json(json).expect_err("must fail");
        assert!(err.to_string().contains("https"), "{err}");
    }

    #[test]
    fn invalid_virtual_dns_is_rejected() {
        let err = Config::from_json(r#"{"dnsV4":"::1"}"#).expect_err("must fail");
        assert!(err.to_string().contains("dnsV4"), "{err}");
    }

    #[test]
    fn upstream_unknown_type_is_rejected() {
        let err = Config::from_json(r#"{"upstreams":[{"type":"dot","address":"1.1.1.1"}]}"#)
            .expect_err("must fail");
        assert!(err.to_string().contains("invalid config JSON"), "{err}");
    }

    #[test]
    fn doh_endpoint_parsing() {
        let ep = DohEndpoint::parse("https://dns.alidns.com/dns-query").expect("parse");
        assert_eq!(ep.host, "dns.alidns.com");
        assert_eq!(ep.port, 443);
        assert_eq!(ep.path, "/dns-query");
        assert_eq!(ep.authority, "dns.alidns.com");

        let ep = DohEndpoint::parse("https://example.com:8443/q?x=1").expect("parse");
        assert_eq!(ep.port, 8443);
        assert_eq!(ep.path, "/q?x=1");
        assert_eq!(ep.authority, "example.com:8443");

        let ep = DohEndpoint::parse("https://example.com").expect("parse");
        assert_eq!(ep.path, "/");
    }
}

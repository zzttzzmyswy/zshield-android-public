//! The tunnel loop: TUN fd ⇄ userspace stack ⇄ forwarding tasks.
//!
//! # Event sources
//!
//! The loop waits on exactly three things and never polls:
//! 1. the TUN fd becoming readable (registered with the tokio reactor),
//! 2. the stack's own next deadline (`Interface::poll_delay` — retransmits, keepalives, TIME-WAIT),
//!    which is `None` when no connection needs anything,
//! 3. a nudge from a forwarding task that just wrote bytes or finished.
//!
//! With no traffic and no connections the loop parks on the fd forever, so an idle tunnel costs no
//! wakeups at all. That is `docs/DESIGN.md` decision 10 taken literally, and it is why the DNS
//! cache's old 60 s housekeeping timer is gone: expired entries are now dropped lazily on the query
//! path (`dns::engine::Engine::handle`).
//!
//! # Packet handling
//!
//! Every ingress packet is classified *before* smoltcp sees it:
//! - UDP/53 to **any** address → the DNS engine, never the network. This is what catches a client
//!   that hardcodes `8.8.8.8` (task card §3).
//! - UDP/443 with `blockQuic` → dropped, which forces the browser back onto TCP/TLS.
//! - a SYN to a port the policy refuses (TCP/853) → no listening socket is prepared, so the stack
//!   answers with a RST. A blocked *host* cannot be known from the SYN and is handled after the
//!   handshake by the forwarding task (see `tun::forward`).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, Notify};

use crate::dns::engine::Engine;
use crate::dns::wire::Message;
use crate::http::log::RequestLog;
use crate::http::relay::HttpContext;
use crate::tun::forward::{
    record_connection_block, ForwardContext, ForwardStats, UdpForwarder, MAX_CONNECTIONS,
};
use crate::tun::nat::UdpFlowKey;
use crate::tun::packet::{self, IPPROTO_TCP, IPPROTO_UDP};
use crate::tun::policy::{Action, Policy, PORT_DNS};
use crate::tun::stack::{
    read_packet, set_nonblocking, write_packet, ReadResult, ReadyConnection, TunnelStack,
    MAX_PACKET,
};
pub use crate::tun::stack::{own_fd, StopFlag};

/// Number of DNS queries being processed at once. Keeps memory bounded under a flood.
const MAX_IN_FLIGHT: usize = 64;
/// Cap of finished DNS replies waiting to be written. A full channel drops the newest reply, which
/// is the right back-pressure for DNS: the client retries.
const REPLY_QUEUE: usize = 256;

/// Counters for the tunnel layer itself (packets in/out/dropped), separate from the DNS and
/// forwarding counters.
#[derive(Debug, Default)]
pub struct TunStats {
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,
    pub dropped: AtomicU64,
}

impl TunStats {
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.packets_in.load(Ordering::Relaxed),
            self.packets_out.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
    }
}

/// The two optional filtering pipelines, behind one lock each so a compile that lands *after* the
/// tunnel started can install them without rebuilding the interface (MYS-2716).
///
/// Before this existed the two were plain `Option`s captured by [`run`], which is why a tunnel
/// started before the first compile never picked the engine up: there was nowhere to put it. A
/// forwarding task takes a clone of the `Arc` it needs for one connection, so a swap can never make
/// one connection be judged by two rule sets.
#[derive(Default)]
pub struct PipelineSlots {
    http: std::sync::RwLock<Option<HttpContext>>,
    https: std::sync::RwLock<Option<Arc<crate::tun::forward::HttpsPipeline>>>,
}

impl PipelineSlots {
    /// Slots seeded with the pipelines `start` managed to build.
    pub fn new(
        http: Option<HttpContext>,
        https: Option<Arc<crate::tun::forward::HttpsPipeline>>,
    ) -> Self {
        Self {
            http: std::sync::RwLock::new(http),
            https: std::sync::RwLock::new(https),
        }
    }

    /// The plaintext-HTTP context in force, if an engine is loaded.
    pub fn http(&self) -> Option<HttpContext> {
        self.http.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The HTTPS pipeline in force, if one could be built.
    pub fn https(&self) -> Option<Arc<crate::tun::forward::HttpsPipeline>> {
        self.https
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Install a plaintext-HTTP context (the engine artifact appeared after the tunnel started).
    pub fn install_http(&self, context: HttpContext) {
        *self.http.write().unwrap_or_else(|e| e.into_inner()) = Some(context);
    }

    /// Install an HTTPS pipeline built after the tunnel started.
    pub fn install_https(&self, pipeline: Arc<crate::tun::forward::HttpsPipeline>) {
        *self.https.write().unwrap_or_else(|e| e.into_inner()) = Some(pipeline);
    }

    /// Whether a plaintext-HTTP engine is loaded (`statsJson`'s `httpEngineLoaded`).
    pub fn has_http(&self) -> bool {
        self.http
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Whether HTTPS connections are being decrypted (`statsJson`'s `httpsFiltering`).
    pub fn has_https(&self) -> bool {
        self.https
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }
}

impl std::fmt::Debug for PipelineSlots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipelineSlots")
            .field("http", &self.has_http())
            .field("https", &self.has_https())
            .finish()
    }
}

/// Everything the loop needs, bundled so the signature stays readable.
pub struct TunnelConfig {
    pub engine: Arc<Engine>,
    pub policy: Arc<Policy>,
    pub stop: Arc<StopFlag>,
    pub tun_stats: Arc<TunStats>,
    pub forward_stats: Arc<ForwardStats>,
    /// The optional filtering pipelines (M2b plaintext, M3a HTTPS). Empty at start when the compiled
    /// artifacts did not exist yet; `Native.reload` fills them in when the first compile lands.
    pub pipelines: Arc<PipelineSlots>,
    /// The owner lookup the HTTPS decision needs. On Android it is a JNI callback into
    /// `ConnectivityManager`; everywhere else it is a no-op that reports "unknown", which makes every
    /// 443 connection pass through.
    pub owner_lookup: Arc<dyn crate::https::policy::OwnerLookup>,
    /// The unified request log (MYS-2742 §修复②): DNS queries, connection-level blocks and HTTP
    /// requests all land in it, so the log and `statsJson`'s blocked counters tell one story.
    pub log: Arc<RequestLog>,
}

/// Run the tunnel until `stop` is requested or the fd is closed.
pub async fn run(fd: std::os::fd::OwnedFd, config: TunnelConfig) {
    let TunnelConfig {
        engine,
        policy,
        stop,
        tun_stats,
        forward_stats,
        pipelines,
        owner_lookup,
        log,
    } = config;

    let raw_fd = fd.as_raw_fd();
    // SAFETY: the OwnedFd is moved into the AsyncFd and stays open for its whole lifetime, so
    // `as_raw_fd` keeps returning the same descriptor.
    let async_fd = match unsafe { AsyncFd::register(fd) } {
        Ok(async_fd) => async_fd,
        Err(err) => {
            let (_fd, cause) = err.into_parts();
            crate::log_msg("error", &format!("cannot register tun fd: {cause}"));
            return;
        }
    };
    // VpnService establishes the fd in blocking mode; the loop drives it through readiness.
    if let Err(err) = set_nonblocking(raw_fd) {
        crate::log_msg("warn", &format!("cannot set O_NONBLOCK on tun fd: {err}"));
    }

    let notify = Arc::new(Notify::new());
    let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<u8>>(1024);
    let mut stack = match TunnelStack::new(
        egress_tx.clone(),
        notify.clone(),
        forward_stats.clone(),
        policy.mtu,
        MAX_CONNECTIONS,
    ) {
        Ok(stack) => stack,
        Err(err) => {
            crate::log_msg("error", &format!("cannot start the tcp/ip stack: {err}"));
            return;
        }
    };
    crate::log_msg(
        "info",
        &format!("tunnel stack up: mode {:?}, mtu {}", policy.mode, policy.mtu),
    );

    let mut forwarder = UdpForwarder::new(policy.clone(), forward_stats.clone(), egress_tx);
    let (dns_tx, mut dns_rx) = mpsc::channel::<Vec<u8>>(REPLY_QUEUE);
    let in_flight = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
    let mut read_buf = vec![0u8; MAX_PACKET];

    loop {
        if stop.is_set() {
            break;
        }

        // The stack's own next deadline: `None` when nothing is scheduled, in which case the loop
        // waits on the fd/nudge arms alone.
        let stack_delay = stack.poll_delay();

        tokio::select! {
            biased;
            _ = stop.wait() => break,

            // A forwarding task wrote bytes or a socket changed state: move them now.
            _ = notify.notified() => {
                stack.poll();
            }

            readable = async_fd.readable() => {
                let mut guard = match readable {
                    Ok(guard) => guard,
                    Err(err) => {
                        crate::log_msg("error", &format!("tun wait failed: {err}"));
                        break;
                    }
                };
                // `try_io` only clears the readiness flag when the closure returns `WouldBlock`, so
                // the `WouldBlock` is propagated rather than swallowed — otherwise the reactor would
                // keep reporting the fd as readable and the loop would spin.
                let result = guard.try_io(|inner| {
                    let fd = inner.get_ref().as_raw_fd();
                    match read_packet(fd, &mut read_buf) {
                        ReadResult::Packet(len) => Ok(Some(len)),
                        ReadResult::WouldBlock => Err(io::ErrorKind::WouldBlock.into()),
                        // A gone device ends the loop anyway, so the flag does not matter here.
                        ReadResult::Closed(err) => Err(err),
                    }
                });
                match result {
                    Ok(Ok(Some(len))) => {
                        tun_stats.packets_in.fetch_add(1, Ordering::Relaxed);
                        let packet = read_buf[..len].to_vec();
                        handle_ingress(
                            packet,
                            &mut stack,
                            &engine,
                            &policy,
                            &mut forwarder,
                            &tun_stats,
                            &forward_stats,
                            &log,
                            &in_flight,
                            &dns_tx,
                        )
                        .await;
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(err)) => {
                        crate::log_msg("info", &format!("tun device closed: {err}"));
                        break;
                    }
                    // Readiness was stale (the queue was already drained): the guard has cleared the
                    // flag, so just wait again.
                    Err(_would_block) => {}
                }
            }

            packet = egress_rx.recv() => {
                let Some(packet) = packet else { break };
                write_out(raw_fd, &packet, &tun_stats);
            }

            reply = dns_rx.recv() => {
                let Some(reply) = reply else { break };
                write_out(raw_fd, &reply, &tun_stats);
            }

            _ = wait_stack_delay(stack_delay) => {
                stack.poll();
            }
        }

        for ready in stack.take_ready() {
            dispatch_connection(
                ready,
                &engine,
                &policy,
                &forward_stats,
                &pipelines,
                &owner_lookup,
                &log,
                &notify,
            );
        }
    }

    forwarder.clear();
    stop.request();
    crate::log_msg("info", "tunnel loop stopped");
}

/// `select!` arm that never completes when the stack has no deadline, so an idle stack parks.
async fn wait_stack_delay(delay: Option<smoltcp::time::Duration>) {
    match delay {
        Some(delay) => {
            let millis = delay.total_millis().max(1);
            tokio::time::sleep(std::time::Duration::from_millis(millis)).await
        }
        None => std::future::pending().await,
    }
}

fn write_out(fd: std::os::fd::RawFd, packet: &[u8], tun_stats: &Arc<TunStats>) {
    match write_packet(fd, packet) {
        Ok(true) => {
            tun_stats.packets_out.fetch_add(1, Ordering::Relaxed);
        }
        Ok(false) | Err(_) => {
            tun_stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Classify and dispatch one ingress packet.
#[allow(clippy::too_many_arguments)]
async fn handle_ingress(
    packet_buf: Vec<u8>,
    stack: &mut TunnelStack,
    engine: &Arc<Engine>,
    policy: &Arc<Policy>,
    forwarder: &mut UdpForwarder,
    tun_stats: &Arc<TunStats>,
    forward_stats: &Arc<ForwardStats>,
    log: &Arc<RequestLog>,
    in_flight: &Arc<tokio::sync::Semaphore>,
    dns_replies: &mpsc::Sender<Vec<u8>>,
) {
    let Some(packet) = packet::parse(&packet_buf) else {
        // Fragments, IPv4 options, extension headers, ICMP: nothing this tunnel handles.
        tun_stats.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    };

    match packet.protocol {
        IPPROTO_UDP => {
            let Some(datagram) = packet::parse_udp(packet.payload) else {
                tun_stats.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            };
            match policy.udp_action(packet.dst, datagram.dst_port) {
                Action::HijackDns => {
                    forward_stats.dns_hijacked.fetch_add(1, Ordering::Relaxed);
                    hijack_dns(
                        packet.src,
                        packet.dst,
                        datagram.src_port,
                        datagram.payload,
                        engine,
                        in_flight,
                        dns_replies,
                        tun_stats,
                    );
                }
                Action::Drop(reason) => {
                    // QUIC is the one drop that arrives as a datagram stream, so the log (and the
                    // counter, see `record_connection_block`) deduplicates per destination: the
                    // `host` here is the tuple, which is the only identity a UDP datagram has.
                    record_connection_block(
                        forward_stats,
                        Some(log),
                        &format!("{}:{}", packet.dst, datagram.dst_port),
                        reason,
                    );
                }
                Action::Forward => {
                    // A datagram arriving is also the moment to expire idle UDP flows: no timer is
                    // needed, and an idle tunnel has no traffic to expire.
                    let expired = forwarder.reap();
                    if expired > 0 {
                        crate::log_msg("debug", &format!("udp nat: closed {expired} idle flows"));
                    }
                    let key = UdpFlowKey::new(
                        SocketAddr::new(packet.src, datagram.src_port),
                        SocketAddr::new(packet.dst, datagram.dst_port),
                    );
                    match forwarder.send(key, datagram.payload).await {
                        Ok(true) => {}
                        Ok(false) => {
                            tun_stats.dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(err) => {
                            crate::log_msg("debug", &format!("udp flow {key:?} failed: {err}"));
                            forwarder.close(&key);
                            tun_stats.dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
        IPPROTO_TCP => {
            let Some(head) = packet::parse_tcp(packet.payload) else {
                tun_stats.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            };
            if head.syn && !head.ack_flag {
                if let Action::Drop(reason) = policy.tcp_connect_action(head.dst_port) {
                    // No listening socket is prepared, so smoltcp answers the SYN with a RST — the
                    // same thing the kernel does for a closed port.
                    record_connection_block(
                        forward_stats,
                        Some(log),
                        &format!("{}:{}", packet.dst, head.dst_port),
                        reason,
                    );
                    return;
                }
                stack.ensure_listener(head.dst_port);
            }
            if !stack.push_ingress(packet_buf) {
                tun_stats.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            stack.poll();
        }
        _ => {
            tun_stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Answer one DNS query from the engine and write the reply back to the tunnel.
#[allow(clippy::too_many_arguments)]
fn hijack_dns(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    query: &[u8],
    engine: &Arc<Engine>,
    in_flight: &Arc<tokio::sync::Semaphore>,
    dns_replies: &mpsc::Sender<Vec<u8>>,
    tun_stats: &Arc<TunStats>,
) {
    if !looks_like_query(query) {
        tun_stats.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let Ok(permit) = in_flight.clone().try_acquire_owned() else {
        tun_stats.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let request = query.to_vec();
    let engine = engine.clone();
    let replies = dns_replies.clone();
    let stats = tun_stats.clone();
    tokio::spawn(async move {
        let _permit = permit;
        let (reply, outcome) = engine.handle(&request).await;
        if reply.is_empty() {
            crate::log_msg("debug", &format!("dns query failed: {outcome:?}"));
            stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        match packet::build_udp(dst_ip, src_ip, PORT_DNS, src_port, &reply) {
            Ok(packet) => {
                if replies.try_send(packet).is_err() {
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(err) => {
                crate::log_msg("warn", &format!("cannot build dns reply: {err}"));
                stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
}

/// A cheap sanity check before doing any parsing work.
fn looks_like_query(payload: &[u8]) -> bool {
    if payload.len() < 12 {
        return false;
    }
    let Ok(message) = Message::parse(payload) else {
        return false;
    };
    // QR=0 means query; a client sending us a response would be nonsense.
    message.flags & 0x8000 == 0 && message.question().is_some()
}

/// Spawn the forwarding task for one accepted connection.
#[allow(clippy::too_many_arguments)]
fn dispatch_connection(
    ready: ReadyConnection,
    engine: &Arc<Engine>,
    policy: &Arc<Policy>,
    stats: &Arc<ForwardStats>,
    pipelines: &Arc<PipelineSlots>,
    owner_lookup: &Arc<dyn crate::https::policy::OwnerLookup>,
    log: &Arc<RequestLog>,
    notify: &Arc<Notify>,
) {
    let ReadyConnection {
        mut stream,
        client,
        target,
    } = ready;

    // DNS over TCP (RFC 1035 §4.2.2) goes to the engine too: a client that fell back to TCP after a
    // truncated UDP answer must get exactly the same filtering.
    if target.port() == PORT_DNS {
        crate::log_msg("debug", &format!("tcp dns from {client} to {target}"));
        let engine = engine.clone();
        let notify = notify.clone();
        tokio::spawn(async move {
            if crate::tun::forward::serve_tcp_dns(&mut stream, engine).await.is_ok() {
                stream.finish();
            }
            notify.notify_one();
        });
        return;
    }

    // One snapshot of each pipeline per connection, taken here rather than at tunnel start: a
    // compile that lands while the tunnel runs installs its engine into the slot, and the next
    // connection uses it. A connection already in flight keeps the snapshot it started with.
    let ctx = ForwardContext {
        filter: engine.filter(),
        policy: policy.clone(),
        stats: stats.clone(),
        log: Some(log.clone()),
        http: pipelines.http(),
        https: pipelines.https(),
        client_addr: client,
        target_port: target.port(),
        remote: target,
        owner_lookup: owner_lookup.clone(),
    };
    let notify = notify.clone();
    tokio::spawn(async move {
        forward_owned(stream, client, target, &ctx).await;
        notify.notify_one();
    });
}

/// Connect the outbound leg, then relay. Split from `forward::relay_stream` only so the accounting
/// and the clean-finish bookkeeping live next to the task that owns the stream.
async fn forward_owned(
    mut stream: crate::tun::stack::TunnelStream,
    client: SocketAddr,
    target: SocketAddr,
    ctx: &ForwardContext,
) {
    use std::sync::atomic::Ordering::Relaxed;
    ctx.stats.tcp_total.fetch_add(1, Relaxed);
    if let Action::Drop(reason) = ctx.policy.tcp_connect_action(target.port()) {
        // Reached only when the policy changed between the SYN and the accept; the SYN path above is
        // the one that normally refuses port 853. Logged here too so a counted block always has a
        // line (the ledger between the log and the counters).
        record_connection_block(
            &ctx.stats,
            ctx.log.as_deref(),
            &format!("{}:{}", target.ip(), target.port()),
            reason,
        );
        stream.abort();
        return;
    }
    let outbound = match crate::tun::forward::connect_outbound(target).await {
        Ok(outbound) => outbound,
        Err(err) => {
            crate::log_msg("debug", &format!("connect {client} -> {target} failed: {err}"));
            stream.abort();
            return;
        }
    };
    ctx.stats.tcp_active.fetch_add(1, Relaxed);
    let clean = crate::tun::forward::relay_stream(&mut stream, outbound, ctx).await;
    ctx.stats.tcp_active.fetch_sub(1, Relaxed);
    let _ = clean;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_sanity_check() {
        let mut query = vec![0u8; 12];
        query[2] = 0x01; // RD set, QR clear
        query[5] = 1; // one question, but the body is missing -> not a usable query
        assert!(!looks_like_query(&query));

        let mut response = vec![0u8; 12];
        response[2] = 0x81; // QR set
        assert!(!looks_like_query(&response));

        assert!(!looks_like_query(&[0u8; 4]));
    }

    #[test]
    fn tun_stats_snapshot() {
        let stats = TunStats::default();
        stats.packets_in.fetch_add(2, Ordering::Relaxed);
        stats.dropped.fetch_add(1, Ordering::Relaxed);
        assert_eq!(stats.snapshot(), (2, 0, 1));
    }
}

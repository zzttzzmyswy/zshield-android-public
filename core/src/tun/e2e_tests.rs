//! End-to-end test of the tunnel data path, with a fake TUN and a real loopback server.
//!
//! The fake TUN is a UNIX `socketpair` standing in for the TUN file descriptor: the test plays "the
//! kernel" (it writes the client's packets into the pair and reads the tunnel's replies out of it)
//! while the code under test sees an ordinary file descriptor. The whole path therefore runs for
//! real — packet parsing, smoltcp's handshake and state machine, the ring buffers, the forwarding
//! task, and a real TCP socket on `127.0.0.1` — with no privileges and no device.
//!
//! This is the "at least one end-to-end test" the task card asks for: three-way handshake,
//! bidirectional data, and a FIN close, against a test server on loopback.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::dns::filter::Filter;
use crate::tun::forward::{connect_outbound, relay_stream, ForwardContext, ForwardStats};
use crate::tun::packet::{self, IPPROTO_TCP, TCP_MIN_HEADER};
use crate::tun::policy::Policy;
use crate::tun::stack::{set_nonblocking, write_packet, ReadyConnection, TunnelStack};

/// The client's address on the fake tunnel: what the stack sees as the packet source.
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 111, 222, 1);
const CLIENT_PORT: u16 = 40000;

/// The endpoints the tests use for the addresses the HTTPS decision would need. The HTTPS suite
/// builds its own context; these only have to be present and consistent.
const CLIENT_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(CLIENT_IP), CLIENT_PORT);
const TARGET_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const FIN: u8 = 0x01;

#[test]
fn tunnel_carries_a_full_tcp_conversation_between_a_client_and_a_server() {
    // A real echo server on loopback, exactly as the card asks ("对端是本机回环上的测试服务器").
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
    let server_addr = listener.local_addr().expect("addr");
    let server_done = Arc::new(AtomicBool::new(false));
    let server_thread = {
        let server_done = server_done.clone();
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            let mut buffer = [0u8; 1024];
            let mut received = Vec::new();
            loop {
                match socket.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        received.extend_from_slice(&buffer[..n]);
                        // Echo, so the test sees data flowing in both directions.
                        if socket.write_all(&buffer[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = socket.flush();
            server_done.store(true, Ordering::SeqCst);
            received
        })
    };

    let mut harness = Harness::new();
    let client = SocketAddr::new(IpAddr::V4(CLIENT_IP), CLIENT_PORT);
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_addr.port());
    let client_isn = 1000u32;

    // ---- 1. three-way handshake --------------------------------------------------------------
    harness.stack.ensure_listener(target.port());
    harness.send(tcp_packet(client, target, client_isn, 0, SYN, &[]));
    let syn_ack = harness.expect_from_server(target.port(), client.port(), "SYN-ACK");
    assert_eq!(syn_ack.flags & (SYN | ACK), SYN | ACK);
    assert_eq!(
        syn_ack.ack,
        client_isn.wrapping_add(1),
        "the stack must acknowledge the client's SYN"
    );
    let server_isn = syn_ack.seq;

    harness.send(tcp_packet(
        client,
        target,
        client_isn.wrapping_add(1),
        server_isn.wrapping_add(1),
        ACK,
        &[],
    ));
    let ready = harness.stack.take_ready();
    assert_eq!(ready.len(), 1, "the handshake must yield exactly one connection");
    let ReadyConnection {
        mut stream,
        client: connection_client,
        target: connection_target,
    } = ready.into_iter().next().expect("one connection");
    assert_eq!(connection_client, client);
    assert_eq!(connection_target, target);

    // ---- 2. bidirectional data ----------------------------------------------------------------
    let ctx = ForwardContext {
        filter: Arc::new(Filter::new()),
        policy: Arc::new(Policy::default()),
        stats: harness.stats.clone(),
        log: None,
        http: None,
        // HTTPS filtering is off in these tests: the MITM path has its own suite in
        // `crate::https::mitm::e2e_tests`, and a tunnel test that also decrypted would make a
        // failure ambiguous between the two layers.
        https: None,
        client_addr: CLIENT_ADDR,
        target_port: 443,
        remote: TARGET_ADDR,
        owner_lookup: Arc::new(crate::https::policy::NoOwnerLookup),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let relay = runtime.spawn(async move {
        let outbound = connect_outbound(target).await.expect("outbound connect");
        let clean = relay_stream(&mut stream, outbound, &ctx).await;
        if clean {
            stream.finish();
        }
    });

    let request = b"hello tunnel";
    let client_seq = client_isn.wrapping_add(1);
    harness.send(tcp_packet(
        client,
        target,
        client_seq,
        server_isn.wrapping_add(1),
        ACK,
        request,
    ));

    let mut echoed = Vec::new();
    let mut server_ack = server_isn.wrapping_add(1);
    let deadline = Instant::now() + Duration::from_secs(10);
    while echoed.len() < request.len() && Instant::now() < deadline {
        let Some(frame) = harness.next_packet() else {
            continue;
        };
        if frame.src_port != target.port() || frame.payload.is_empty() {
            continue;
        }
        server_ack = frame.seq.wrapping_add(frame.payload.len() as u32);
        echoed.extend_from_slice(&frame.payload);
        // Acknowledge what arrived, otherwise the stack's window stalls.
        harness.send(tcp_packet(
            client,
            target,
            client_seq.wrapping_add(request.len() as u32),
            server_ack,
            ACK,
            &[],
        ));
    }
    assert_eq!(
        echoed, request,
        "the echo server's reply must arrive back through the tunnel"
    );

    // ---- 3. FIN close -------------------------------------------------------------------------
    harness.send(tcp_packet(
        client,
        target,
        client_seq.wrapping_add(request.len() as u32),
        server_ack,
        ACK | FIN,
        &[],
    ));

    // The client's FIN reaches the server, which closes; the tunnel then emits its own FIN.
    let mut saw_fin = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !saw_fin && Instant::now() < deadline {
        if let Some(frame) = harness.next_packet() {
            if frame.src_port == target.port() && frame.flags & FIN != 0 {
                saw_fin = true;
            }
        }
    }
    assert!(saw_fin, "the tunnel must close its half once the server is done");
    assert!(
        server_done.load(Ordering::SeqCst),
        "the server must have seen the connection close"
    );

    relay.abort();
    let received = server_thread.join().expect("server thread");
    assert_eq!(
        received, request,
        "the server must have received exactly the bytes the client sent"
    );
}

/// Server-first protocols (SMTP, FTP, POP3, plain IMAP): the client sends nothing until it sees the
/// server's greeting, so the sniff phase must not hold that greeting back until its deadline.
#[test]
fn a_server_first_greeting_is_not_delayed_by_the_sniff_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
    let server_addr = listener.local_addr().expect("addr");
    let greeting: &[u8] = b"220 smtp.example ESMTP ready\r\n";
    let server_thread = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        socket.write_all(greeting).expect("greeting");
        // Keep the connection open long enough for the assertion below.
        std::thread::sleep(Duration::from_secs(2));
    });

    let mut harness = Harness::new();
    let client = SocketAddr::new(IpAddr::V4(CLIENT_IP), CLIENT_PORT + 1);
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_addr.port());
    let client_isn = 5000u32;

    harness.stack.ensure_listener(target.port());
    harness.send(tcp_packet(client, target, client_isn, 0, SYN, &[]));
    let syn_ack = harness.expect_from_server(target.port(), client.port(), "SYN-ACK");
    let server_isn = syn_ack.seq;
    harness.send(tcp_packet(
        client,
        target,
        client_isn.wrapping_add(1),
        server_isn.wrapping_add(1),
        ACK,
        &[],
    ));
    let ReadyConnection { mut stream, .. } =
        harness.stack.take_ready().into_iter().next().expect("one connection");

    let policy = Policy::default();
    let sniff_timeout = policy.sniff_timeout;
    assert!(sniff_timeout >= Duration::from_secs(2), "test assumes a multi-second sniff timeout");
    let ctx = ForwardContext {
        filter: Arc::new(Filter::new()),
        policy: Arc::new(policy),
        stats: harness.stats.clone(),
        log: None,
        http: None,
        https: None,
        client_addr: CLIENT_ADDR,
        target_port: 443,
        remote: TARGET_ADDR,
        owner_lookup: Arc::new(crate::https::policy::NoOwnerLookup),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let started = Instant::now();
    let relay = runtime.spawn(async move {
        let outbound = connect_outbound(target).await.expect("outbound connect");
        relay_stream(&mut stream, outbound, &ctx).await;
    });

    // The client says nothing; the greeting must still come through promptly.
    let mut received = Vec::new();
    let deadline = Instant::now() + sniff_timeout;
    while received.len() < greeting.len() && Instant::now() < deadline {
        let Some(frame) = harness.next_packet() else {
            continue;
        };
        if frame.src_port != target.port() || frame.payload.is_empty() {
            continue;
        }
        received.extend_from_slice(&frame.payload);
        harness.send(tcp_packet(
            client,
            target,
            client_isn.wrapping_add(1),
            frame.seq.wrapping_add(frame.payload.len() as u32),
            ACK,
            &[],
        ));
    }
    let elapsed = started.elapsed();
    assert_eq!(received, greeting, "the server greeting must reach the client");
    assert!(
        elapsed < sniff_timeout / 2,
        "greeting took {elapsed:?}; it must not wait for the {sniff_timeout:?} sniff deadline"
    );

    relay.abort();
    server_thread.join().expect("server thread");
}

/// The same property with the M2b HTTP pipeline wired in (`http: Some(..)`).
///
/// The two M2a regression cases both run with `http: None`, so neither covers the path M2b added:
/// when the sniff phase gives up because the server spoke first, `relay_stream` must forward the
/// greeting immediately rather than hand the connection to the request-parsing relay, which would
/// wait for bytes that never come.
#[test]
fn a_server_first_greeting_is_not_delayed_when_http_filtering_is_on() {
    use crate::http::decision::HttpFilter;
    use crate::http::log::RequestLog;
    use crate::http::relay::{HttpContext, HttpStats};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
    let server_addr = listener.local_addr().expect("addr");
    let greeting: &[u8] = b"220 smtp.example ESMTP ready\r\n";
    let server_thread = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        socket.write_all(greeting).expect("greeting");
        std::thread::sleep(Duration::from_secs(2));
    });

    let mut harness = Harness::new();
    let client = SocketAddr::new(IpAddr::V4(CLIENT_IP), CLIENT_PORT + 3);
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_addr.port());
    let client_isn = 7000u32;

    harness.stack.ensure_listener(target.port());
    harness.send(tcp_packet(client, target, client_isn, 0, SYN, &[]));
    let syn_ack = harness.expect_from_server(target.port(), client.port(), "SYN-ACK");
    let server_isn = syn_ack.seq;
    harness.send(tcp_packet(
        client,
        target,
        client_isn.wrapping_add(1),
        server_isn.wrapping_add(1),
        ACK,
        &[],
    ));
    let ReadyConnection { mut stream, .. } =
        harness.stack.take_ready().into_iter().next().expect("one connection");

    // An engine that would block anything it is asked about, so a mis-routed greeting would be
    // visible as a synthesized response rather than as the server's own bytes.
    let mut set = adblock::lists::FilterSet::new(true);
    set.add_filter_list(
        "||example.com^".to_string(),
        adblock::lists::ParseOptions::default(),
    );
    let http_stats = Arc::new(HttpStats::default());
    let http = HttpContext {
        cosmetic: Arc::new(crate::cosmetic::CosmeticStats::default()),
        framing: crate::cosmetic::OutFraming::Chunked,
        filter: Arc::new(HttpFilter::new(adblock::Engine::new_with_filter_set(set))),
        log: Arc::new(RequestLog::new()),
        stats: http_stats.clone(),
        head_limit: 8 * 1024,
        scheme: crate::http::head::Scheme::Http,
        modifiers: None,
    };
    let policy = Policy::default();
    let sniff_timeout = policy.sniff_timeout;
    let ctx = ForwardContext {
        filter: Arc::new(Filter::new()),
        policy: Arc::new(policy),
        stats: harness.stats.clone(),
        log: None,
        http: Some(http),
        https: None,
        client_addr: CLIENT_ADDR,
        target_port: 443,
        remote: TARGET_ADDR,
        owner_lookup: Arc::new(crate::https::policy::NoOwnerLookup),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let started = Instant::now();
    let relay = runtime.spawn(async move {
        let outbound = connect_outbound(target).await.expect("outbound connect");
        relay_stream(&mut stream, outbound, &ctx).await;
    });

    let mut received = Vec::new();
    let deadline = Instant::now() + sniff_timeout;
    while received.len() < greeting.len() && Instant::now() < deadline {
        let Some(frame) = harness.next_packet() else {
            continue;
        };
        if frame.src_port != target.port() || frame.payload.is_empty() {
            continue;
        }
        received.extend_from_slice(&frame.payload);
        harness.send(tcp_packet(
            client,
            target,
            client_isn.wrapping_add(1),
            frame.seq.wrapping_add(frame.payload.len() as u32),
            ACK,
            &[],
        ));
    }
    let elapsed = started.elapsed();
    assert_eq!(
        received, greeting,
        "the greeting must arrive byte for byte, not as a synthesized response"
    );
    assert!(
        elapsed < sniff_timeout / 2,
        "with HTTP filtering on, the greeting took {elapsed:?}; it must not wait for the          {sniff_timeout:?} sniff deadline"
    );
    assert_eq!(
        http_stats.snapshot().requests,
        0,
        "a server-first protocol must never be parsed as an HTTP request"
    );

    relay.abort();
    server_thread.join().expect("server thread");
}

/// A connection is promoted while still SynReceived; a poll between the SYN and the client's ACK
/// must not latch "client closed". Otherwise the relay sees EOF as soon as its receive buffer runs
/// dry, and every client segment after the first is lost.
#[test]
fn client_data_after_a_pause_still_reaches_the_server() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
    let server_addr = listener.local_addr().expect("addr");
    let server_thread = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        socket.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
        let mut buffer = [0u8; 1024];
        let mut received = Vec::new();
        while let Ok(n) = socket.read(&mut buffer) {
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buffer[..n]);
            if socket.write_all(&buffer[..n]).is_err() {
                break;
            }
        }
        received
    });

    let mut harness = Harness::new();
    let client = SocketAddr::new(IpAddr::V4(CLIENT_IP), CLIENT_PORT + 2);
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_addr.port());
    let client_isn = 9000u32;

    harness.stack.ensure_listener(target.port());
    harness.send(tcp_packet(client, target, client_isn, 0, SYN, &[]));
    let syn_ack = harness.expect_from_server(target.port(), client.port(), "SYN-ACK");
    let server_isn = syn_ack.seq;
    // An unrelated poll between SYN and ACK, as a busy tunnel does all the time.
    harness.pump();
    harness.send(tcp_packet(
        client,
        target,
        client_isn.wrapping_add(1),
        server_isn.wrapping_add(1),
        ACK,
        &[],
    ));
    let ReadyConnection { mut stream, .. } =
        harness.stack.take_ready().into_iter().next().expect("one connection");

    let ctx = ForwardContext {
        filter: Arc::new(Filter::new()),
        policy: Arc::new(Policy::default()),
        stats: harness.stats.clone(),
        log: None,
        http: None,
        // HTTPS filtering is off in these tests: the MITM path has its own suite in
        // `crate::https::mitm::e2e_tests`, and a tunnel test that also decrypted would make a
        // failure ambiguous between the two layers.
        https: None,
        client_addr: CLIENT_ADDR,
        target_port: 443,
        remote: TARGET_ADDR,
        owner_lookup: Arc::new(crate::https::policy::NoOwnerLookup),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let relay = runtime.spawn(async move {
        let outbound = connect_outbound(target).await.expect("outbound connect");
        relay_stream(&mut stream, outbound, &ctx).await;
    });

    let mut client_seq = client_isn.wrapping_add(1);
    let mut server_ack = server_isn.wrapping_add(1);
    let mut echoed = Vec::new();
    for segment in [&b"GET /first"[..], &b" second-segment"[..]] {
        harness.send(tcp_packet(client, target, client_seq, server_ack, ACK, segment));
        client_seq = client_seq.wrapping_add(segment.len() as u32);
        let want = echoed.len() + segment.len();
        let deadline = Instant::now() + Duration::from_secs(5);
        while echoed.len() < want && Instant::now() < deadline {
            let Some(frame) = harness.next_packet() else {
                continue;
            };
            if frame.src_port != target.port() || frame.payload.is_empty() {
                continue;
            }
            server_ack = frame.seq.wrapping_add(frame.payload.len() as u32);
            echoed.extend_from_slice(&frame.payload);
            harness.send(tcp_packet(client, target, client_seq, server_ack, ACK, &[]));
        }
        // Let the relay drain its receive buffer before the next segment arrives.
        std::thread::sleep(Duration::from_millis(200));
        harness.pump();
    }
    assert_eq!(echoed, b"GET /first second-segment", "both client segments must reach the server");

    relay.abort();
    drop(harness);
    let received = server_thread.join().expect("server thread");
    assert_eq!(received, b"GET /first second-segment");
}

/// The fake TUN plus the stack, with the pumping loop a real tunnel loop would run.
struct Harness {
    /// The test's side of the socketpair: what the tunnel "reads from the device".
    peer: std::os::unix::net::UnixStream,
    /// The descriptor the tunnel writes to and reads from (as `VpnService`'s detached fd would be).
    device_fd: OwnedFd,
    stack: TunnelStack,
    egress: tokio::sync::mpsc::Receiver<Vec<u8>>,
    stats: Arc<ForwardStats>,
}

impl Harness {
    fn new() -> Self {
        use std::os::unix::net::UnixStream;
        let (device, peer) = UnixStream::pair().expect("socketpair");
        let device_fd = {
            let raw = device.into_raw_fd();
            // SAFETY: ownership of `raw` moves into the OwnedFd and nothing else closes it.
            unsafe { OwnedFd::from_raw_fd(raw) }
        };
        set_nonblocking(device_fd.as_raw_fd()).expect("nonblocking");
        peer.set_read_timeout(Some(Duration::from_millis(20))).ok();

        let (egress_tx, egress) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        let notify = Arc::new(tokio::sync::Notify::new());
        let stats = Arc::new(ForwardStats::default());
        let stack = TunnelStack::new(egress_tx, notify, stats.clone(), 1500, 16).expect("stack");

        Self {
            peer,
            device_fd,
            stack,
            egress,
            stats,
        }
    }

    /// Feed one packet from the client into the stack, then move everything the stack produced onto
    /// the fake device — the two jobs a real tunnel loop performs around `Interface::poll`.
    fn send(&mut self, packet: Vec<u8>) {
        self.stack.push_ingress(packet);
        self.pump();
    }

    /// One poll plus one egress drain.
    fn pump(&mut self) {
        self.stack.poll();
        while let Ok(packet) = self.egress.try_recv() {
            write_packet(self.device_fd.as_raw_fd(), &packet).expect("write to the fake tun");
        }
    }

    /// Poll, drain, then read one packet the tunnel emitted and return it along with a
    /// [`TcpView`] of it. `None` when the tunnel emitted nothing within the read timeout.
    fn next_packet(&mut self) -> Option<TcpView> {
        self.pump();
        let mut buffer = vec![0u8; 65535];
        match self.peer.read(&mut buffer) {
            Ok(0) | Err(_) => None,
            Ok(n) => Some(view(&buffer[..n])),
        }
    }

    /// Read packets until one arrives from `from_port` to `to_port`, failing the test if none does.
    ///
    /// Bare ACKs from the stack are skipped: they are expected traffic (the stack acknowledges the
    /// server's data) and not what a given assertion is about.
    fn expect_from_server(&mut self, from_port: u16, to_port: u16, what: &str) -> TcpView {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Some(frame) = self.next_packet() {
                if frame.src_port == from_port && frame.dst_port == to_port {
                    return frame;
                }
            }
        }
        panic!("no {what} arrived from the tunnel");
    }
}

/// Build one IPv4/TCP packet by hand, checksums included.
fn tcp_packet(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut segment = vec![0u8; TCP_MIN_HEADER];
    segment[0..2].copy_from_slice(&src.port().to_be_bytes());
    segment[2..4].copy_from_slice(&dst.port().to_be_bytes());
    segment[4..8].copy_from_slice(&seq.to_be_bytes());
    segment[8..12].copy_from_slice(&ack.to_be_bytes());
    segment[12] = 5 << 4; // data offset 5, no options
    segment[13] = flags;
    segment[14..16].copy_from_slice(&65535u16.to_be_bytes()); // window
    segment.extend_from_slice(payload);

    let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (src.ip(), dst.ip()) else {
        panic!("this helper only builds IPv4 packets");
    };
    let checksum = packet::tcp_checksum(src_ip, dst_ip, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());

    let total = 20 + segment.len();
    let mut out = vec![0u8; 20];
    out[0] = 0x45;
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    out[8] = 64;
    out[9] = IPPROTO_TCP;
    out[12..16].copy_from_slice(&src_ip.octets());
    out[16..20].copy_from_slice(&dst_ip.octets());
    let header_checksum = packet::checksum(&out);
    out[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    out.extend_from_slice(&segment);
    out
}

/// The TCP fields a test reads off a packet the tunnel emitted.
struct TcpView {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: Vec<u8>,
}

fn view(packet: &[u8]) -> TcpView {
    let parsed = packet::parse(packet).expect("an IP packet");
    assert_eq!(parsed.protocol, IPPROTO_TCP);
    let segment = parsed.payload;
    let data_offset = usize::from(segment[12] >> 4) * 4;
    TcpView {
        src_port: u16::from_be_bytes([segment[0], segment[1]]),
        dst_port: u16::from_be_bytes([segment[2], segment[3]]),
        seq: u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]),
        ack: u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]),
        flags: segment[13],
        payload: segment[data_offset..].to_vec(),
    }
}

#[test]
fn the_policy_refuses_dot_before_the_handshake() {
    // TCP/853 must never reach the network: no listener is prepared, so smoltcp answers with a RST
    // and the counter records why. This is the packet-level half of the encrypted-DNS block.
    let mut harness = Harness::new();
    let client = SocketAddr::new(IpAddr::V4(CLIENT_IP), CLIENT_PORT);
    let policy = Policy::default();
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 853);
    assert!(matches!(
        policy.tcp_connect_action(target.port()),
        crate::tun::policy::Action::Drop(_)
    ));
    // The tunnel does not prepare a listener for a refused port, so the stack's answer is a RST.
    harness.send(tcp_packet(client, target, 1000, 0, SYN, &[]));
    let reply = harness.expect_from_server(target.port(), client.port(), "RST");
    assert_eq!(
        reply.flags & 0x04,
        0x04,
        "a refused port must answer with RST, not SYN-ACK"
    );
    assert_eq!(harness.stack.connection_count(), 0);
}

//! The userspace TCP/IP stack: smoltcp driven by the TUN file descriptor.
//!
//! # Why smoltcp directly instead of a wrapper crate
//!
//! The M2a task card leaves the stack choice open. `smoltcp` 0.14 was chosen over the two obvious
//! wrappers after reading their sources:
//!
//! | candidate | verdict |
//! |---|---|
//! | `ipstack` 1.0.1 | Rejected. Its own TCP implementation has a fixed 16 KiB unacked window, no window scaling, a hard-coded 60 s connection timeout, and `block_in_place` inside `Drop` (which panics on a current-thread runtime). Throughput is capped at roughly `16 KiB / RTT` — about 4.4 Mbit/s at 30 ms RTT — which cannot meet "≥ 80 % of no-VPN throughput". |
//! | `netstack-smoltcp` 0.2.5 | Close, but it accepts every SYN and hands out an opaque stream: there is no hook to refuse a connection by port before the handshake (TCP/853), and no way to abort with RST after reading the SNI — both of which this task requires. Its UDP side is one global datagram channel instead of the per-flow NAT the card specifies. |
//! | `smoltcp` 0.14 (direct) | Chosen. `medium-ip` is exactly TUN framing, `any_ip` makes transparent forwarding work, and every ingress packet is visible before it reaches a socket, which is what per-connection policy needs. The price is the ~450 lines of glue below. |
//!
//! # Shape of the glue
//!
//! One loop owns the `Interface` and the `SocketSet`; it is the only code that touches them.
//!
//! * TUN → stack: incoming packets go into a `VecDeque`; `Interface::poll` drains it.
//! * stack → TUN: a `TxToken` pushes finished packets into the egress channel the loop owns.
//! * stack ↔ forwarder: per connection, a pair of ring buffers plus wakers ([`TunnelStream`]). The
//!   forwarding task reads and writes those buffers as a plain `AsyncRead`/`AsyncWrite`; the loop is
//!   what moves bytes between them and the smoltcp socket. No per-packet channel traffic, and no
//!   lock is ever held across an `await`.
//! * Waiting: the loop sleeps until the fd is readable, a forwarding task nudges it, or the stack's
//!   own next deadline (`poll_delay`) arrives. With no connections open `poll_delay` is `None`, so
//!   an idle tunnel parks forever — there is no periodic timer anywhere (decision 10).

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll as TaskPoll, Waker};

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer, State as TcpState};
use smoltcp::storage::RingBuffer;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Notify};

use crate::tun::forward::ForwardStats;

/// Bytes kept per connection direction (tunnel→server and server→tunnel).
///
/// This is the TCP window, so it caps a single flow at `window / RTT`; 64 KiB gives ~17 Mbit/s at
/// 30 ms RTT and is line rate on a LAN. With the connection cap it also bounds the stack's memory:
/// 256 × 128 KiB = 32 MiB worst case, far less in practice.
pub const CONNECTION_BUFFER: usize = 64 * 1024;

/// Largest packet the TUN device can hand us.
pub const MAX_PACKET: usize = 65535;

/// How many ingress packets may wait for a poll.
const INGRESS_QUEUE: usize = 512;

/// One accepted connection.
struct Connection {
    shared: Arc<ConnShared>,
    /// The tunnelled app's endpoint.
    client: SocketAddr,
    /// The address the app dialled.
    target: SocketAddr,
    /// A forwarding task has been spawned for this connection.
    dispatched: bool,
}

/// State shared with a forwarding task.
struct ConnState {
    /// Bytes from the tunnelled client, waiting to be written to the outbound socket.
    rx: RingBuffer<'static, u8>,
    /// Bytes for the tunnelled client, written by the forwarding task.
    tx: RingBuffer<'static, u8>,
    /// The client half-closed: no more data will arrive.
    rx_closed: bool,
    /// The forwarding task finished writing: send a FIN once the buffer drains.
    tx_finished: bool,
    /// The forwarding task wants a RST (blocked host, truncated stream).
    abort: bool,
    /// The socket is gone; readers see EOF, writers see `BrokenPipe`.
    closed: bool,
    rx_waker: Option<Waker>,
    tx_waker: Option<Waker>,
}

pub struct ConnShared {
    state: Mutex<ConnState>,
}

impl ConnShared {
    fn new() -> Self {
        Self {
            state: Mutex::new(ConnState {
                rx: RingBuffer::new(vec![0u8; CONNECTION_BUFFER]),
                tx: RingBuffer::new(vec![0u8; CONNECTION_BUFFER]),
                rx_closed: false,
                tx_finished: false,
                abort: false,
                closed: false,
                rx_waker: None,
                tx_waker: None,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ConnState> {
        // A poisoned lock only means a previous holder panicked mid-update; every field is a plain
        // buffer or flag with no invariant a panic can break.
        self.state.lock().unwrap_or_else(|err| err.into_inner())
    }
}

/// The tunnel-side end of one TCP connection, as seen by a forwarding task.
///
/// A plain `AsyncRead`/`AsyncWrite` pair over the ring buffers, so `copy_bidirectional` and the
/// DNS-over-TCP handler need no knowledge of smoltcp.
pub struct TunnelStream {
    shared: Arc<ConnShared>,
    notify: Arc<Notify>,
    /// Set when the stream ended cleanly (both directions drained), so `Drop` sends FIN not RST.
    finished: bool,
}

impl TunnelStream {
    /// Abort the connection with a RST instead of a FIN.
    ///
    /// Used when a connection is refused *after* the handshake (SNI/Host blocked), where a FIN would
    /// look like a well-behaved server closing rather than a blocked host.
    pub fn abort(&mut self) {
        {
            let mut state = self.shared.lock();
            state.abort = true;
            state.tx.clear();
        }
        self.notify.notify_one();
    }

    /// Mark the stream finished so `Drop` closes gracefully.
    pub fn finish(&mut self) {
        self.finished = true;
    }

    /// A handle that can end this connection cleanly after the stream itself has been moved away.
    ///
    /// The HTTPS path hands the stream to the MITM state machine (and, on HTTP/2, on to per-stream
    /// tasks), so the forwarding task no longer holds anything to call [`TunnelStream::finish`] on.
    /// Without this handle every decrypted connection would end with the `Drop` RST — which truncates
    /// the tail of a `Connection: close` response, because the ring buffer still holds bytes the
    /// stack has not written yet.
    pub fn clean_end(&self) -> CleanEnd {
        CleanEnd {
            shared: Arc::clone(&self.shared),
            notify: Arc::clone(&self.notify),
        }
    }

    /// Hand the connection to an owned handle, leaving this one inert.
    ///
    /// The MITM layer needs an owned `Send + 'static` stream (the HTTP/2 leg moves it between
    /// tasks), while the forwarding task owns it by reference. Both views share the same ring
    /// buffers through the `Arc`, and the original is marked finished so dropping it does not send a
    /// second FIN/RST — the owned handle now owns the connection's ending.
    pub fn take_owned(&mut self) -> Option<TunnelStream> {
        if self.finished {
            return None;
        }
        self.finished = true;
        Some(TunnelStream {
            shared: Arc::clone(&self.shared),
            notify: Arc::clone(&self.notify),
            finished: false,
        })
    }
}

/// Ends a connection cleanly (FIN) once nothing owns the stream any more.
///
/// Obtained from [`TunnelStream::clean_end`] before the stream is handed to the MITM layer. [`finish`]
/// is the "the transfer completed" signal: the stack writes out whatever is still buffered and then
/// closes the socket. Dropping this handle without calling it does nothing, so an error path still
/// ends with the RST that a truncated transfer deserves.
pub struct CleanEnd {
    shared: Arc<ConnShared>,
    notify: Arc<Notify>,
}

impl CleanEnd {
    /// Let the socket drain and close with a FIN.
    pub fn finish(&self) {
        {
            let mut state = self.shared.lock();
            state.tx_finished = true;
        }
        self.notify.notify_one();
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> TaskPoll<io::Result<()>> {
        let mut state = self.shared.lock();
        if state.rx.is_empty() {
            if state.closed || state.rx_closed {
                return TaskPoll::Ready(Ok(()));
            }
            state.rx_waker = Some(cx.waker().clone());
            return TaskPoll::Pending;
        }
        let n = state.rx.dequeue_slice(buf.initialize_unfilled());
        buf.advance(n);
        drop(state);
        // Reading reopened the receive window: let the loop announce it and pull more data.
        self.notify.notify_one();
        TaskPoll::Ready(Ok(()))
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> TaskPoll<io::Result<usize>> {
        let mut state = self.shared.lock();
        if state.closed {
            return TaskPoll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if state.tx.is_full() {
            state.tx_waker = Some(cx.waker().clone());
            return TaskPoll::Pending;
        }
        let n = state.tx.enqueue_slice(buf);
        drop(state);
        self.notify.notify_one();
        TaskPoll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> TaskPoll<io::Result<()>> {
        TaskPoll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> TaskPoll<io::Result<()>> {
        {
            let mut state = self.shared.lock();
            state.tx_finished = true;
        }
        // The FIN goes out once the loop has drained the buffer; the caller may keep reading.
        self.notify.notify_one();
        TaskPoll::Ready(Ok(()))
    }
}

impl Drop for TunnelStream {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Any exit that was not a clean both-directions-drained copy truncated something: a RST is
        // the honest signal, and it also makes the client retry instead of hanging on a half-open
        // connection until the 2 h timeout.
        let mut state = self.shared.lock();
        state.abort = true;
        state.tx_finished = true;
        drop(state);
        self.notify.notify_one();
    }
}

/// The smoltcp device: an ingress queue plus a channel to the TUN writer.
pub struct TunDevice {
    ingress: VecDeque<Vec<u8>>,
    egress: mpsc::Sender<Vec<u8>>,
    mtu: usize,
}

impl TunDevice {
    fn push_ingress(&mut self, packet: Vec<u8>) -> bool {
        if self.ingress.len() >= INGRESS_QUEUE {
            return false;
        }
        self.ingress.push_back(packet);
        true
    }
}

pub struct TunRxToken(Vec<u8>);

impl RxToken for TunRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

pub struct TunTxToken {
    egress: mpsc::Sender<Vec<u8>>,
}

impl TxToken for TunTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        // A full egress queue means the writer is behind; dropping is what the kernel does with a
        // full device queue, and TCP retransmits.
        let _ = self.egress.try_send(buffer);
        result
    }
}

impl Device for TunDevice {
    type RxToken<'a> = TunRxToken;
    type TxToken<'a> = TunTxToken;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.ingress.pop_front()?;
        Some((
            TunRxToken(packet),
            TunTxToken {
                egress: self.egress.clone(),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken {
            egress: self.egress.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = Some(1);
        // A TUN device has no checksum offload, so both directions are done in software. Skipping
        // the receive check would let a corrupted packet into the stack for no gain.
        let mut checksums = ChecksumCapabilities::default();
        checksums.ipv4 = Checksum::Both;
        checksums.tcp = Checksum::Both;
        checksums.udp = Checksum::Both;
        caps.checksum = checksums;
        caps
    }
}

/// Allocate exactly what one forwarded connection holds, for the memory accounting in
/// `core/examples/heap_probe.rs` and `docs/PERF.md` §14.
///
/// Kept in the library rather than in the example so the sizes come from the same constants the data
/// path uses: an example that hard-coded 64 KiB would keep reporting 64 KiB after a change.
pub fn probe_one_connection() -> Vec<Vec<u8>> {
    vec![
        vec![0u8; CONNECTION_BUFFER],
        vec![0u8; CONNECTION_BUFFER],
        vec![0u8; crate::tun::forward::COPY_BUFFER],
        vec![0u8; crate::tun::forward::COPY_BUFFER],
    ]
}

/// The stack plus its socket bookkeeping. Owned by the tunnel loop, never shared.
pub struct TunnelStack {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: TunDevice,
    connections: HashMap<SocketHandle, Connection>,
    /// Listening sockets that are not yet pinned to a peer, by local port.
    free_listeners: HashMap<u16, Vec<SocketHandle>>,
    notify: Arc<Notify>,
    stats: Arc<ForwardStats>,
    started: std::time::Instant,
    mtu: usize,
    max_connections: usize,
}

impl TunnelStack {
    pub fn new(
        egress: mpsc::Sender<Vec<u8>>,
        notify: Arc<Notify>,
        stats: Arc<ForwardStats>,
        mtu: usize,
        max_connections: usize,
    ) -> io::Result<Self> {
        let mut device = TunDevice {
            ingress: VecDeque::with_capacity(INGRESS_QUEUE),
            egress,
            mtu,
        };
        let mut config = IfaceConfig::new(HardwareAddress::Ip);
        config.random_seed = random_seed();
        let now = SmolInstant::from_millis(0);
        let mut iface = Interface::new(config, &mut device, now);
        iface.update_ip_addrs(|addrs| {
            // The interface owns no real address. With `any_ip` these placeholders only satisfy
            // smoltcp's requirement to have a unicast address, and the default routes below need a
            // gateway of the same family.
            let _ = addrs.push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0));
            let _ = addrs.push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0));
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(0, 0, 0, 1))
            .map_err(|err| io::Error::other(format!("ipv4 route: {err}")))?;
        iface
            .routes_mut()
            .add_default_ipv6_route(smoltcp::wire::Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
            .map_err(|err| io::Error::other(format!("ipv6 route: {err}")))?;
        // Accept traffic addressed to any IP: this is what makes the tunnel transparent.
        iface.set_any_ip(true);

        Ok(Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            connections: HashMap::new(),
            free_listeners: HashMap::new(),
            notify,
            stats,
            started: std::time::Instant::now(),
            mtu,
            max_connections,
        })
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.started.elapsed().as_micros() as i64)
    }

    /// Queue an ingress packet for the stack. Returns false when the queue is full (the packet is
    /// dropped, which TCP recovers from).
    pub fn push_ingress(&mut self, packet: Vec<u8>) -> bool {
        self.device.push_ingress(packet)
    }

    pub fn has_ingress(&self) -> bool {
        !self.device.ingress.is_empty()
    }

    /// True when the connection table is at its limit, so new SYNs are refused.
    pub fn at_connection_limit(&self) -> bool {
        self.connections.len() >= self.max_connections
    }

    /// Prepare a listening socket for `local_port` if none is free.
    ///
    /// Called for every SYN *before* the packet reaches smoltcp: without a listening socket the
    /// stack answers with a RST, which is exactly the refusal wanted for TCP/853 — and the reason a
    /// blocked port is simply not prepared here.
    pub fn ensure_listener(&mut self, local_port: u16) {
        if let Some(handles) = self.free_listeners.get(&local_port) {
            for handle in handles {
                if self.sockets.get::<TcpSocket>(*handle).is_listening() {
                    return;
                }
            }
        }
        if self.at_connection_limit() {
            return;
        }
        let mut socket = TcpSocket::new(
            SocketBuffer::new(vec![0u8; CONNECTION_BUFFER]),
            SocketBuffer::new(vec![0u8; CONNECTION_BUFFER]),
        );
        // 2 h is the Linux default and the value the task card asks for. It is refreshed by traffic,
        // so an idle tunnel keeps no timer alive.
        socket.set_timeout(Some(SmolDuration::from_secs(2 * 60 * 60)));
        socket.set_keep_alive(Some(SmolDuration::from_secs(28)));
        // The tunnel is already one hop; Nagle on top of it is visibly slow for page loads.
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        if socket
            .listen(IpListenEndpoint {
                addr: None,
                port: local_port,
            })
            .is_err()
        {
            return;
        }
        let handle = self.sockets.add(socket);
        self.free_listeners.entry(local_port).or_default().push(handle);
    }

    /// Run one stack poll, moving bytes between sockets and forwarding tasks.
    pub fn poll(&mut self) {
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.pump_connections();
        self.promote_listeners();
    }

    /// The delay until the stack next needs attention, `None` when nothing is scheduled.
    pub fn poll_delay(&mut self) -> Option<SmolDuration> {
        self.iface.poll_delay(self.now(), &self.sockets)
    }

    /// Move data between each connection's socket and its ring buffers, and retire finished sockets.
    fn pump_connections(&mut self) {
        let now = self.now();
        let mut finished: Vec<SocketHandle> = Vec::new();

        let sockets = &mut self.sockets;
        for (handle, conn) in self.connections.iter() {
            let socket = sockets.get_mut::<TcpSocket>(*handle);
            let _ = now;

            if socket.state() == TcpState::Closed {
                let mut state = conn.shared.lock();
                state.closed = true;
                state.rx_closed = true;
                let rx_waker = state.rx_waker.take();
                let tx_waker = state.tx_waker.take();
                drop(state);
                if let Some(waker) = rx_waker {
                    waker.wake();
                }
                if let Some(waker) = tx_waker {
                    waker.wake();
                }
                finished.push(*handle);
                continue;
            }

            if conn.shared.lock().abort {
                socket.abort();
                continue;
            }

            // socket → forwarding task (the client's bytes)
            let mut received = 0usize;
            let mut rx_closed_now = false;
            {
                let shared = &conn.shared;
                let mut state = shared.lock();
                while socket.can_recv() && !state.rx.is_full() {
                    let mut pushed = 0usize;
                    let result = socket.recv(|data| {
                        pushed = state.rx.enqueue_slice(data);
                        (pushed, pushed)
                    });
                    match result {
                        Ok(_) if pushed > 0 => received += pushed,
                        _ => break,
                    }
                }
                // `may_recv()` is also false during the handshake (a connection is promoted while
                // still SynReceived), so only treat it as the client's FIN once the handshake is over;
                // otherwise any poll between SYN and ACK would latch a premature EOF.
                let handshaking = matches!(
                    socket.state(),
                    TcpState::Listen | TcpState::SynSent | TcpState::SynReceived
                );
                if !socket.may_recv() && !handshaking && !state.rx_closed {
                    state.rx_closed = true;
                    rx_closed_now = true;
                }
                if rx_closed_now {
                    let waker = state.rx_waker.take();
                    drop(state);
                    if let Some(waker) = waker {
                        waker.wake();
                    }
                }
            }
            if received > 0 {
                let waker = conn.shared.lock().rx_waker.take();
                if let Some(waker) = waker {
                    waker.wake();
                }
            }

            // forwarding task → socket (the server's bytes)
            let mut sent = 0usize;
            let mut want_close = false;
            {
                let mut state = conn.shared.lock();
                while socket.can_send() && !state.tx.is_empty() {
                    let mut pulled = 0usize;
                    let result = socket.send(|into| {
                        pulled = state.tx.dequeue_slice(into);
                        (pulled, pulled)
                    });
                    match result {
                        Ok(_) if pulled > 0 => sent += pulled,
                        _ => break,
                    }
                }
                if state.tx_finished && state.tx.is_empty() && socket.may_send() {
                    want_close = true;
                }
            }
            if sent > 0 {
                let waker = conn.shared.lock().tx_waker.take();
                if let Some(waker) = waker {
                    waker.wake();
                }
            }
            if want_close {
                socket.close();
                let waker = conn.shared.lock().tx_waker.take();
                if let Some(waker) = waker {
                    waker.wake();
                }
            }
        }

        for handle in finished {
            if let Some(conn) = self.connections.remove(&handle) {
                crate::log_msg("debug", &format!("tcp {} -> {} closed", conn.client, conn.target));
            }
            self.sockets.remove(handle);
        }
    }

    /// Promote listeners whose handshake finished into connections, and drop listeners whose
    /// connection was reset before it was accepted.
    fn promote_listeners(&mut self) {
        let mut promote: Vec<(u16, SocketHandle, SocketAddr, SocketAddr)> = Vec::new();
        let mut retire: Vec<(u16, SocketHandle)> = Vec::new();

        for (port, handles) in self.free_listeners.iter() {
            for handle in handles {
                let socket = self.sockets.get::<TcpSocket>(*handle);
                match socket.state() {
                    TcpState::Listen => {}
                    TcpState::SynReceived => {
                        if let (Some(target), Some(client)) =
                            (socket.local_endpoint(), socket.remote_endpoint())
                        {
                            promote.push((
                                *port,
                                *handle,
                                ip_endpoint_to_socket_addr(target),
                                ip_endpoint_to_socket_addr(client),
                            ));
                        }
                    }
                    _ => retire.push((*port, *handle)),
                }
            }
        }

        let promoted_ports: Vec<u16> = promote.iter().map(|(port, ..)| *port).collect();
        for (port, handle, target, client) in promote {
            if let Some(handles) = self.free_listeners.get_mut(&port) {
                handles.retain(|candidate| *candidate != handle);
            }
            self.connections.insert(
                handle,
                Connection {
                    shared: Arc::new(ConnShared::new()),
                    client,
                    target,
                    dispatched: false,
                },
            );
        }
        // Keep one free listener per port that just got a connection, so the next SYN is accepted.
        for port in promoted_ports {
            if !self.at_connection_limit() {
                self.ensure_listener(port);
            }
        }

        for (port, handle) in retire {
            if let Some(handles) = self.free_listeners.get_mut(&port) {
                handles.retain(|candidate| *candidate != handle);
            }
            self.sockets.remove(handle);
        }
    }

    /// Connections that are established and not yet handed to a forwarding task.
    pub fn take_ready(&mut self) -> Vec<ReadyConnection> {
        let mut ready = Vec::new();
        let sockets = &self.sockets;
        for (handle, conn) in self.connections.iter_mut() {
            if conn.dispatched {
                continue;
            }
            let state = sockets.get::<TcpSocket>(*handle).state();
            if state == TcpState::Established || state == TcpState::CloseWait {
                conn.dispatched = true;
                ready.push(ReadyConnection {
                    stream: TunnelStream {
                        shared: conn.shared.clone(),
                        notify: self.notify.clone(),
                        finished: false,
                    },
                    client: conn.client,
                    target: conn.target,
                });
            }
        }
        ready
    }

    /// Number of live connections, for stats.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn stats(&self) -> &Arc<ForwardStats> {
        &self.stats
    }
}

/// A connection that finished its handshake and is waiting for a forwarding task.
///
/// The naming follows what a tunnel means, not what smoltcp means: `client` is the tunnelled app's
/// endpoint (smoltcp's *remote*), `target` is the address the app dialled (smoltcp's *local*, the
/// one we accepted on behalf of).
pub struct ReadyConnection {
    pub stream: TunnelStream,
    pub client: SocketAddr,
    pub target: SocketAddr,
}

fn ip_endpoint_to_socket_addr(endpoint: IpEndpoint) -> SocketAddr {
    // smoltcp's `Ipv4Address`/`Ipv6Address` are re-exports of `core::net`, so the octets convert
    // directly into the `std::net` types the rest of the tunnel uses.
    match endpoint.addr {
        IpAddress::Ipv4(addr) => {
            SocketAddr::new(std::net::IpAddr::V4(addr), endpoint.port)
        }
        IpAddress::Ipv6(addr) => {
            SocketAddr::new(std::net::IpAddr::V6(addr), endpoint.port)
        }
    }
}

fn random_seed() -> u64 {
    // smoltcp uses this only for its ephemeral initial sequence numbers. `RandomState` is seeded
    // from the OS, which avoids pulling in `getrandom` for a single number.
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or_default(),
    );
    hasher.finish()
}

/// Outcome of one TUN read.
pub enum ReadResult {
    /// Bytes read into the caller's buffer.
    Packet(usize),
    /// Nothing to read right now.
    WouldBlock,
    /// The device is gone.
    Closed(io::Error),
}

/// Read one packet from the TUN fd. Non-blocking; `WouldBlock` means "come back on readiness".
pub fn read_packet(fd: RawFd, buf: &mut [u8]) -> ReadResult {
    loop {
        // SAFETY: `fd` is owned by the AsyncFd for the duration of the call and `buf` is a valid
        // mutable slice of the length passed.
        let ret = unsafe { sys_read(fd, buf.as_mut_ptr(), buf.len()) };
        if ret > 0 {
            return ReadResult::Packet(ret as usize);
        }
        if ret == 0 {
            return ReadResult::Closed(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tun device returned end of file",
            ));
        }
        let err = io::Error::last_os_error();
        match err.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => return ReadResult::WouldBlock,
            _ => return ReadResult::Closed(err),
        }
    }
}

/// Write a full IP packet. `Ok(false)` means the TUN queue was full.
pub fn write_packet(fd: RawFd, buf: &[u8]) -> io::Result<bool> {
    let mut written = 0usize;
    while written < buf.len() {
        // SAFETY: same contract as `read_packet`.
        let ret = unsafe { sys_write(fd, buf[written..].as_ptr(), buf.len() - written) };
        if ret >= 0 {
            written += ret as usize;
            continue;
        }
        let err = io::Error::last_os_error();
        match err.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => return Ok(false),
            _ => return Err(err),
        }
    }
    Ok(true)
}

pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl with F_GETFL/F_SETFL on an fd we own.
    let flags = unsafe { sys_fcntl(fd, F_GETFL, 0) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let ret = unsafe { sys_fcntl(fd, F_SETFL, flags | O_NONBLOCK) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const O_NONBLOCK: i32 = 0o4000;

extern "C" {
    #[link_name = "read"]
    fn sys_read(fd: i32, buf: *mut u8, count: usize) -> isize;
    #[link_name = "write"]
    fn sys_write(fd: i32, buf: *const u8, count: usize) -> isize;
    #[link_name = "fcntl"]
    fn sys_fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
}

/// Take ownership of a raw TUN file descriptor handed over by `VpnService`.
///
/// # Safety contract
/// `fd` must be an open descriptor whose ownership is transferred exactly once. `Native.start`
/// receives it from `ParcelFileDescriptor.detachFd()` and passes it here.
pub fn own_fd(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "negative file descriptor",
        ));
    }
    // SAFETY: ownership of `fd` is transferred to the returned OwnedFd by contract.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A stop flag that can also wake a parked tunnel loop.
#[derive(Debug)]
pub struct StopFlag {
    flag: AtomicBool,
    notify: Notify,
}

impl Default for StopFlag {
    fn default() -> Self {
        Self {
            flag: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }
}

impl StopFlag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn request(&self) {
        self.flag.store(true, Ordering::SeqCst);
        // `notify_one` (not `notify_waiters`) so a request that lands between the flag check inside
        // `wait` and its first poll still leaves a permit behind instead of being lost.
        self.notify.notify_one();
    }

    pub fn is_set(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Resolves when [`StopFlag::request`] is called. Safe to call repeatedly from one loop.
    pub async fn wait(&self) {
        // Close the race between the flag check and the await: a request landing in between would
        // otherwise be missed until the next packet.
        if self.flag.load(Ordering::SeqCst) {
            return;
        }
        self.notify.notified().await;
    }
}

/// A wrapper that keeps the fd for the writer task.
pub struct TunFd(pub OwnedFd);

impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_flag_wakes_a_waiter() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let flag = Arc::new(StopFlag::new());
            let waiter = {
                let flag = flag.clone();
                tokio::spawn(async move { flag.wait().await })
            };
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            flag.request();
            tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
                .await
                .expect("the waiter must be woken by request()")
                .expect("no panic");
            assert!(flag.is_set());
        });
    }

    #[test]
    fn stop_flag_set_before_wait_does_not_park() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let flag = StopFlag::new();
            flag.request();
            tokio::time::timeout(std::time::Duration::from_millis(100), flag.wait())
                .await
                .expect("wait on an already-set flag must not park");
        });
    }

    #[test]
    fn negative_fd_is_rejected() {
        assert!(own_fd(-1).is_err());
    }

    fn stack(max_connections: usize) -> TunnelStack {
        let (tx, _rx) = mpsc::channel(8);
        TunnelStack::new(
            tx,
            Arc::new(Notify::new()),
            Arc::new(ForwardStats::default()),
            1500,
            max_connections,
        )
        .expect("stack")
    }

    #[test]
    fn an_idle_stack_schedules_nothing() {
        // The "no periodic timer while idle" requirement, asserted rather than assumed. DNS-only mode
        // used to run a 60 s cache housekeeping timer here.
        let mut stack = stack(8);
        assert_eq!(stack.connection_count(), 0);
        assert!(
            stack.poll_delay().is_none(),
            "an empty stack must not ask to be polled again"
        );
    }

    #[test]
    fn listeners_are_created_once_per_port() {
        let mut stack = stack(8);
        stack.ensure_listener(443);
        assert_eq!(stack.free_listeners.get(&443).map(Vec::len), Some(1));
        stack.ensure_listener(443);
        assert_eq!(stack.free_listeners.get(&443).map(Vec::len), Some(1));
        stack.ensure_listener(80);
        assert_eq!(stack.free_listeners.get(&80).map(Vec::len), Some(1));
    }

    #[test]
    fn connection_limit_refuses_new_listeners() {
        let mut stack = stack(0);
        stack.ensure_listener(443);
        assert!(!stack.free_listeners.contains_key(&443));
    }

    #[test]
    fn stream_round_trips_through_the_ring_buffers() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let notify = Arc::new(Notify::new());
            let shared = Arc::new(ConnShared::new());
            let mut stream = TunnelStream {
                shared: shared.clone(),
                notify,
                finished: false,
            };
            stream.write_all(b"hello").await.expect("write");
            assert_eq!(shared.lock().tx.dequeue_slice(&mut [0u8; 8]), 5);

            assert_eq!(shared.lock().rx.enqueue_slice(b"world"), 5);
            let mut buf = [0u8; 8];
            let n = stream.read(&mut buf).await.expect("read");
            assert_eq!(&buf[..n], b"world");
            // Dropping without a clean finish must request a RST.
            drop(stream);
            assert!(shared.lock().abort);
        });
    }
}

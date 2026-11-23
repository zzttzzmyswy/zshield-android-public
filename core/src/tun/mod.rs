//! Packet handling and the userspace TCP/IP stack for the tunnel.
//!
//! Module map:
//! - [`packet`] — IPv4/IPv6, TCP and UDP parsing plus UDP/IP construction (checksums included);
//! - [`inspect`] — reading the hostname out of a TLS ClientHello or an HTTP/1.x request head;
//! - [`policy`] — which packets are hijacked / forwarded / dropped, as pure functions;
//! - [`nat`] — the UDP flow table with idle expiry and a hard size bound;
//! - [`stack`] — smoltcp driving the TUN fd (the `Device`, the socket bookkeeping, the ring buffers
//!   a forwarding task reads and writes);
//! - [`forward`] — the forwarding tasks: per-connection outbound sockets, SNI/Host enforcement,
//!   UDP relay, counters.
//!
//! The DNS-only mode of M0/M1 did not have a stack at all: it parsed UDP datagrams by hand and
//! replied. That path is gone — `mode = "dns_only"` now runs the same stack with a TUN route that
//! only covers the virtual DNS addresses, so there is one data path to maintain and test.

pub mod forward;
pub mod inspect;
pub mod nat;
pub mod packet;
pub mod policy;
pub mod stack;

#[cfg(test)]
mod e2e_tests;

pub use packet::{build_udp, checksum, parse, parse_tcp, parse_udp, IpPacket, UdpDatagram};
pub use policy::{Action, DropReason, Policy};
pub use stack::{own_fd, probe_one_connection, StopFlag, TunnelStack, MAX_PACKET};

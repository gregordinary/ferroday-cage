//! A stand-in for the host's resolver, for the network stack's nameserver to
//! ask in a test.
//!
//! [`Resolver`] answers on one loopback port, over UDP and TCP, and counts the
//! queries it takes over each. The stack's own sockets reach a loopback port,
//! where a sandbox's own traffic is refused, so a test points the stack's
//! upstream at it and resolves from inside the sandbox through the stack.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// The name a [`Resolver`] knows.
pub const KNOWN_NAME: &str = "resolver.example";

/// A stand-in for the host's resolver, on one loopback port over UDP and TCP.
///
/// It answers an A query for [`KNOWN_NAME`] with as many addresses as it was
/// made with, from `192.0.2.1` up, a query of another type for that name with
/// no records, and a query for any other name with NXDOMAIN. Over UDP it sends
/// an answer whole, however long: a resolver bounded by the protocol would not,
/// and what becomes of an answer a sandbox cannot take in one packet is the
/// stack's to show.
///
/// Its threads serve until the test process exits, or a minute passes with no
/// datagram.
pub struct Resolver {
    address: SocketAddr,
    udp: Arc<AtomicUsize>,
    tcp: Arc<AtomicUsize>,
}

impl Resolver {
    /// A resolver answering [`KNOWN_NAME`] with `records` addresses.
    pub fn new(records: usize) -> Resolver {
        let udp_socket =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a loopback UDP socket binds");
        let address = udp_socket.local_addr().expect("the socket has an address");
        let listener = TcpListener::bind(address).expect("a TCP listener binds the same port");
        let (udp, tcp) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));

        let counted = Arc::clone(&udp);
        udp_socket
            .set_read_timeout(Some(Duration::from_secs(60)))
            .expect("the read timeout is set");
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((len, peer)) = udp_socket.recv_from(&mut buf) {
                counted.fetch_add(1, Ordering::SeqCst);
                let _ = udp_socket.send_to(&answer(&buf[..len], records), peer);
            }
        });
        let counted = Arc::clone(&tcp);
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                counted.fetch_add(1, Ordering::SeqCst);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let mut prefix = [0u8; 2];
                if stream.read_exact(&mut prefix).is_err() {
                    continue;
                }
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
                if stream.read_exact(&mut query).is_err() {
                    continue;
                }
                let answer = answer(&query, records);
                let length = u16::try_from(answer.len()).expect("an answer a prefix states");
                let _ = stream.write_all(&[&length.to_be_bytes()[..], &answer].concat());
            }
        });
        Resolver { address, udp, tcp }
    }

    /// The loopback address and port it answers on, over both transports.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// How many queries it has taken over UDP and over TCP.
    pub fn asked(&self) -> (usize, usize) {
        (
            self.udp.load(Ordering::SeqCst),
            self.tcp.load(Ordering::SeqCst),
        )
    }
}

/// A [`Resolver`]'s answer to `query`, which a sandbox's C library wrote: one
/// question, its name uncompressed.
fn answer(query: &[u8], records: usize) -> Vec<u8> {
    let mut labels = Vec::new();
    let mut at = 12;
    while query[at] != 0 {
        let len = usize::from(query[at]);
        labels.push(String::from_utf8_lossy(&query[at + 1..at + 1 + len]).into_owned());
        at += 1 + len;
    }
    let question_end = at + 5;
    let qtype = u16::from_be_bytes([query[at + 1], query[at + 2]]);
    let known = labels.join(".").eq_ignore_ascii_case(KNOWN_NAME);
    let (rcode, count) = match (known, qtype) {
        (false, _) => (3, 0),
        (true, 1) => (0, records),
        (true, _) => (0, 0),
    };
    let mut answer = query[..2].to_vec();
    answer.extend_from_slice(&[0x81, 0x80 | rcode, 0, 1]);
    answer.extend_from_slice(
        &u16::try_from(count)
            .expect("a count a header states")
            .to_be_bytes(),
    );
    answer.extend_from_slice(&[0, 0, 0, 0]);
    answer.extend_from_slice(&query[12..question_end]);
    for index in 0..count {
        let last = u8::try_from(index % 250 + 1).expect("an octet");
        answer.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, last]);
    }
    answer
}

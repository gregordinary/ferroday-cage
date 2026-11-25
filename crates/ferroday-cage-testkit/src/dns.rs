//! A stand-in for the host's resolver, for the network stack's nameserver to
//! ask in a test.
//!
//! [`Resolver`] answers on one loopback port, over UDP and TCP, and counts the
//! queries it takes over each and for each name. The stack's own sockets reach
//! a loopback port, where a sandbox's own traffic is refused, so a test points
//! the stack's upstream at it and resolves from inside the sandbox through the
//! stack.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// The name a [`Resolver::new`] knows.
pub const KNOWN_NAME: &str = "resolver.example";

/// One record of a [`Resolver`]'s zone.
#[derive(Debug, Clone)]
pub enum Record {
    /// An IPv4 address, type A.
    A(Ipv4Addr),
    /// An IPv6 address, type AAAA.
    Aaaa(Ipv6Addr),
    /// An alias for the name given, type CNAME.
    Cname(&'static str),
    /// A service binding, type HTTPS, in alias mode to the root: one whose
    /// presence is all a test asks about.
    Https,
}

impl Record {
    /// The record's type, by its number.
    fn kind(&self) -> u16 {
        match self {
            Record::A(_) => 1,
            Record::Cname(_) => 5,
            Record::Aaaa(_) => 28,
            Record::Https => 65,
        }
    }

    /// The record's data, as it goes on the wire.
    fn data(&self) -> Vec<u8> {
        match self {
            Record::A(address) => address.octets().to_vec(),
            Record::Aaaa(address) => address.octets().to_vec(),
            Record::Cname(target) => wire(target),
            // Priority 0, alias mode, and the root as its target.
            Record::Https => vec![0, 0, 0],
        }
    }
}

/// The names a [`Resolver`] answers for: each question name with the records
/// that sit in the answer section of a reply to it, each with its owner.
pub type Zone = Vec<(&'static str, Vec<(&'static str, Record)>)>;

/// A stand-in for the host's resolver, on one loopback port over UDP and TCP.
///
/// It answers a question for a name its zone holds with that name's records of
/// the type asked for, and with every alias the zone lists for it, each under
/// the owner the zone gives it: the asked name, a name along its aliases, or
/// any other. A question for a name the zone does not hold is answered
/// NXDOMAIN. Over UDP it sends an answer whole, however long: a resolver bounded
/// by the protocol would not, and what becomes of an answer a sandbox cannot
/// take in one packet is the stack's to show.
///
/// Its threads serve until the test process exits, or a minute passes with no
/// datagram.
pub struct Resolver {
    address: SocketAddr,
    udp: Arc<AtomicUsize>,
    tcp: Arc<AtomicUsize>,
    /// How many questions it has taken for each name, in lower case.
    names: Arc<Mutex<HashMap<String, usize>>>,
}

impl Resolver {
    /// A resolver answering an A question for [`KNOWN_NAME`] with `records`
    /// addresses, from `192.0.2.1` up, a question of another type for that
    /// name with no records, and a question for any other name with NXDOMAIN.
    pub fn new(records: usize) -> Resolver {
        let addresses = (0..records)
            .map(|index| {
                let last = u8::try_from(index % 250 + 1).expect("an octet");
                (KNOWN_NAME, Record::A(Ipv4Addr::new(192, 0, 2, last)))
            })
            .collect();
        Resolver::serving(vec![(KNOWN_NAME, addresses)], 60)
    }

    /// A resolver answering for `zone`, each record with a time to live of
    /// `ttl` seconds.
    pub fn serving(zone: Zone, ttl: u32) -> Resolver {
        let udp_socket =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a loopback UDP socket binds");
        let address = udp_socket.local_addr().expect("the socket has an address");
        let listener = TcpListener::bind(address).expect("a TCP listener binds the same port");
        let (udp, tcp) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let names = Arc::new(Mutex::new(HashMap::new()));
        let zone = Arc::new(zone);

        let counted = Arc::clone(&udp);
        let (by_name, served) = (Arc::clone(&names), Arc::clone(&zone));
        udp_socket
            .set_read_timeout(Some(Duration::from_secs(60)))
            .expect("the read timeout is set");
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((len, peer)) = udp_socket.recv_from(&mut buf) {
                counted.fetch_add(1, Ordering::SeqCst);
                let answer = answer(&buf[..len], &served, ttl, &by_name);
                let _ = udp_socket.send_to(&answer, peer);
            }
        });
        let counted = Arc::clone(&tcp);
        let by_name = Arc::clone(&names);
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
                let answer = answer(&query, &zone, ttl, &by_name);
                let length = u16::try_from(answer.len()).expect("an answer a prefix states");
                let _ = stream.write_all(&[&length.to_be_bytes()[..], &answer].concat());
            }
        });
        Resolver {
            address,
            udp,
            tcp,
            names,
        }
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

    /// How many questions it has taken for `name`, in any case, over both
    /// transports.
    pub fn asked_for(&self, name: &str) -> usize {
        let names = self.names.lock().unwrap_or_else(PoisonError::into_inner);
        names.get(&name.to_ascii_lowercase()).copied().unwrap_or(0)
    }
}

/// The wire form of a dotted name.
fn wire(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for label in name.split('.').filter(|label| !label.is_empty()) {
        bytes.push(u8::try_from(label.len()).expect("a label's length"));
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes
}

/// A [`Resolver`]'s answer to `query`, which a sandbox's C library or a test
/// wrote: one question, its name uncompressed. Counts the question in `names`.
fn answer(query: &[u8], zone: &Zone, ttl: u32, names: &Mutex<HashMap<String, usize>>) -> Vec<u8> {
    let mut labels = Vec::new();
    let mut at = 12;
    while query[at] != 0 {
        let len = usize::from(query[at]);
        labels.push(String::from_utf8_lossy(&query[at + 1..at + 1 + len]).into_owned());
        at += 1 + len;
    }
    let question_end = at + 5;
    let qtype = u16::from_be_bytes([query[at + 1], query[at + 2]]);
    let asked = labels.join(".").to_ascii_lowercase();
    *names
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(asked.clone())
        .or_default() += 1;
    let held = zone
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(&asked));
    let (rcode, records): (u8, Vec<&(&str, Record)>) = match held {
        None => (3, Vec::new()),
        Some((_, records)) => (
            0,
            records
                .iter()
                .filter(|(_, record)| record.kind() == qtype || record.kind() == 5)
                .collect(),
        ),
    };
    let mut answer = query[..2].to_vec();
    answer.extend_from_slice(&[0x81, 0x80 | rcode, 0, 1]);
    answer.extend_from_slice(
        &u16::try_from(records.len())
            .expect("a count a header states")
            .to_be_bytes(),
    );
    answer.extend_from_slice(&[0, 0, 0, 0]);
    answer.extend_from_slice(&query[12..question_end]);
    for (owner, record) in records {
        // The asked name is a pointer to the question's, as a resolver writes
        // it; any other is written out.
        if owner.eq_ignore_ascii_case(&asked) {
            answer.extend_from_slice(&[0xc0, 12]);
        } else {
            answer.extend_from_slice(&wire(owner));
        }
        let data = record.data();
        answer.extend_from_slice(&record.kind().to_be_bytes());
        answer.extend_from_slice(&[0, 1]);
        answer.extend_from_slice(&ttl.to_be_bytes());
        answer.extend_from_slice(
            &u16::try_from(data.len())
                .expect("a record's length")
                .to_be_bytes(),
        );
        answer.extend_from_slice(&data);
    }
    answer
}

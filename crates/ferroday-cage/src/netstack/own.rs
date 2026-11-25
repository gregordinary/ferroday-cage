//! The host's own networks: the addresses its interfaces hold, each with the
//! network its prefix makes of it, and the networks its main routing table
//! reaches directly.
//!
//! A name anyone can register can be resolved to an address on the host's own
//! network, so an allow name rule admits none there, as it admits none in a
//! private range ([`Policy::decide`](super::policy::Policy::decide)). The
//! private ranges are fixed; these are read from the host when a stack
//! attaches, so they cover a LAN numbered from global addresses, and the
//! host's own public addresses, where a service bound to every address
//! answers. They are a snapshot: a network the host joins later is not among
//! them.
//!
//! IPv4's addresses are read over rtnetlink (`RTM_GETADDR`), since the kernel
//! lists them in no file, and IPv6's from `/proc/net/if_inet6`. Each address is
//! taken whatever routes it has: a public `/32` reached through an `onlink`
//! gateway, one added with `noprefixroute`, and one whose routes are in a table
//! other than main. The routes `/proc/net/route` lists with no gateway, the
//! default route aside, add the main table's other networks. That file lists
//! the main table alone, so a network that only another table's route reaches
//! is not among them. Loopback and link-local addresses are refused under every
//! rule and are left out here.

use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustix::io::Errno;
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};

use super::prefix;
use crate::mechanism::frame::retry_on_intr;

/// The most of one of the two files, or of the kernel's answer listing the
/// IPv4 addresses, that is read. A host's on-link routes and addresses take a
/// line or a message each, of about a hundred bytes; a router holding a full
/// table lists its routes with a gateway, which this leaves out, and reading
/// past this would read them.
const MAX_FILE_BYTES: u64 = 1 << 20;

/// The most networks kept, past which the rest of a file, or of the kernel's
/// answer, is not read.
const MAX_NETWORKS: usize = 1024;

/// The scope `/proc/net/if_inet6` gives a global address.
const SCOPE_GLOBAL: u32 = 0;

/// What rtnetlink's dump of the IPv4 addresses is asked and answered with
/// (`linux/netlink.h`, `linux/rtnetlink.h`, `linux/if_addr.h`): the sizes of a
/// message's header, of `struct ifaddrmsg` and of an attribute's header, the
/// message types and flags of the request and its answer, and the two
/// attributes that carry an address. Every field is in the host's byte order.
const NLMSG_HEADER: usize = 16;
const IFADDRMSG: usize = 8;
const RTA_HEADER: usize = 4;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

/// The sequence number the request carries, which every message answering it
/// repeats.
const SEQUENCE: u32 = 1;

/// The largest datagram a part of the kernel's answer comes in. The kernel
/// sizes each part of a dump to what the reader's last read could take, up to
/// 32 KiB, so a buffer of that size takes any part whole.
const MAX_DATAGRAM: usize = 32 * 1024;

/// The host's own networks, as networks and their prefix lengths, read now.
/// A file that cannot be read, or an rtnetlink socket the caller cannot open
/// or the kernel does not answer, contributes none.
///
/// The addresses come first, so the bound on how many are kept leaves routes
/// out before them.
pub(super) fn networks() -> Vec<(IpAddr, u8)> {
    let read = |path: &str| {
        let mut text = String::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(MAX_FILE_BYTES).read_to_string(&mut text))
            .map(|_| text)
            .unwrap_or_default()
    };
    let mut networks = addresses_v4();
    networks.extend(addresses_v6(&read("/proc/net/if_inet6")));
    networks.extend(routes_v4(&read("/proc/net/route")));
    networks.truncate(MAX_NETWORKS);
    networks
}

/// The networks of the IPv4 addresses the host's interfaces hold, asked of
/// the kernel over rtnetlink.
///
/// An answer that ends early, or that cannot be read on, contributes what it
/// held so far. A datagram any sender but the kernel sent is passed over:
/// another process can address a netlink socket by its port.
fn addresses_v4() -> Vec<(IpAddr, u8)> {
    let mut networks = Vec::new();
    let _ = dump_addresses_v4(&mut networks);
    networks.truncate(MAX_NETWORKS);
    networks
}

/// Asks the kernel for every IPv4 address and reads its answer into
/// `networks`, until the answer ends or [`MAX_FILE_BYTES`] of it have been
/// read.
///
/// The socket does not block. The kernel writes the first part of its answer
/// while it takes the request, and each further part while the read of the one
/// before it takes that, so a read that would wait finds an answer that has
/// ended, or one that will not come, and ends the reading rather than holding
/// the attachment on it.
fn dump_addresses_v4(networks: &mut Vec<(IpAddr, u8)>) -> Result<(), Errno> {
    let socket = rustix::net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    let kernel = SocketAddrNetlink::new(0, 0);
    retry_on_intr!(rustix::net::sendto(
        &socket,
        &address_request(),
        SendFlags::empty(),
        &kernel
    ))?;
    let mut datagram = vec![0; MAX_DATAGRAM];
    let mut read = 0;
    while read < MAX_FILE_BYTES && networks.len() < MAX_NETWORKS {
        let (taken, length, sender) = retry_on_intr!(rustix::net::recvfrom(
            &socket,
            &mut datagram[..],
            RecvFlags::TRUNC
        ))?;
        read += u64::try_from(length).unwrap_or(u64::MAX);
        if length > taken {
            break;
        }
        let from_kernel = sender
            .and_then(|sender| SocketAddrNetlink::try_from(sender).ok())
            .is_some_and(|sender| sender.pid() == 0);
        if from_kernel && read_addresses(&datagram[..taken], networks) {
            break;
        }
    }
    Ok(())
}

/// The request for a dump of every IPv4 address: a message header, then a
/// `struct ifaddrmsg` naming the family alone.
fn address_request() -> [u8; NLMSG_HEADER + IFADDRMSG] {
    let mut request = [0; NLMSG_HEADER + IFADDRMSG];
    let length = u32::try_from(request.len()).expect("the request is a few bytes long");
    request[0..4].copy_from_slice(&length.to_ne_bytes());
    request[4..6].copy_from_slice(&RTM_GETADDR.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&SEQUENCE.to_ne_bytes());
    // The sender's port, zero, lets the kernel fill in the socket's own.
    request[NLMSG_HEADER] = address_family_inet();
    request
}

/// `AF_INET`, as the one byte `struct ifaddrmsg` holds a family in.
fn address_family_inet() -> u8 {
    u8::try_from(AddressFamily::INET.as_raw()).expect("AF_INET fits a byte")
}

/// Reads one datagram of the kernel's answer to [`address_request`], adding
/// to `networks` each address an `RTM_NEWADDR` message names, and returns
/// whether the answer has ended: with its last message, with an error in
/// place of one, or with a message this does not read to its end.
///
/// Each address contributes the network its prefix length makes of it, and
/// its local address alone where that network does not hold it: on a
/// point-to-point link, the address a message names is the peer's. A prefix
/// length of zero would make every address the host's, and is taken as no
/// network. A message answering another request than [`SEQUENCE`] is passed
/// over.
fn read_addresses(datagram: &[u8], networks: &mut Vec<(IpAddr, u8)>) -> bool {
    let mut rest = datagram;
    while !rest.is_empty() {
        let Some(header) = rest.get(..NLMSG_HEADER) else {
            return true;
        };
        let length = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]);
        let length = usize::try_from(length).unwrap_or(usize::MAX);
        let kind = u16::from_ne_bytes([header[4], header[5]]);
        let sequence = u32::from_ne_bytes([header[8], header[9], header[10], header[11]]);
        let Some(payload) = rest.get(NLMSG_HEADER..length) else {
            return true;
        };
        if sequence == SEQUENCE {
            match kind {
                NLMSG_DONE | NLMSG_ERROR => return true,
                RTM_NEWADDR if !read_address(payload, networks) => return true,
                _ => {}
            }
        }
        rest = rest.get(aligned(length)..).unwrap_or_default();
    }
    false
}

/// Adds to `networks` what one `RTM_NEWADDR` message's `payload` names, a
/// `struct ifaddrmsg` and then its attributes, and returns whether it read to
/// its end. A message for another family than IPv4 adds nothing.
fn read_address(payload: &[u8], networks: &mut Vec<(IpAddr, u8)>) -> bool {
    let Some((head, mut attributes)) = payload.split_at_checked(IFADDRMSG) else {
        return false;
    };
    let (family, prefix_len) = (head[0], head[1]);
    let (mut address, mut local) = (None, None);
    while let Some(header) = attributes.get(..RTA_HEADER) {
        let length = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        let kind = u16::from_ne_bytes([header[2], header[3]]);
        let Some(data) = attributes.get(RTA_HEADER..length) else {
            return false;
        };
        let value = <[u8; 4]>::try_from(data).ok().map(Ipv4Addr::from);
        match kind {
            IFA_ADDRESS => address = value,
            IFA_LOCAL => local = value,
            _ => {}
        }
        attributes = attributes.get(aligned(length)..).unwrap_or_default();
    }
    if family != address_family_inet() || prefix_len > 32 {
        return true;
    }
    let own = |address: &Ipv4Addr| !address.is_loopback() && !address.is_link_local();
    let network = address
        .filter(own)
        .filter(|_| prefix_len > 0)
        .map(|address| (IpAddr::V4(address), prefix_len));
    let local = local
        .or(address)
        .filter(own)
        .map(IpAddr::V4)
        .filter(|&local| {
            !network.is_some_and(|(network, len)| prefix::contains(network, len, local))
        });
    networks.extend(network);
    networks.extend(local.map(|local| (local, 32)));
    true
}

/// `length` rounded up to the four-byte boundary netlink aligns each message
/// and each attribute to.
fn aligned(length: usize) -> usize {
    length.saturating_add(3) & !3
}

/// The networks `/proc/net/route`'s `text` routes to directly: a route with no
/// gateway, other than the default.
///
/// The kernel prints each address as the hexadecimal of the 32-bit value it
/// holds in network order, so its native-order bytes are the address's.
fn routes_v4(text: &str) -> Vec<(IpAddr, u8)> {
    let hex = |field: &str| u32::from_str_radix(field, 16).ok();
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (destination, gateway, mask) = (
                hex(fields.get(1)?)?,
                hex(fields.get(2)?)?,
                hex(fields.get(7)?)?,
            );
            let mask = Ipv4Addr::from(mask.to_ne_bytes());
            let prefix_len = u8::try_from(u32::from(mask).leading_ones()).ok()?;
            (gateway == 0 && prefix_len > 0).then(|| {
                let network = IpAddr::V4(Ipv4Addr::from(destination.to_ne_bytes()));
                (network, prefix_len)
            })
        })
        .filter(|&(network, _)| !network.is_loopback())
        .take(MAX_NETWORKS)
        .collect()
}

/// The networks `/proc/net/if_inet6`'s `text` gives the host's global
/// addresses: each address with the prefix length it is configured with.
fn addresses_v6(text: &str) -> Vec<(IpAddr, u8)> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let address = u128::from_str_radix(fields.first()?, 16).ok()?;
            let prefix_len = u8::from_str_radix(fields.get(2)?, 16).ok()?;
            let scope = u32::from_str_radix(fields.get(3)?, 16).ok()?;
            (scope == SCOPE_GLOBAL && prefix_len <= 128)
                .then_some((IpAddr::V6(Ipv6Addr::from(address)), prefix_len))
        })
        .take(MAX_NETWORKS)
        .collect()
}

/// Whether `address` is on one of `networks`.
pub(super) fn holds(networks: &[(IpAddr, u8)], address: IpAddr) -> bool {
    networks
        .iter()
        .any(|&(network, prefix_len)| prefix::contains(network, prefix_len, address))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The text is as a little-endian host's kernel prints it.
    #[cfg(target_endian = "little")]
    #[test]
    fn the_directly_routed_networks_are_read_and_the_rest_left_out() {
        // A default route through a gateway, the LAN it reaches directly, a
        // docker bridge, a route through another gateway, and loopback.
        let routes = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
eth0\t00000A0A\t0201A8C0\t0003\t0\t0\t0\t0000FFFF\t0\t0\t0
lo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0
";
        assert_eq!(
            routes_v4(routes),
            [
                ("192.168.1.0".parse().unwrap(), 24),
                ("172.17.0.0".parse().unwrap(), 16)
            ]
        );
    }

    #[test]
    fn a_global_address_gives_its_network_and_a_link_local_one_none() {
        let addresses = "\
00000000000000000000000000000001 01 80 10 80       lo
20010db8000100020000000000000005 02 40 00 80     eth0
fe800000000000000000000000000005 02 40 20 80     eth0
";
        assert_eq!(
            addresses_v6(addresses),
            [("2001:db8:1:2::5".parse().unwrap(), 64)]
        );
        let networks = addresses_v6(addresses);
        assert!(holds(&networks, "2001:db8:1:2::77".parse().unwrap()));
        assert!(!holds(&networks, "2001:db8:1:3::5".parse().unwrap()));
    }

    /// A netlink message of type `kind`, answering the request `sequence`
    /// numbers, around `payload`, padded as the kernel pads one.
    fn message(kind: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let length = u32::try_from(NLMSG_HEADER + payload.len()).unwrap();
        let mut message = length.to_ne_bytes().to_vec();
        message.extend_from_slice(&kind.to_ne_bytes());
        message.extend_from_slice(&2u16.to_ne_bytes());
        message.extend_from_slice(&sequence.to_ne_bytes());
        message.extend_from_slice(&4242u32.to_ne_bytes());
        message.extend_from_slice(payload);
        message.resize(aligned(message.len()), 0);
        message
    }

    /// An `RTM_NEWADDR` message's payload: an IPv4 address of `prefix_len`
    /// on interface 2, and `attributes`, each a type and an address.
    fn address(prefix_len: u8, attributes: &[(u16, &str)]) -> Vec<u8> {
        let mut payload = vec![address_family_inet(), prefix_len, 0, 0];
        payload.extend_from_slice(&2u32.to_ne_bytes());
        for (kind, value) in attributes {
            let value: Ipv4Addr = value.parse().unwrap();
            payload.extend_from_slice(&8u16.to_ne_bytes());
            payload.extend_from_slice(&kind.to_ne_bytes());
            payload.extend_from_slice(&value.octets());
        }
        payload
    }

    fn network(text: &str, prefix_len: u8) -> (IpAddr, u8) {
        (text.parse().unwrap(), prefix_len)
    }

    #[test]
    fn each_ipv4_address_gives_itself_and_its_network() {
        // A public /32 reached through an `onlink` gateway, an address added
        // with `noprefixroute`, the two ends of a point-to-point link, and
        // loopback and link-local addresses, which are left out.
        let mut datagram = Vec::new();
        for (prefix_len, attributes) in [
            (
                32,
                &[(IFA_ADDRESS, "203.0.113.5"), (IFA_LOCAL, "203.0.113.5")][..],
            ),
            (
                24,
                &[(IFA_LOCAL, "198.51.100.7"), (IFA_ADDRESS, "198.51.100.7")],
            ),
            (32, &[(IFA_LOCAL, "192.0.2.1"), (IFA_ADDRESS, "192.0.2.2")]),
            (8, &[(IFA_ADDRESS, "127.0.0.1"), (IFA_LOCAL, "127.0.0.1")]),
            (
                16,
                &[(IFA_ADDRESS, "169.254.7.7"), (IFA_LOCAL, "169.254.7.7")],
            ),
        ] {
            datagram.extend(message(
                RTM_NEWADDR,
                SEQUENCE,
                &address(prefix_len, attributes),
            ));
        }
        // A message answering another request is passed over.
        datagram.extend(message(
            RTM_NEWADDR,
            SEQUENCE + 1,
            &address(32, &[(IFA_ADDRESS, "233.252.0.1")]),
        ));
        let mut networks = Vec::new();
        assert!(
            !read_addresses(&datagram, &mut networks),
            "the answer goes on"
        );
        assert_eq!(
            networks,
            [
                network("203.0.113.5", 32),
                network("198.51.100.7", 24),
                network("192.0.2.2", 32),
                network("192.0.2.1", 32),
            ]
        );
        assert!(holds(&networks, "198.51.100.200".parse().unwrap()));
        assert!(!holds(&networks, "203.0.113.6".parse().unwrap()));
        // The answer ends with its last message, or with an error in place of
        // one, and what follows either is not read.
        for end in [NLMSG_DONE, NLMSG_ERROR] {
            let mut datagram = message(end, SEQUENCE, &0i32.to_ne_bytes());
            datagram.extend(message(
                RTM_NEWADDR,
                SEQUENCE,
                &address(32, &[(IFA_ADDRESS, "233.252.0.1")]),
            ));
            let mut networks = Vec::new();
            assert!(read_addresses(&datagram, &mut networks));
            assert_eq!(networks, []);
        }
    }

    #[test]
    fn an_answer_that_does_not_read_to_its_end_ends_where_it_stops() {
        let whole = message(
            RTM_NEWADDR,
            SEQUENCE,
            &address(32, &[(IFA_ADDRESS, "203.0.113.5")]),
        );
        // A message shorter than its header says, or than a header, and an
        // attribute running past its message.
        let mut overlong = whole.clone();
        overlong[0] += 4;
        let mut attribute = whole.clone();
        attribute[NLMSG_HEADER + IFADDRMSG] = 12;
        for datagram in [
            &whole[..whole.len() - 1],
            &whole[..8],
            &overlong,
            &attribute,
        ] {
            let mut networks = Vec::new();
            assert!(read_addresses(datagram, &mut networks));
            assert_eq!(networks, []);
        }
    }

    #[test]
    fn the_kernel_lists_the_address_the_host_connects_from() {
        let Some(own) = ferroday_cage_testkit::require::routable_v4() else {
            return;
        };
        let addresses = addresses_v4();
        assert!(holds(&addresses, IpAddr::V4(own)), "{own} in {addresses:?}");
        assert!(
            !holds(&addresses, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "{addresses:?}"
        );
        assert!(holds(&networks(), IpAddr::V4(own)));
    }
}

//! The host's own networks: the ones its routing table reaches directly, and
//! each of its IPv6 addresses with its prefix.
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
//! IPv4's are the routes `/proc/net/route` lists with no gateway, the default
//! route aside, and IPv6's the global addresses `/proc/net/if_inet6` lists,
//! each as the network its prefix length makes of it. Loopback and link-local
//! addresses are refused under every rule and are left out here.

use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::prefix;

/// The most of one of the two files that is read. A host's on-link routes
/// and addresses take a line each, of about a hundred bytes; a router holding
/// a full table lists its routes with a gateway, which this leaves out, and
/// reading past this would read them.
const MAX_FILE_BYTES: u64 = 1 << 20;

/// The most networks kept, past which the rest of a file is not read.
const MAX_NETWORKS: usize = 1024;

/// The scope `/proc/net/if_inet6` gives a global address.
const SCOPE_GLOBAL: u32 = 0;

/// The host's own networks, as networks and their prefix lengths, read now.
/// A file that cannot be read contributes none.
pub(super) fn networks() -> Vec<(IpAddr, u8)> {
    let read = |path: &str| {
        let mut text = String::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(MAX_FILE_BYTES).read_to_string(&mut text))
            .map(|_| text)
            .unwrap_or_default()
    };
    let mut networks = routes_v4(&read("/proc/net/route"));
    networks.extend(addresses_v6(&read("/proc/net/if_inet6")));
    networks.truncate(MAX_NETWORKS);
    networks
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
}

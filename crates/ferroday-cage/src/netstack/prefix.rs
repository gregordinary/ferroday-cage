//! Address prefixes, as the stack's address plan and its destination rules both
//! read them: the mask of a prefix length, whether a network holds an address,
//! and the IPv4 address NAT64's well-known prefix embeds.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The mask of an IPv4 prefix `prefix_len` bits long, from 0 to 32.
///
/// Shifted with `checked_shl`, since a prefix of length 0 shifts by the whole
/// width, which `<<` refuses and which leaves no bit of the mask set.
pub(super) fn mask_v4(prefix_len: u8) -> u32 {
    u32::MAX
        .checked_shl(32u32.saturating_sub(u32::from(prefix_len)))
        .unwrap_or(0)
}

/// The mask of an IPv6 prefix `prefix_len` bits long, from 0 to 128, built as
/// [`mask_v4`] builds an IPv4 one.
pub(super) fn mask_v6(prefix_len: u8) -> u128 {
    u128::MAX
        .checked_shl(128u32.saturating_sub(u32::from(prefix_len)))
        .unwrap_or(0)
}

/// The number of bits in an address of `address`'s family.
pub(super) fn width(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Whether `address` is in the network `network`/`prefix_len`. An address of
/// the other family never is.
pub(super) fn contains(network: IpAddr, prefix_len: u8, address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            let mask = mask_v4(prefix_len);
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            let mask = mask_v6(prefix_len);
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

/// Whether `network` sets no bit past its first `prefix_len`, so it names the
/// network itself rather than an address in it.
pub(super) fn is_network(network: IpAddr, prefix_len: u8) -> bool {
    match network {
        IpAddr::V4(network) => u32::from(network) & !mask_v4(prefix_len) == 0,
        IpAddr::V6(network) => u128::from(network) & !mask_v6(prefix_len) == 0,
    }
}

/// The IPv4 address `addr` embeds under NAT64's well-known prefix,
/// `64:ff9b::/96`, or `None` for an address outside it.
///
/// A host on an IPv6-only network reaches IPv4 destinations through a
/// translator, and the guest reaches what the host reaches, so the prefix as a
/// whole is carried. The translator connects to the embedded IPv4 address from
/// its own position, which is the host's where the translator runs on the
/// host. So an embedded address is held to the IPv4 rules, the destination
/// rules a caller gives included. That keeps an IPv4 refusal from being
/// re-expressed through the translator, as the mapped and compatible forms
/// would re-express it through the host's own stack.
///
/// Only the well-known prefix says so in the address. A network-specific
/// prefix, the local-use `64:ff9b:1::/48` among them, is indistinguishable
/// from any other routable address, and a caller on such a network names it in
/// a rule of its own.
pub(super) fn nat64_embedded(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    match addr.segments() {
        [0x0064, 0xff9b, 0, 0, 0, 0, high, low] => {
            Some(Ipv4Addr::from(u32::from(high) << 16 | u32::from(low)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mask_covers_its_prefix_at_every_length() {
        assert_eq!(mask_v4(0), 0);
        assert_eq!(mask_v4(8), 0xff00_0000);
        assert_eq!(mask_v4(27), 0xffff_ffe0);
        assert_eq!(mask_v4(32), u32::MAX);
        assert_eq!(mask_v6(0), 0);
        assert_eq!(mask_v6(64), u128::MAX << 64);
        assert_eq!(mask_v6(128), u128::MAX);
    }

    #[test]
    fn a_network_contains_its_own_family_alone() {
        let v4 = |text: &str| text.parse::<IpAddr>().unwrap();
        assert!(contains(v4("192.0.2.0"), 24, v4("192.0.2.255")));
        assert!(!contains(v4("192.0.2.0"), 24, v4("192.0.3.0")));
        assert!(contains(v4("0.0.0.0"), 0, v4("203.0.113.9")));
        assert!(contains(v4("192.0.2.7"), 32, v4("192.0.2.7")));
        assert!(!contains(v4("192.0.2.7"), 32, v4("192.0.2.8")));
        assert!(contains(v4("2001:db8::"), 32, v4("2001:db8:ffff::1")));
        assert!(contains(v4("::"), 0, v4("2001:db8::1")));
        // Prefix 0 holds every address of its family and none of the other.
        assert!(!contains(v4("0.0.0.0"), 0, v4("::1")));
        assert!(!contains(v4("::"), 0, v4("127.0.0.1")));
    }

    #[test]
    fn a_network_sets_no_bit_past_its_prefix() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        assert!(is_network(ip("192.0.2.0"), 24));
        assert!(!is_network(ip("192.0.2.7"), 24));
        assert!(is_network(ip("192.0.2.7"), 32));
        assert!(is_network(ip("0.0.0.0"), 0));
        assert!(!is_network(ip("10.0.0.0"), 0));
        assert!(is_network(ip("2001:db8::"), 32));
        assert!(!is_network(ip("2001:db8::1"), 64));
    }
}

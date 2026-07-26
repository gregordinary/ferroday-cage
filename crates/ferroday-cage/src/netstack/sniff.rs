//! Frame classification ahead of the interface.
//!
//! The pump inspects every frame read from the tap before queueing it for
//! the interface, because a TCP connection attempt needs a listening
//! socket to exist by the time the interface processes the segment — the
//! same poll that ingests the SYN. The classifier is a pure function over
//! `smoltcp::wire`, with no state and no side effects.
//!
//! Only cleanly parsed frames classify. IPv6 extension headers are not
//! walked: a connection-opening segment behind one classifies as
//! [`Sniff::Other`], leaving it to the interface, which answers an
//! unmatched segment with a reset. Checksums are not verified here; the
//! interface remains the arbiter of validity, and a listener created for
//! a segment the interface then discards is reaped by the establish
//! deadline.

use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, IpAddress, IpEndpoint, IpProtocol, Ipv4Packet, Ipv6Packet,
    TcpPacket, UdpPacket,
};

/// What a frame means to the flow engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Sniff {
    /// A TCP connection-opening segment: SYN set, ACK clear.
    TcpSyn {
        /// The guest endpoint originating the connection.
        src: IpEndpoint,
        /// The destination the guest addressed.
        dst: IpEndpoint,
    },
    /// A UDP datagram: the interface needs a receive socket bound to its
    /// destination port before it processes the datagram.
    Udp {
        /// The guest endpoint originating the datagram.
        src: IpEndpoint,
        /// The destination the guest addressed.
        dst: IpEndpoint,
    },
    /// Anything else: no per-flow action ahead of the interface.
    Other,
}

/// Classifies one Ethernet frame.
pub(super) fn classify(frame: &[u8]) -> Sniff {
    let Ok(ethernet) = EthernetFrame::new_checked(frame) else {
        return Sniff::Other;
    };
    match ethernet.ethertype() {
        EthernetProtocol::Ipv4 => {
            let Ok(packet) = Ipv4Packet::new_checked(ethernet.payload()) else {
                return Sniff::Other;
            };
            classify_transport(
                packet.next_header(),
                IpAddress::Ipv4(packet.src_addr()),
                IpAddress::Ipv4(packet.dst_addr()),
                packet.payload(),
            )
        }
        EthernetProtocol::Ipv6 => {
            let Ok(packet) = Ipv6Packet::new_checked(ethernet.payload()) else {
                return Sniff::Other;
            };
            classify_transport(
                packet.next_header(),
                IpAddress::Ipv6(packet.src_addr()),
                IpAddress::Ipv6(packet.dst_addr()),
                packet.payload(),
            )
        }
        _ => Sniff::Other,
    }
}

/// Classifies a transport payload between the given addresses.
fn classify_transport(
    protocol: IpProtocol,
    src: IpAddress,
    dst: IpAddress,
    payload: &[u8],
) -> Sniff {
    match protocol {
        IpProtocol::Tcp => {
            let Ok(segment) = TcpPacket::new_checked(payload) else {
                return Sniff::Other;
            };
            if segment.syn() && !segment.ack() {
                Sniff::TcpSyn {
                    src: IpEndpoint::new(src, segment.src_port()),
                    dst: IpEndpoint::new(dst, segment.dst_port()),
                }
            } else {
                Sniff::Other
            }
        }
        IpProtocol::Udp => {
            let Ok(datagram) = UdpPacket::new_checked(payload) else {
                return Sniff::Other;
            };
            Sniff::Udp {
                src: IpEndpoint::new(src, datagram.src_port()),
                dst: IpEndpoint::new(dst, datagram.dst_port()),
            }
        }
        _ => Sniff::Other,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpAddress, Ipv4Packet,
        Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
    };

    use super::*;

    /// Builds an Ethernet frame around a TCP segment with the given flags.
    fn tcp_frame(v6: bool, control: TcpControl, ack: Option<TcpSeqNumber>) -> Vec<u8> {
        let tcp = TcpRepr {
            src_port: 41000,
            dst_port: 80,
            control,
            seq_number: TcpSeqNumber(7),
            ack_number: ack,
            window_len: 4096,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        let (src, dst): (IpAddress, IpAddress) = if v6 {
            (
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x15).into(),
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(),
            )
        } else {
            (
                Ipv4Addr::new(10, 0, 2, 15).into(),
                Ipv4Addr::new(203, 0, 113, 9).into(),
            )
        };
        let checksums = ChecksumCapabilities::default();
        let mut ip_payload = vec![0u8; tcp.buffer_len()];
        let mut segment = TcpPacket::new_unchecked(&mut ip_payload);
        tcp.emit(&mut segment, &src, &dst, &checksums);

        let ethernet = EthernetRepr {
            src_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            dst_addr: EthernetAddress([0x02, 0, 0, 0, 0, 2]),
            ethertype: if v6 {
                EthernetProtocol::Ipv6
            } else {
                EthernetProtocol::Ipv4
            },
        };
        let ip_len = if v6 {
            let repr = Ipv6Repr {
                src_addr: match src {
                    IpAddress::Ipv6(addr) => addr,
                    IpAddress::Ipv4(_) => unreachable!(),
                },
                dst_addr: match dst {
                    IpAddress::Ipv6(addr) => addr,
                    IpAddress::Ipv4(_) => unreachable!(),
                },
                next_header: IpProtocol::Tcp,
                payload_len: ip_payload.len(),
                hop_limit: 64,
            };
            repr.buffer_len()
        } else {
            let repr = Ipv4Repr {
                src_addr: match src {
                    IpAddress::Ipv4(addr) => addr,
                    IpAddress::Ipv6(_) => unreachable!(),
                },
                dst_addr: match dst {
                    IpAddress::Ipv4(addr) => addr,
                    IpAddress::Ipv6(_) => unreachable!(),
                },
                next_header: IpProtocol::Tcp,
                payload_len: ip_payload.len(),
                hop_limit: 64,
            };
            repr.buffer_len()
        };

        let mut frame = vec![0u8; ethernet.buffer_len() + ip_len + ip_payload.len()];
        let mut eth = EthernetFrame::new_unchecked(&mut frame);
        ethernet.emit(&mut eth);
        if v6 {
            let repr = Ipv6Repr {
                src_addr: match src {
                    IpAddress::Ipv6(addr) => addr,
                    IpAddress::Ipv4(_) => unreachable!(),
                },
                dst_addr: match dst {
                    IpAddress::Ipv6(addr) => addr,
                    IpAddress::Ipv4(_) => unreachable!(),
                },
                next_header: IpProtocol::Tcp,
                payload_len: ip_payload.len(),
                hop_limit: 64,
            };
            let mut packet = Ipv6Packet::new_unchecked(eth.payload_mut());
            repr.emit(&mut packet);
            packet.payload_mut()[..ip_payload.len()].copy_from_slice(&ip_payload);
        } else {
            let repr = Ipv4Repr {
                src_addr: match src {
                    IpAddress::Ipv4(addr) => addr,
                    IpAddress::Ipv6(_) => unreachable!(),
                },
                dst_addr: match dst {
                    IpAddress::Ipv4(addr) => addr,
                    IpAddress::Ipv6(_) => unreachable!(),
                },
                next_header: IpProtocol::Tcp,
                payload_len: ip_payload.len(),
                hop_limit: 64,
            };
            let mut packet = Ipv4Packet::new_unchecked(eth.payload_mut());
            repr.emit(&mut packet, &checksums);
            packet.payload_mut()[..ip_payload.len()].copy_from_slice(&ip_payload);
        }
        frame
    }

    #[test]
    fn a_v4_syn_classifies_with_its_endpoints() {
        let frame = tcp_frame(false, TcpControl::Syn, None);
        match classify(&frame) {
            Sniff::TcpSyn { src, dst } => {
                assert_eq!(src.addr, IpAddress::Ipv4(Ipv4Addr::new(10, 0, 2, 15)));
                assert_eq!(src.port, 41000);
                assert_eq!(dst.addr, IpAddress::Ipv4(Ipv4Addr::new(203, 0, 113, 9)));
                assert_eq!(dst.port, 80);
            }
            other => panic!("a SYN must classify as TcpSyn, not {other:?}"),
        }
    }

    #[test]
    fn a_v6_syn_classifies_with_its_endpoints() {
        let frame = tcp_frame(true, TcpControl::Syn, None);
        match classify(&frame) {
            Sniff::TcpSyn { src, dst } => {
                assert_eq!(src.port, 41000);
                assert_eq!(
                    dst.addr,
                    IpAddress::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
                );
            }
            other => panic!("a SYN must classify as TcpSyn, not {other:?}"),
        }
    }

    #[test]
    fn a_syn_ack_is_not_a_connection_attempt() {
        let frame = tcp_frame(false, TcpControl::Syn, Some(TcpSeqNumber(3)));
        assert_eq!(classify(&frame), Sniff::Other);
    }

    #[test]
    fn a_plain_segment_is_not_a_connection_attempt() {
        let frame = tcp_frame(false, TcpControl::None, Some(TcpSeqNumber(3)));
        assert_eq!(classify(&frame), Sniff::Other);
    }

    #[test]
    fn garbage_classifies_as_other() {
        assert_eq!(classify(&[]), Sniff::Other);
        assert_eq!(classify(&[0xff; 10]), Sniff::Other);
        assert_eq!(classify(&[0x00; 64]), Sniff::Other);
    }
}

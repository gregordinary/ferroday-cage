//! Frame classification ahead of the interface.
//!
//! The pump inspects every frame read from the tap before queueing it for
//! the interface, for three reasons. A TCP connection attempt needs a listening
//! socket to exist by the time the interface processes the segment — the
//! same poll that ingests the SYN. A request the interface would answer
//! *on behalf of an address it does not own* has to be withheld from it: the
//! interface accepts any destination (`any_ip`) so that routed traffic reaches
//! the flows' sockets, and that switch also makes it answer address resolution
//! and ICMP echo for the whole address space. Those two are the only frames
//! whose answer is the interface's own, so classifying them is what keeps
//! `any_ip` a receive rule rather than a claim of ownership. And TCP and UDP
//! are carried only from the guest's own address, so every segment and
//! datagram reports its source. The classifier is a pure function over
//! `smoltcp::wire`, with no state and no side effects; it reports what a frame
//! is, and [`pump`](super::pump) decides.
//!
//! Only cleanly parsed, unfragmented frames classify. IP fragmentation is
//! not compiled in, so the interface rejects every fragment before it
//! reaches a socket; classifying one would create state for a frame that
//! is about to be discarded, so an IPv4 fragment classifies as
//! [`Sniff::Other`] here too. IPv6 needs no such rule, since its fragment
//! header is an extension header and extension headers are not walked: a
//! connection-opening segment behind one classifies as [`Sniff::Other`],
//! leaving it to the interface, which answers an unmatched segment with a
//! reset. A datagram behind an extension header reaches its port's socket
//! without being classified, which is why the UDP table checks the source again
//! where it opens a flow. Checksums are not verified here; the interface
//! remains the arbiter of validity, and a listener created for a segment the
//! interface then discards is reaped by the establish deadline.

use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetFrame, EthernetProtocol, Icmpv4Message, Icmpv4Packet,
    Icmpv6Message, Icmpv6Packet, IpAddress, IpEndpoint, IpProtocol, Ipv4Packet, Ipv6Packet,
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
    /// Any other TCP segment: the interface delivers it to the flow it
    /// belongs to, or answers it with a reset.
    TcpSegment {
        /// The address the segment came from.
        src: IpAddress,
    },
    /// A UDP datagram: the interface needs a receive socket bound to its
    /// destination port before it processes the datagram.
    Udp {
        /// The guest endpoint originating the datagram.
        src: IpEndpoint,
        /// The destination the guest addressed.
        dst: IpEndpoint,
    },
    /// An address-resolution request: an ARP request, whose answer would
    /// assert that this interface holds `target`.
    Resolve {
        /// The address whose hardware address the guest is asking for.
        target: IpAddress,
    },
    /// An ICMP echo request, whose answer would come back sourced from `dst`.
    Echo {
        /// The destination the guest addressed.
        dst: IpAddress,
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
            // Reassembly is not compiled in, so the interface rejects every
            // fragment. A first fragment does carry a transport header and
            // would classify on it; a later one carries the middle of a
            // datagram and would classify on whatever those bytes say. Either
            // way the state raised for it — a flow, a port socket — would serve
            // traffic that never reaches a socket.
            if packet.more_frags() || packet.frag_offset() != 0 {
                return Sniff::Other;
            }
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
        EthernetProtocol::Arp => {
            let Ok(packet) = ArpPacket::new_checked(ethernet.payload()) else {
                return Sniff::Other;
            };
            // Only a request asks the interface to speak for an address. A
            // reply is the guest answering something this stack asked for, and
            // the interface's own use for it — filling the neighbor cache —
            // asserts nothing.
            match ArpRepr::parse(&packet) {
                Ok(ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Request,
                    target_protocol_addr,
                    ..
                }) => Sniff::Resolve {
                    target: IpAddress::Ipv4(target_protocol_addr),
                },
                _ => Sniff::Other,
            }
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
                Sniff::TcpSegment { src }
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
        // An echo request is the one ICMP message the interface answers by
        // itself. Every other ICMPv6 message is left alone, neighbor discovery
        // among them: an advertisement is confined to the interface's own
        // addresses already, and a solicitation the interface ignores is how
        // the guest learns an address is nobody's.
        IpProtocol::Icmp => match Icmpv4Packet::new_checked(payload) {
            Ok(message) if message.msg_type() == Icmpv4Message::EchoRequest => Sniff::Echo { dst },
            _ => Sniff::Other,
        },
        IpProtocol::Icmpv6 => match Icmpv6Packet::new_checked(payload) {
            Ok(message) if message.msg_type() == Icmpv6Message::EchoRequest => Sniff::Echo { dst },
            _ => Sniff::Other,
        },
        _ => Sniff::Other,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
        EthernetRepr, IpAddress, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket,
        TcpRepr, TcpSeqNumber,
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

    /// Rewrites an IPv4 frame's fragmentation fields in place: the first
    /// fragment of a datagram when `offset` is zero and `more` is set, a later
    /// one otherwise. The header checksum is refilled so the frame stays
    /// well-formed.
    fn fragment(frame: &mut [u8], offset: u16, more: bool) {
        let mut ethernet = EthernetFrame::new_unchecked(frame);
        let mut packet = Ipv4Packet::new_unchecked(ethernet.payload_mut());
        packet.set_dont_frag(false);
        packet.set_more_frags(more);
        packet.set_frag_offset(offset);
        packet.fill_checksum();
    }

    #[test]
    fn a_fragmented_syn_is_not_a_connection_attempt() {
        // A first fragment does carry a complete TCP header, so it would
        // otherwise classify as a connection attempt — but reassembly is not
        // compiled in, so the interface rejects it and no socket ever sees it.
        // Acting on it would start a real host connect and hold a flow slot to
        // the establish deadline for traffic the guest cannot complete.
        let mut frame = tcp_frame(false, TcpControl::Syn, None);
        fragment(&mut frame, 0, true);
        assert_eq!(classify(&frame), Sniff::Other);
    }

    #[test]
    fn a_later_fragment_is_not_read_as_a_transport_header() {
        // A non-first fragment's payload is the middle of a datagram, not a
        // header; reading ports out of it yields whatever the bytes say.
        let mut frame = tcp_frame(false, TcpControl::Syn, None);
        fragment(&mut frame, 8, false);
        assert_eq!(classify(&frame), Sniff::Other);
    }

    #[test]
    fn an_unfragmented_syn_still_classifies() {
        // The fragmentation check must turn on the fragmentation fields alone:
        // an ordinary datagram sets neither, and clearing "don't fragment"
        // makes a packet fragmentable, not a fragment.
        let mut frame = tcp_frame(false, TcpControl::Syn, None);
        fragment(&mut frame, 0, false);
        assert!(matches!(classify(&frame), Sniff::TcpSyn { .. }));
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

    /// The guest's address in the fixtures' IPv4 frames.
    const GUEST_V4: IpAddress = IpAddress::Ipv4(Ipv4Addr::new(10, 0, 2, 15));

    #[test]
    fn a_syn_ack_is_not_a_connection_attempt() {
        // Still classified by its source, which is what holds every TCP segment
        // to the guest's own address.
        let frame = tcp_frame(false, TcpControl::Syn, Some(TcpSeqNumber(3)));
        assert_eq!(classify(&frame), Sniff::TcpSegment { src: GUEST_V4 });
    }

    #[test]
    fn a_plain_segment_is_not_a_connection_attempt() {
        let frame = tcp_frame(false, TcpControl::None, Some(TcpSeqNumber(3)));
        assert_eq!(classify(&frame), Sniff::TcpSegment { src: GUEST_V4 });
    }

    #[test]
    fn garbage_classifies_as_other() {
        assert_eq!(classify(&[]), Sniff::Other);
        assert_eq!(classify(&[0xff; 10]), Sniff::Other);
        assert_eq!(classify(&[0x00; 64]), Sniff::Other);
    }

    /// Builds an ARP frame of `operation` asking after `target`.
    fn arp_frame(operation: ArpOperation, target: Ipv4Addr) -> Vec<u8> {
        let guest = EthernetAddress([0x02, 0, 0, 0, 0, 1]);
        let arp = ArpRepr::EthernetIpv4 {
            operation,
            source_hardware_addr: guest,
            source_protocol_addr: Ipv4Addr::new(10, 0, 2, 15),
            target_hardware_addr: EthernetAddress([0; 6]),
            target_protocol_addr: target,
        };
        let ethernet = EthernetRepr {
            src_addr: guest,
            dst_addr: EthernetAddress([0xff; 6]),
            ethertype: EthernetProtocol::Arp,
        };
        let mut frame = vec![0u8; ethernet.buffer_len() + arp.buffer_len()];
        let mut eth = EthernetFrame::new_unchecked(&mut frame);
        ethernet.emit(&mut eth);
        arp.emit(&mut ArpPacket::new_unchecked(eth.payload_mut()));
        frame
    }

    #[test]
    fn an_arp_request_classifies_by_the_address_it_asks_after() {
        // What the pump needs to withhold it: an answer would assert that this
        // interface holds the target, which `any_ip` alone would make it do for
        // every address on the guest's link.
        let frame = arp_frame(ArpOperation::Request, Ipv4Addr::new(10, 0, 2, 99));
        assert_eq!(
            classify(&frame),
            Sniff::Resolve {
                target: IpAddress::Ipv4(Ipv4Addr::new(10, 0, 2, 99)),
            },
        );
    }

    #[test]
    fn an_arp_reply_asks_nothing_of_the_interface() {
        // A reply answers something this stack asked for. The interface's use
        // for it is to fill its neighbor cache, which asserts nothing, so
        // withholding one would only cost the stack a lookup it made itself.
        let frame = arp_frame(ArpOperation::Reply, Ipv4Addr::new(10, 0, 2, 2));
        assert_eq!(classify(&frame), Sniff::Other);
    }

    /// Builds an ICMP frame of `message` addressed to `dst`, in whichever
    /// family `dst` names.
    fn icmp_frame(message: u8, dst: IpAddress) -> Vec<u8> {
        // Type, code, and a zero checksum the interface would recompute; the
        // classifier reads the type alone and never verifies a checksum.
        let payload = [message, 0, 0, 0, 0, 0, 0, 0];
        let checksums = ChecksumCapabilities::default();
        let ethernet = EthernetRepr {
            src_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            dst_addr: EthernetAddress([0x02, 0, 0, 0, 0, 2]),
            ethertype: match dst {
                IpAddress::Ipv4(_) => EthernetProtocol::Ipv4,
                IpAddress::Ipv6(_) => EthernetProtocol::Ipv6,
            },
        };
        let mut frame = vec![0u8; ethernet.buffer_len() + 40 + payload.len()];
        let mut eth = EthernetFrame::new_unchecked(&mut frame);
        ethernet.emit(&mut eth);
        match dst {
            IpAddress::Ipv4(dst) => {
                let repr = Ipv4Repr {
                    src_addr: Ipv4Addr::new(10, 0, 2, 15),
                    dst_addr: dst,
                    next_header: IpProtocol::Icmp,
                    payload_len: payload.len(),
                    hop_limit: 64,
                };
                let mut packet = Ipv4Packet::new_unchecked(eth.payload_mut());
                repr.emit(&mut packet, &checksums);
                packet.payload_mut()[..payload.len()].copy_from_slice(&payload);
                frame.truncate(ethernet.buffer_len() + repr.buffer_len() + payload.len());
            }
            IpAddress::Ipv6(dst) => {
                let repr = Ipv6Repr {
                    src_addr: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x15),
                    dst_addr: dst,
                    next_header: IpProtocol::Icmpv6,
                    payload_len: payload.len(),
                    hop_limit: 64,
                };
                let mut packet = Ipv6Packet::new_unchecked(eth.payload_mut());
                repr.emit(&mut packet);
                packet.payload_mut()[..payload.len()].copy_from_slice(&payload);
            }
        }
        frame
    }

    #[test]
    fn an_echo_request_classifies_by_the_address_it_would_answer_as() {
        // The reply is sourced from the destination, so answering one for an
        // address the interface does not hold reports that address as up.
        for dst in [
            IpAddress::Ipv4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddress::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ] {
            let message = match dst {
                // Echo request: type 8 in ICMPv4, type 128 in ICMPv6.
                IpAddress::Ipv4(_) => 8,
                IpAddress::Ipv6(_) => 128,
            };
            assert_eq!(classify(&icmp_frame(message, dst)), Sniff::Echo { dst });
        }
    }

    #[test]
    fn neighbor_discovery_is_not_an_echo_request() {
        // Withholding a neighbor solicitation would break the guest's only way
        // to reach the gateway. It needs no rule of its own: smoltcp answers
        // one only for an address whose solicited-node group the interface
        // joined, which `any_ip` does not widen.
        let solicitation = 135;
        let frame = icmp_frame(
            solicitation,
            IpAddress::Ipv6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 2)),
        );
        assert_eq!(classify(&frame), Sniff::Other);
    }
}

//! The stack's reports: each decision it takes about a flow the guest opens or
//! a question it asks the stack's nameserver.
//!
//! The pump offers each one through its [`Reporter`], and the caller reads them
//! from a [`Reports`](crate::Reports) queue, which never makes the pump wait on
//! its reader (see [`crate::reports`]).

use std::fmt;
use std::net::SocketAddr;

use smoltcp::wire::IpEndpoint;

use super::dns;
use super::policy::{DestinationRule, Transport};

/// A decision the network stack took, as
/// [`NetStackHandle::take_reports`](super::NetStackHandle::take_reports) delivers it.
///
/// The stack decides each flow the guest opens toward the host: each TCP
/// connection attempt, and each UDP flow, the datagrams between one port of the
/// guest's and one destination. A flow is reported once, carried or refused. A
/// carried flow is reported when the stack starts carrying it. A refused TCP
/// attempt is answered with a reset, so the guest does not repeat it. A refused
/// UDP flow is reported at its first datagram, and again only once its
/// datagrams have stopped for as long as the stack keeps an idle flow, two
/// minutes.
///
/// Under name rules the stack also reads the server a carried TCP flow's first
/// bytes ask for, a TLS server name or an HTTP host, and holds it to the rules.
/// A flow refused there is reported a second time, refused, after the report
/// that carried it.
///
/// A flow's report names its destination's name where the stack's nameserver
/// resolved one to the destination's address: the name a name rule matched,
/// where one decided, and otherwise the name most recently resolved to it.
///
/// The stack's nameserver decides each question the guest asks it, and each
/// is reported once, as it is relayed to the host's resolver, refused, or
/// answered with no records. The guest's resolver asks again where an answer
/// is slow to come, and each time is a question of its own.
///
/// The stack's own grants are not reported: the connections a published port
/// accepts, and a connection or datagram to the nameserver, whose questions are
/// what its reports name. Nor is a flow the stack admits and cannot open on the
/// host, to a protocol the host has no route for, say: the guest's attempt is
/// reset, or its datagram dropped, as the host's own refusal would have it. Nor
/// is a question the nameserver cannot read, or cannot relay for want of room
/// or a socket.
///
/// [`Display`](fmt::Display) writes a report as one line:
///
/// ```text
/// refused tcp from 10.0.2.15:41234 to 198.51.100.7:443: no allow rule admits the address, and the stack resolved no name an allow rule admits to it
/// carried tcp from 10.0.2.15:41236 to 192.0.2.7:443 (example.com): the allow rule example.com admits it
/// refused the AAAA question for example.net from 10.0.2.15:53140: no allow rule admits it
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetStackReport {
    /// The stack carries a flow the guest opened on to the host.
    #[non_exhaustive]
    FlowAdmitted {
        /// The flow's transport.
        transport: Transport,
        /// The guest's end of the flow.
        guest: SocketAddr,
        /// The destination the guest addressed.
        destination: SocketAddr,
        /// The name the stack's nameserver resolved to the destination's
        /// address, where it resolved one, in the spelling the
        /// [question reports](Self::QuestionRelayed) use.
        name: Option<String>,
        /// What admitted the flow.
        admission: FlowAdmission,
    },
    /// The stack refuses a flow the guest opened.
    #[non_exhaustive]
    FlowRefused {
        /// The flow's transport.
        transport: Transport,
        /// The guest's end of the flow.
        guest: SocketAddr,
        /// The destination the guest addressed.
        destination: SocketAddr,
        /// The name the stack's nameserver resolved to the destination's
        /// address, where it resolved one, in the spelling the
        /// [question reports](Self::QuestionRelayed) use.
        name: Option<String>,
        /// Why the stack refuses the flow.
        refusal: FlowRefusal,
    },
    /// The stack's nameserver relays a question of the guest's to the host's
    /// resolver.
    #[non_exhaustive]
    QuestionRelayed {
        /// The guest's end of the query.
        guest: SocketAddr,
        /// The name the question asks about: its labels in lower case, joined
        /// by dots, with any byte but a letter, a digit, `-` and `_` written as
        /// a backslash and three decimal digits, as a zone file writes one. The
        /// root is `.`.
        name: String,
        /// The record type the question asks for, by its number: 1 for an
        /// IPv4 address, 28 for an IPv6 one.
        record_type: u16,
        /// What admitted the question: by default, or by the allow name rule
        /// that matches its name.
        admission: FlowAdmission,
    },
    /// The stack's nameserver refuses a question of the guest's: it answers
    /// that the name does not exist, and relays nothing.
    #[non_exhaustive]
    QuestionRefused {
        /// The guest's end of the query.
        guest: SocketAddr,
        /// The name the question asks about, spelled as
        /// [`QuestionRelayed`](Self::QuestionRelayed) spells it.
        name: String,
        /// The record type the question asks for, by its number.
        record_type: u16,
        /// Why the question is refused: no allow name rule admits its name, or
        /// a deny name rule refuses it.
        refusal: FlowRefusal,
    },
    /// The stack's nameserver answers a question of the guest's for a name's
    /// HTTPS or SVCB records with none, and relays nothing.
    ///
    /// Under name rules the stack withholds those records, which carry the keys
    /// a client encrypts its server name with, so a client names its server in
    /// the clear.
    #[non_exhaustive]
    QuestionWithheld {
        /// The guest's end of the query.
        guest: SocketAddr,
        /// The name the question asks about, spelled as
        /// [`QuestionRelayed`](Self::QuestionRelayed) spells it.
        name: String,
        /// The record type the question asks for, by its number: 64 for SVCB,
        /// 65 for HTTPS.
        record_type: u16,
    },
}

impl NetStackReport {
    /// A report that the stack carries the flow from `guest` to `destination`
    /// over `transport`, whose address the nameserver resolved `name` to.
    pub(super) fn admitted(
        transport: Transport,
        guest: IpEndpoint,
        destination: IpEndpoint,
        name: Option<&str>,
        admission: FlowAdmission,
    ) -> NetStackReport {
        NetStackReport::FlowAdmitted {
            transport,
            guest: guest.into(),
            destination: destination.into(),
            name: name.map(str::to_owned),
            admission,
        }
    }

    /// A report that the stack refuses the flow from `guest` to `destination`
    /// over `transport`, whose address the nameserver resolved `name` to.
    pub(super) fn refused(
        transport: Transport,
        guest: IpEndpoint,
        destination: IpEndpoint,
        name: Option<&str>,
        refusal: FlowRefusal,
    ) -> NetStackReport {
        NetStackReport::FlowRefused {
            transport,
            guest: guest.into(),
            destination: destination.into(),
            name: name.map(str::to_owned),
            refusal,
        }
    }

    /// A report that the nameserver relays the question from `guest` for
    /// `name`'s records of `record_type`.
    pub(super) fn relayed(
        guest: IpEndpoint,
        name: &str,
        record_type: u16,
        admission: FlowAdmission,
    ) -> NetStackReport {
        NetStackReport::QuestionRelayed {
            guest: guest.into(),
            name: name.to_owned(),
            record_type,
            admission,
        }
    }

    /// A report that the nameserver refuses the question from `guest` for
    /// `name`'s records of `record_type`.
    pub(super) fn question_refused(
        guest: IpEndpoint,
        name: &str,
        record_type: u16,
        refusal: FlowRefusal,
    ) -> NetStackReport {
        NetStackReport::QuestionRefused {
            guest: guest.into(),
            name: name.to_owned(),
            record_type,
            refusal,
        }
    }

    /// A report that the nameserver answers the question from `guest` for
    /// `name`'s records of `record_type` with none.
    pub(super) fn withheld(guest: IpEndpoint, name: &str, record_type: u16) -> NetStackReport {
        NetStackReport::QuestionWithheld {
            guest: guest.into(),
            name: name.to_owned(),
            record_type,
        }
    }

    /// Whether the report is of something the stack refused.
    ///
    /// A caller that shows refusals alone, so the command's user learns why a
    /// connection or a lookup failed, asks this rather than naming the
    /// variants, so a kind of refusal a later version reports is shown too.
    pub fn is_refusal(&self) -> bool {
        match self {
            NetStackReport::FlowAdmitted { .. }
            | NetStackReport::QuestionRelayed { .. }
            | NetStackReport::QuestionWithheld { .. } => false,
            NetStackReport::FlowRefused { .. } | NetStackReport::QuestionRefused { .. } => true,
        }
    }
}

/// A record type as a zone file writes it: its mnemonic, or `TYPE` and its
/// number for a type without one here (RFC 3597).
struct RecordType(u16);

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match dns::type_mnemonic(self.0) {
            Some(mnemonic) => f.write_str(mnemonic),
            None => write!(f, "TYPE{}", self.0),
        }
    }
}

/// A flow's destination, with the name resolved to it in parentheses where
/// there is one.
struct Destination<'a>(&'a SocketAddr, &'a Option<String>);

impl fmt::Display for Destination<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.1 {
            Some(name) => write!(f, "{} ({name})", self.0),
            None => write!(f, "{}", self.0),
        }
    }
}

impl fmt::Display for NetStackReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetStackReport::FlowAdmitted {
                transport,
                guest,
                destination,
                name,
                admission,
            } => write!(
                f,
                "carried {transport} from {guest} to {}: {admission}",
                Destination(destination, name)
            ),
            NetStackReport::FlowRefused {
                transport,
                guest,
                destination,
                name,
                refusal,
            } => write!(
                f,
                "refused {transport} from {guest} to {}: {refusal}",
                Destination(destination, name)
            ),
            NetStackReport::QuestionRelayed {
                guest,
                name,
                record_type,
                admission,
            } => write!(
                f,
                "relayed the {} question for {name} from {guest}: {admission}",
                RecordType(*record_type)
            ),
            NetStackReport::QuestionRefused {
                guest,
                name,
                record_type,
                refusal,
            } => write!(
                f,
                "refused the {} question for {name} from {guest}: {refusal}",
                RecordType(*record_type)
            ),
            NetStackReport::QuestionWithheld {
                guest,
                name,
                record_type,
            } => write!(
                f,
                "answered the {} question for {name} from {guest} with no records: the stack \
                 withholds them under name rules",
                RecordType(*record_type)
            ),
        }
    }
}

/// What admitted a flow the stack carries, carried by
/// [`NetStackReport::FlowAdmitted`].
///
/// A question the stack's nameserver relays is admitted by the same rules,
/// read for its name, and [`NetStackReport::QuestionRelayed`] carries what
/// admitted it: [`Default`](Self::Default) or [`Allowed`](Self::Allowed).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlowAdmission {
    /// The stack has no allow rule, and no deny rule matches the destination,
    /// so the stack carries it as it carries every destination it does not
    /// always refuse. Every admission of a stack without rules is this one.
    Default,
    /// An allow rule matches the destination, and no deny rule does: an
    /// address rule its address, or a name rule a name the stack's nameserver
    /// resolved to it.
    #[non_exhaustive]
    Allowed {
        /// The allow rule that admits the destination: the first address rule,
        /// in the order given, that matches its address, or where none does,
        /// the first name rule that matches a name resolved to it. A question
        /// is admitted by the first name rule that matches its name.
        rule: DestinationRule,
    },
    /// The destination is the gateway, on a port
    /// [`host_loopback`](super::NetStackBuilder::host_loopback) or
    /// [`host_loopback_port`](super::NetStackBuilder::host_loopback_port) maps
    /// to the host's loopback, which the stack carries it to. The rules do not
    /// decide the mapping.
    HostLoopback,
}

impl fmt::Display for FlowAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowAdmission::Default => f.write_str("no rule refuses it"),
            FlowAdmission::Allowed { rule } => write!(f, "the allow rule {rule} admits it"),
            FlowAdmission::HostLoopback => {
                f.write_str("the gateway's port is mapped to the host's loopback")
            }
        }
    }
}

/// Why the stack refuses a flow, carried by [`NetStackReport::FlowRefused`].
///
/// The caller's rules refuse with [`NotAllowed`](Self::NotAllowed),
/// [`Denied`](Self::Denied), the three refusals of a flow its name rules leave
/// out, and the four of a TCP flow's first bytes. Most of the rest are the
/// destinations the stack refuses under any configuration, which no rule
/// admits, and an address under NAT64's well-known prefix, `64:ff9b::/96`, that
/// the stack refuses for the IPv4 address it embeds is refused for that
/// address's reason.
///
/// A TCP flow's first bytes are read under name rules, for the server they ask
/// for: the server name of a TLS ClientHello, or the host of an HTTP/1
/// request, its `Host` header or an absolute target's. The stack forwards
/// nothing the guest sends until it has read them, and answers a refusal there
/// in the flow's own protocol before it closes the flow: a TLS alert,
/// `unrecognized_name` or `decode_error`, or an HTTP `403 Forbidden` or
/// `400 Bad Request` whose body says why.
///
/// A question the stack's nameserver refuses is refused by the same rules,
/// read for its name, and [`NetStackReport::QuestionRefused`] carries why:
/// [`NotAllowed`](Self::NotAllowed) or [`Denied`](Self::Denied).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlowRefusal {
    /// The stack has allow rules, and none of them matches the destination.
    NotAllowed,
    /// A deny rule matches the destination: an address rule its address, or a
    /// name rule its name or a name the stack's nameserver resolved to it.
    #[non_exhaustive]
    Denied {
        /// The first deny rule, in the order given, that matches.
        rule: DestinationRule,
    },
    /// A loopback address: `127.0.0.0/8` or `::1`.
    Loopback,
    /// A link-local address: `169.254.0.0/16`, where the cloud metadata
    /// services answer, or `fe80::/10`.
    LinkLocal,
    /// A multicast address.
    Multicast,
    /// The broadcast address, `255.255.255.255`.
    Broadcast,
    /// An address of IPv4's "this network" block, `0.0.0.0/8`, or IPv6's
    /// unspecified address, `::`.
    Unspecified,
    /// An IPv6 address that embeds an IPv4 one, the mapped `::ffff:a.b.c.d` or
    /// the deprecated compatible `::a.b.c.d`, which the stack refuses so an
    /// IPv4 refusal cannot be spelled in the other family.
    EmbeddedIpv4,
    /// A cloud's IPv6 instance services, where a metadata service answers the
    /// instance that asks with the instance's own credentials: AWS's block,
    /// `fd00:ec2::/32`, Google Cloud's metadata server, `fd20:ce::254`, and
    /// Oracle Cloud's, `fd00:c1::a9fe:a9fe`.
    #[non_exhaustive]
    InstanceServices {
        /// The cloud whose services they are, as its own documentation names
        /// it.
        cloud: &'static str,
    },
    /// An address of the guest's own network, other than the gateway and the
    /// stack's nameserver on port 53.
    GuestNetwork,
    /// The gateway, on a port the stack does not map to the host's loopback.
    GatewayUnmapped,
    /// The destination's protocol, IPv4 or IPv6, is turned off.
    ///
    /// [`NetStack::forwards`](super::NetStack::forwards) can answer this, and
    /// an attachment never reports it: the guest holds no address of a protocol
    /// that is off, and the stack carries nothing from any other.
    ProtocolDisabled,
    /// The stack already carries as many of the guest's flows over the
    /// transport as it holds at once: 128 TCP connections, or 256 UDP flows.
    TooManyFlows,
    /// The stack has an allow name rule, no allow rule admits the destination's
    /// address, and the stack's nameserver resolved no name to it: the guest
    /// learned the address some other way, or wrote it as a literal.
    NotResolved,
    /// An allow name rule matches a name the stack's nameserver resolved to
    /// the destination, whose address is in a private range, `10.0.0.0/8`,
    /// `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` or `fc00::/7`, or on
    /// one of the host's own networks as it stood when the stack attached: one
    /// its routing table reaches directly, or the network of one of its
    /// global IPv6 addresses. A name rule admits no such address, since a
    /// name anyone can register can be resolved to the host's own network. An
    /// address rule admits one.
    #[non_exhaustive]
    PrivateBehindName {
        /// The first allow name rule, in the order given, that matches the
        /// name.
        rule: DestinationRule,
    },
    /// An allow name rule matches a name the stack's nameserver resolved to
    /// the destination of a UDP flow. A name rule admits TCP alone, and an
    /// address rule admits UDP.
    #[non_exhaustive]
    NameOverUdp {
        /// The first allow name rule, in the order given, that matches the
        /// name.
        rule: DestinationRule,
    },
    /// The first bytes of a TCP flow an allow name rule admitted ask for a
    /// server no allow name rule admits on the flow's port: another site at an
    /// address it shares with the admitted one, say. An address the first
    /// bytes ask for, other than the flow's own destination, is refused this
    /// way too.
    #[non_exhaustive]
    ServerNameNotAllowed {
        /// The server, a name in the spelling the
        /// [question reports](NetStackReport::QuestionRelayed) use, or an
        /// address.
        name: String,
    },
    /// A deny name rule matches the server a TCP flow's first bytes ask for.
    #[non_exhaustive]
    ServerNameDenied {
        /// The server, in the spelling the
        /// [question reports](NetStackReport::QuestionRelayed) use.
        name: String,
        /// The first deny rule, in the order given, that matches it.
        rule: DestinationRule,
    },
    /// A TCP flow's first bytes began a TLS ClientHello or an HTTP request and
    /// did not finish it within ten seconds, or the guest ended its side of
    /// the flow first. A guest that sends nothing is not held to the deadline.
    ServerNameUnfinished,
    /// A TCP flow's first bytes began a TLS ClientHello or an HTTP request the
    /// stack does not read a server from: one that names several, one not
    /// whole within the stream's first 16 KiB, or one a server could read
    /// another server from than the stack would, a ClientHello carrying
    /// Encrypted Client Hello among them.
    #[non_exhaustive]
    ServerNameUnreadable {
        /// What the stack does not read, as a clause.
        reason: &'static str,
    },
}

impl fmt::Display for FlowRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowRefusal::NotAllowed => f.write_str("no allow rule admits it"),
            FlowRefusal::Denied { rule } => write!(f, "the deny rule {rule} refuses it"),
            FlowRefusal::Loopback => f.write_str("a loopback address is always refused"),
            FlowRefusal::LinkLocal => f.write_str(
                "a link-local address, where the cloud metadata services answer, is always \
                 refused",
            ),
            FlowRefusal::Multicast => f.write_str("a multicast address is always refused"),
            FlowRefusal::Broadcast => f.write_str("the broadcast address is always refused"),
            FlowRefusal::Unspecified => {
                f.write_str("an unspecified or \"this network\" address is always refused")
            }
            FlowRefusal::EmbeddedIpv4 => {
                f.write_str("an IPv6 address embedding an IPv4 one is always refused")
            }
            FlowRefusal::InstanceServices { cloud } => {
                write!(f, "{cloud}'s IPv6 instance services are always refused")
            }
            FlowRefusal::GuestNetwork => f.write_str("the sandbox's own network is always refused"),
            FlowRefusal::GatewayUnmapped => {
                f.write_str("the gateway's port is not mapped to the host's loopback")
            }
            FlowRefusal::ProtocolDisabled => f.write_str("its protocol is turned off"),
            FlowRefusal::TooManyFlows => {
                f.write_str("the stack carries as many of the sandbox's flows as it holds at once")
            }
            FlowRefusal::NotResolved => f.write_str(
                "no allow rule admits the address, and the stack resolved no name an allow rule \
                 admits to it",
            ),
            FlowRefusal::PrivateBehindName { rule } => write!(
                f,
                "the allow rule {rule} admits the name but no address behind it on a private \
                 range or the host's own network"
            ),
            FlowRefusal::NameOverUdp { rule } => {
                write!(f, "the allow rule {rule} admits the name over TCP alone")
            }
            FlowRefusal::ServerNameNotAllowed { name } => {
                write!(
                    f,
                    "its first bytes ask for {name}, which no allow rule admits"
                )
            }
            FlowRefusal::ServerNameDenied { name, rule } => write!(
                f,
                "its first bytes ask for {name}, which the deny rule {rule} refuses"
            ),
            FlowRefusal::ServerNameUnfinished => f.write_str(
                "its first bytes began a TLS handshake or an HTTP request and did not finish it \
                 within 10 seconds",
            ),
            FlowRefusal::ServerNameUnreadable { reason } => write!(
                f,
                "its first bytes began a TLS handshake or an HTTP request the stack does not \
                 read: {reason}"
            ),
        }
    }
}

/// Where the pump offers its reports.
pub(super) type Reporter = crate::reports::Reporter<NetStackReport>;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use smoltcp::wire::IpAddress;

    use super::*;

    fn endpoint(a: u8, b: u8, c: u8, d: u8, port: u16) -> IpEndpoint {
        IpEndpoint::new(IpAddress::Ipv4(Ipv4Addr::new(a, b, c, d)), port)
    }

    #[test]
    fn a_report_reads_as_one_line() {
        let rule: DestinationRule = "udp:192.0.2.0/24".parse().unwrap();
        let carried = NetStackReport::admitted(
            Transport::Udp,
            endpoint(10, 0, 2, 15, 53140),
            endpoint(192, 0, 2, 53, 53),
            None,
            FlowAdmission::Allowed { rule },
        );
        assert_eq!(
            carried.to_string(),
            "carried udp from 10.0.2.15:53140 to 192.0.2.53:53: the allow rule \
             udp:192.0.2.0/24 admits it"
        );
        assert!(!carried.is_refusal());
        let refused = NetStackReport::refused(
            Transport::Tcp,
            IpEndpoint::new(IpAddress::Ipv6("fd00::15".parse().unwrap()), 41234),
            IpEndpoint::new(IpAddress::Ipv6("2001:db8::1".parse().unwrap()), 443),
            None,
            FlowRefusal::Denied {
                rule: "[2001:db8::/32]:443".parse().unwrap(),
            },
        );
        assert_eq!(
            refused.to_string(),
            "refused tcp from [fd00::15]:41234 to [2001:db8::1]:443: the deny rule \
             [2001:db8::/32]:443 refuses it"
        );
        assert!(refused.is_refusal());
        for line in [carried.to_string(), refused.to_string()] {
            assert!(!line.contains('\n'), "{line}");
        }
    }

    #[test]
    fn a_flow_names_the_name_resolved_to_its_destination() {
        let carried = NetStackReport::admitted(
            Transport::Tcp,
            endpoint(10, 0, 2, 15, 41236),
            endpoint(192, 0, 2, 7, 443),
            Some("example.com"),
            FlowAdmission::Allowed {
                rule: "example.com".parse().unwrap(),
            },
        );
        assert_eq!(
            carried.to_string(),
            "carried tcp from 10.0.2.15:41236 to 192.0.2.7:443 (example.com): the allow rule \
             example.com admits it"
        );
        let refused = NetStackReport::refused(
            Transport::Udp,
            endpoint(10, 0, 2, 15, 41237),
            endpoint(192, 0, 2, 7, 443),
            Some("example.com"),
            FlowRefusal::NameOverUdp {
                rule: "example.com".parse().unwrap(),
            },
        );
        assert_eq!(
            refused.to_string(),
            "refused udp from 10.0.2.15:41237 to 192.0.2.7:443 (example.com): the allow rule \
             example.com admits the name over TCP alone"
        );
    }

    #[test]
    fn a_question_reads_as_one_line() {
        let guest = endpoint(10, 0, 2, 15, 53140);
        let relayed = NetStackReport::relayed(guest, "example.com", 28, FlowAdmission::Default);
        assert_eq!(
            relayed.to_string(),
            "relayed the AAAA question for example.com from 10.0.2.15:53140: no rule refuses it"
        );
        assert!(!relayed.is_refusal());
        let refused =
            NetStackReport::question_refused(guest, "example.net", 1, FlowRefusal::NotAllowed);
        assert_eq!(
            refused.to_string(),
            "refused the A question for example.net from 10.0.2.15:53140: no allow rule admits it"
        );
        assert!(refused.is_refusal());
        let withheld = NetStackReport::withheld(guest, "example.com", 65);
        assert_eq!(
            withheld.to_string(),
            "answered the HTTPS question for example.com from 10.0.2.15:53140 with no records: \
             the stack withholds them under name rules"
        );
        assert!(!withheld.is_refusal());
        // A type without a mnemonic here is written as RFC 3597 writes it.
        let unnamed = NetStackReport::relayed(guest, ".", 99, FlowAdmission::Default);
        assert!(
            unnamed
                .to_string()
                .starts_with("relayed the TYPE99 question for . from")
        );
    }

    #[test]
    fn every_reason_reads_as_one_clause() {
        let admissions = [
            FlowAdmission::Default,
            FlowAdmission::Allowed {
                rule: "192.0.2.1".parse().unwrap(),
            },
            FlowAdmission::HostLoopback,
        ];
        let refusals = [
            FlowRefusal::NotAllowed,
            FlowRefusal::Denied {
                rule: "192.0.2.1".parse().unwrap(),
            },
            FlowRefusal::Loopback,
            FlowRefusal::LinkLocal,
            FlowRefusal::Multicast,
            FlowRefusal::Broadcast,
            FlowRefusal::Unspecified,
            FlowRefusal::EmbeddedIpv4,
            FlowRefusal::InstanceServices { cloud: "AWS" },
            FlowRefusal::GuestNetwork,
            FlowRefusal::GatewayUnmapped,
            FlowRefusal::ProtocolDisabled,
            FlowRefusal::TooManyFlows,
            FlowRefusal::NotResolved,
            FlowRefusal::PrivateBehindName {
                rule: "example.com".parse().unwrap(),
            },
            FlowRefusal::NameOverUdp {
                rule: "example.com".parse().unwrap(),
            },
            FlowRefusal::ServerNameNotAllowed {
                name: "other.example".to_string(),
            },
            FlowRefusal::ServerNameDenied {
                name: "other.example".to_string(),
                rule: "*.example".parse().unwrap(),
            },
            FlowRefusal::ServerNameUnfinished,
            FlowRefusal::ServerNameUnreadable {
                reason: "it carries more than one Host header",
            },
        ];
        let clauses = admissions
            .iter()
            .map(ToString::to_string)
            .chain(refusals.iter().map(ToString::to_string));
        // Each follows a colon in a report's line, so it is a clause and not a
        // sentence of its own.
        for clause in clauses {
            assert!(!clause.ends_with('.'), "{clause}");
            assert!(!clause.contains('\n'), "{clause}");
        }
    }
}

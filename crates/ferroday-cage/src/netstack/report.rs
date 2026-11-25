//! The stack's reports: each decision it takes about a flow the guest opens,
//! delivered to the caller without the pump waiting on a reader.
//!
//! The pump offers each report through its [`Reporter`] to a queue of
//! [`QUEUED_REPORTS`], and a caller reads them from the queue's other end, a
//! [`NetStackReports`]. A report the queue has no room for is dropped and
//! counted, so a reader that falls behind, or never reads, costs reports and
//! never a flow: the pump serves every flow of the sandbox on one thread, and a
//! wait on a reader would stall them all.
//!
//! `fcage` hands its own lines to standard error the same way, through its
//! `output::Reports`. The two do not share code, since the CLI's queue is the
//! CLI's and this one is part of the library's API.

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{
    Receiver, RecvError, RecvTimeoutError, SyncSender, TryRecvError, TrySendError,
};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use smoltcp::wire::IpEndpoint;

use super::policy::{DestinationRule, Transport};

/// The most reports an attachment's queue holds for its reader before a further
/// one is dropped.
///
/// Each slot holds a pointer to its report, since the queue allocates every
/// slot when it is made: an attachment whose caller never reads its reports
/// holds those 1024 reports at most, and the empty queue costs a few kilobytes.
pub(super) const QUEUED_REPORTS: usize = 1024;

/// A decision the network stack took, as [`NetStackReports`] delivers it.
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
/// The stack's own grants are not reported: the connections a published port
/// accepts, and the guest's queries to the stack's nameserver. Nor is a flow
/// the stack admits and cannot open on the host, to a protocol the host has no
/// route for, say: the guest's attempt is reset, or its datagram dropped, as
/// the host's own refusal would have it.
///
/// [`Display`](fmt::Display) writes a report as one line:
///
/// ```text
/// refused tcp from 10.0.2.15:41234 to 198.51.100.7:443: no allow rule admits it
/// carried udp from 10.0.2.15:53140 to 192.0.2.53:53: the allow rule udp:192.0.2.0/24 admits it
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
        /// Why the stack refuses the flow.
        refusal: FlowRefusal,
    },
}

impl NetStackReport {
    /// A report that the stack carries the flow from `guest` to `destination`
    /// over `transport`.
    pub(super) fn admitted(
        transport: Transport,
        guest: IpEndpoint,
        destination: IpEndpoint,
        admission: FlowAdmission,
    ) -> NetStackReport {
        NetStackReport::FlowAdmitted {
            transport,
            guest: guest.into(),
            destination: destination.into(),
            admission,
        }
    }

    /// A report that the stack refuses the flow from `guest` to `destination`
    /// over `transport`.
    pub(super) fn refused(
        transport: Transport,
        guest: IpEndpoint,
        destination: IpEndpoint,
        refusal: FlowRefusal,
    ) -> NetStackReport {
        NetStackReport::FlowRefused {
            transport,
            guest: guest.into(),
            destination: destination.into(),
            refusal,
        }
    }

    /// Whether the report is of something the stack refused.
    ///
    /// A caller that shows refusals alone, so the command's user learns why a
    /// connection failed, asks this rather than naming the variants, so a kind
    /// of refusal a later version reports is shown too.
    pub fn is_refusal(&self) -> bool {
        match self {
            NetStackReport::FlowAdmitted { .. } => false,
            NetStackReport::FlowRefused { .. } => true,
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
                admission,
            } => write!(
                f,
                "carried {transport} from {guest} to {destination}: {admission}"
            ),
            NetStackReport::FlowRefused {
                transport,
                guest,
                destination,
                refusal,
            } => write!(
                f,
                "refused {transport} from {guest} to {destination}: {refusal}"
            ),
        }
    }
}

/// What admitted a flow the stack carries, carried by
/// [`NetStackReport::FlowAdmitted`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlowAdmission {
    /// The stack has no allow rule, and no deny rule matches the destination,
    /// so the stack carries it as it carries every destination it does not
    /// always refuse. Every admission of a stack without rules is this one.
    Default,
    /// An allow rule matches the destination, and no deny rule does.
    #[non_exhaustive]
    Allowed {
        /// The first allow rule, in the order given, that matches.
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
/// The caller's rules refuse with [`NotAllowed`](Self::NotAllowed) and
/// [`Denied`](Self::Denied). Most of the rest are the destinations the stack
/// refuses under any configuration, which no rule admits, and an address under
/// NAT64's well-known prefix, `64:ff9b::/96`, that the stack refuses for the
/// IPv4 address it embeds is refused for that address's reason.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlowRefusal {
    /// The stack has allow rules, and none of them matches the destination.
    NotAllowed,
    /// A deny rule matches the destination.
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
    /// AWS's IPv6 instance services, `fd00:ec2::/32`, the metadata service at
    /// `fd00:ec2::254` among them.
    AwsInstanceServices,
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
            FlowRefusal::AwsInstanceServices => {
                f.write_str("AWS's IPv6 instance services are always refused")
            }
            FlowRefusal::GuestNetwork => f.write_str("the sandbox's own network is always refused"),
            FlowRefusal::GatewayUnmapped => {
                f.write_str("the gateway's port is not mapped to the host's loopback")
            }
            FlowRefusal::ProtocolDisabled => f.write_str("its protocol is turned off"),
            FlowRefusal::TooManyFlows => {
                f.write_str("the stack carries as many of the sandbox's flows as it holds at once")
            }
        }
    }
}

/// The receiving end of one attachment's reports, from
/// [`NetStackHandle::take_reports`](super::NetStackHandle::take_reports).
///
/// The stack never waits on its reader. Its queue holds 1024 reports, and a
/// report it has no room for is dropped and counted, which
/// [`dropped`](Self::dropped) answers. A reader that keeps up therefore loses
/// nothing, and one that falls behind, or never reads, loses reports and
/// nothing else: every flow is carried or refused as it would have been.
///
/// The reports end once the stack has stopped and every report queued before
/// it stopped has been read: [`recv`](Self::recv) then answers [`RecvError`].
/// So a thread that reads them in a loop ends after
/// [`stop`](super::NetStackHandle::stop), or after the handle is dropped,
/// having read everything.
///
/// One reader reads at a time: a second thread's call waits for the first's to
/// return.
#[derive(Debug)]
pub struct NetStackReports {
    /// The queue's receiving end. The queue's own receiver can serve only one
    /// thread, and the lock is what lets this be shared.
    queue: Mutex<Receiver<Box<NetStackReport>>>,
    /// How many reports the queue had no room for.
    dropped: Arc<AtomicU64>,
}

impl NetStackReports {
    /// Waits for the next report.
    ///
    /// Answers [`RecvError`] once the stack has stopped and every report has
    /// been read.
    pub fn recv(&self) -> Result<NetStackReport, RecvError> {
        self.queue().recv().map(|report| *report)
    }

    /// Takes the next report, if one is waiting.
    ///
    /// Answers [`TryRecvError::Empty`] where none is, and
    /// [`TryRecvError::Disconnected`] once the stack has stopped and every
    /// report has been read.
    pub fn try_recv(&self) -> Result<NetStackReport, TryRecvError> {
        self.queue().try_recv().map(|report| *report)
    }

    /// Waits for the next report, for at most `timeout`.
    ///
    /// Answers [`RecvTimeoutError::Timeout`] where none arrived in that time,
    /// and [`RecvTimeoutError::Disconnected`] once the stack has stopped and
    /// every report has been read.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<NetStackReport, RecvTimeoutError> {
        self.queue().recv_timeout(timeout).map(|report| *report)
    }

    /// How many reports the stack has dropped so far because the queue was
    /// full.
    ///
    /// The count is final once [`recv`](Self::recv) has answered
    /// [`RecvError`], since the stack has stopped by then.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The queue, which nothing that can panic ever holds.
    fn queue(&self) -> MutexGuard<'_, Receiver<Box<NetStackReport>>> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Where the pump offers its reports: the sending end of the queue a
/// [`NetStackReports`] reads.
pub(super) struct Reporter {
    /// The queue, or `None` once its receiving end is gone, after which the
    /// pump makes no report at all.
    queue: Option<SyncSender<Box<NetStackReport>>>,
    /// How many reports the queue had no room for, which the receiving end
    /// reads.
    dropped: Arc<AtomicU64>,
}

impl Reporter {
    /// A reporter, and the receiving end of its queue, which holds
    /// [`QUEUED_REPORTS`].
    pub(super) fn new() -> (Reporter, NetStackReports) {
        Reporter::holding(QUEUED_REPORTS)
    }

    /// A reporter whose queue holds `capacity` reports, and the queue's
    /// receiving end.
    fn holding(capacity: usize) -> (Reporter, NetStackReports) {
        let (queue, received) = std::sync::mpsc::sync_channel(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        (
            Reporter {
                queue: Some(queue),
                dropped: Arc::clone(&dropped),
            },
            NetStackReports {
                queue: Mutex::new(received),
                dropped,
            },
        )
    }

    /// Offers the report `report` makes to the queue, or drops it and counts
    /// it where the queue is full. Never waits.
    ///
    /// The report is made only where its receiving end is still there to read
    /// it.
    pub(super) fn offer(&mut self, report: impl FnOnce() -> NetStackReport) {
        let Some(queue) = &self.queue else {
            return;
        };
        match queue.try_send(Box::new(report())) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => self.queue = None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use smoltcp::wire::IpAddress;

    use super::*;

    fn endpoint(a: u8, b: u8, c: u8, d: u8, port: u16) -> IpEndpoint {
        IpEndpoint::new(IpAddress::Ipv4(Ipv4Addr::new(a, b, c, d)), port)
    }

    fn refusal(index: u16) -> NetStackReport {
        NetStackReport::refused(
            Transport::Tcp,
            endpoint(10, 0, 2, 15, 40000 + index),
            endpoint(198, 51, 100, 7, 443),
            FlowRefusal::NotAllowed,
        )
    }

    #[test]
    fn a_report_reads_as_one_line() {
        let rule: DestinationRule = "udp:192.0.2.0/24".parse().unwrap();
        let carried = NetStackReport::admitted(
            Transport::Udp,
            endpoint(10, 0, 2, 15, 53140),
            endpoint(192, 0, 2, 53, 53),
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
            FlowRefusal::AwsInstanceServices,
            FlowRefusal::GuestNetwork,
            FlowRefusal::GatewayUnmapped,
            FlowRefusal::ProtocolDisabled,
            FlowRefusal::TooManyFlows,
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

    #[test]
    fn a_full_queue_drops_and_counts_and_never_waits() {
        let (mut reporter, reports) = Reporter::holding(4);
        for index in 0..10 {
            reporter.offer(|| refusal(index));
        }
        assert_eq!(reports.dropped(), 6);
        // The four the queue held are the first four, in order.
        for index in 0..4 {
            assert_eq!(reports.try_recv(), Ok(refusal(index)));
        }
        assert_eq!(reports.try_recv(), Err(TryRecvError::Empty));
        // Room again, so the next is queued.
        reporter.offer(|| refusal(10));
        assert_eq!(reports.try_recv(), Ok(refusal(10)));
        assert_eq!(reports.dropped(), 6);
    }

    #[test]
    fn the_reports_end_once_the_stack_has_stopped_and_they_are_read() {
        let (mut reporter, reports) = Reporter::holding(4);
        reporter.offer(|| refusal(0));
        drop(reporter);
        assert_eq!(reports.recv(), Ok(refusal(0)));
        assert_eq!(reports.recv(), Err(RecvError));
        assert_eq!(
            reports.recv_timeout(Duration::from_millis(10)),
            Err(RecvTimeoutError::Disconnected)
        );
        assert_eq!(reports.try_recv(), Err(TryRecvError::Disconnected));
    }

    #[test]
    fn nothing_is_made_once_the_receiving_end_is_gone() {
        let (mut reporter, reports) = Reporter::holding(4);
        drop(reports);
        // The first offer finds the receiving end gone; neither it nor any
        // later offer is counted, and no later report is made at all.
        reporter.offer(|| refusal(0));
        let mut made = false;
        reporter.offer(|| {
            made = true;
            refusal(1)
        });
        assert!(!made);
    }
}

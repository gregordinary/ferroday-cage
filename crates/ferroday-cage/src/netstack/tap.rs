//! Tap-device creation and configuration inside the sandbox's network
//! namespace.
//!
//! This module is one of the crate's two homes of `unsafe` (the other is
//! the launch mechanism). The unsafe surface here is the fork of the helper
//! process and the interface-ioctl boundary: each ioctl passes a
//! `#[repr(C)]` view of the kernel's request struct, laid out
//! field-for-field with a compile-time size assertion, and carries a SAFETY
//! comment stating the layout it relies on.
//!
//! The work happens in a forked, short-lived helper process, and the shape
//! is dictated by a kernel rule: `setns` to a network namespace demands
//! `CAP_SYS_ADMIN` in the caller's *own* user namespace as well as the
//! target's, so no thread of an unprivileged caller can join the sandbox's
//! network namespace directly — owning it is not enough. Entering the
//! sandbox's *user* namespace first acquires those capabilities (the
//! caller's user created it, which is exactly what that entry requires),
//! but the kernel refuses user-namespace entry to any multithreaded
//! process. A freshly forked child is single-threaded by construction, so
//! the helper forks, joins the user namespace and then the network
//! namespace, builds the tap, and hands the descriptor back over a
//! socketpair before exiting.
//!
//! The fork may happen while other caller threads hold locks, so the child
//! runs under the same constraints as the launch stages (see
//! [`crate::mechanism::child`]): everything it needs is marshaled before
//! the fork, and it allocates nothing, takes no locks, and never panics.
//! Failures travel back as a fixed-size step-and-errno record, and the
//! parent turns them into typed errors.
//!
//! Everything the helper opens after joining belongs to the sandbox's
//! network namespace: the tun clone device captures its namespace at open,
//! the configuration sockets act on the namespace they were created in,
//! and `/proc/sys/net` resolves against the opener's namespace.
//! Configuration runs in interface-down order first — hardware address and
//! MTU, then the sysctls that disable IPv6 duplicate address detection,
//! then the IPv4 address and netmask — and brings the interface up before
//! the pieces that need it live: the IPv4 default route (whose gateway
//! must resolve on the now-connected subnet), the IPv6 address, and the
//! IPv6 default route.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, OwnedFd};

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use rustix::ioctl;
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketFlags, SocketType,
};
use rustix::runtime::{self, Fork, How, KernelSigSet};
use rustix::thread::LinkNameSpaceType;

use super::{GUEST_MAC, NetStackError, Plan, PlanV4, PlanV6};
use crate::mechanism::frame;
use crate::mechanism::sweep_fds_keeping;
use crate::wire::wire_enum;

/// `TUNSETIFF`: create or attach to a tun/tap interface (`_IOW('T', 202, int)`).
const TUNSETIFF: ioctl::Opcode = 0x400454CA;
/// `IFF_TAP`: an Ethernet-level device, frames in and out whole.
const IFF_TAP: i16 = 0x0002;
/// `IFF_NO_PI`: no packet-information header before each frame.
const IFF_NO_PI: i16 = 0x1000;

/// `IFF_UP` from the interface flags.
const IFF_UP: i16 = 0x1;
/// `SIOCADDRT`: add a route.
const SIOCADDRT: ioctl::Opcode = 0x890B;
/// `SIOCGIFFLAGS`: read an interface's flags.
const SIOCGIFFLAGS: ioctl::Opcode = 0x8913;
/// `SIOCSIFFLAGS`: set an interface's flags.
const SIOCSIFFLAGS: ioctl::Opcode = 0x8914;
/// `SIOCSIFADDR`: set an interface's address (v4 on an `AF_INET` socket,
/// v6 — with a different request struct — on an `AF_INET6` socket).
const SIOCSIFADDR: ioctl::Opcode = 0x8916;
/// `SIOCSIFNETMASK`: set an interface's IPv4 netmask.
const SIOCSIFNETMASK: ioctl::Opcode = 0x891C;
/// `SIOCSIFMTU`: set an interface's MTU.
const SIOCSIFMTU: ioctl::Opcode = 0x8922;
/// `SIOCSIFHWADDR`: set an interface's hardware address.
const SIOCSIFHWADDR: ioctl::Opcode = 0x8924;
/// `SIOCGIFINDEX`: read an interface's index.
const SIOCGIFINDEX: ioctl::Opcode = 0x8933;

/// `ARPHRD_ETHER`: the hardware type accompanying an Ethernet MAC.
const ARPHRD_ETHER: u16 = 1;
/// `RTF_UP`: the route is usable.
const RTF_UP: u16 = 0x0001;
/// `RTF_GATEWAY`: the route's destination is reached via a gateway.
const RTF_GATEWAY: u16 = 0x0002;

/// The `accept_dad` sysctl for every interface in the namespace. The kernel
/// runs duplicate address detection unless both this and the per-interface
/// value are zero.
const DAD_ALL: &CStr = c"/proc/sys/net/ipv6/conf/all/accept_dad";

wire_enum! {
    /// The steps of the helper's work, in wire form: a failure report names the
    /// step and the errno. The explicit discriminants are the record encoding
    /// between the helper and its parent within one build; zero is reserved for
    /// the success record.
    enum Step {
        /// Close the inherited descriptors this process does not own.
        SweepFds = 1 => "closing the tap helper's inherited descriptors",
        /// Join the sandbox's user namespace.
        JoinUser = 2 => "joining the sandbox's user namespace",
        /// Join the sandbox's network namespace.
        JoinNet = 3 => "joining the sandbox's network namespace",
        /// Open `/dev/net/tun`.
        OpenTun = 4 => "opening /dev/net/tun",
        /// Create the tap interface.
        CreateTap = 5 => "creating the tap interface",
        /// Open the IPv4 configuration socket.
        OpenInet = 6 => "opening the IPv4 configuration socket",
        /// Set the hardware address.
        SetHwaddr = 7 => "setting the tap interface's hardware address",
        /// Set the MTU.
        SetMtu = 8 => "setting the tap interface's MTU",
        /// Assign the IPv4 address.
        SetV4Addr = 9 => "assigning the tap interface's IPv4 address",
        /// Set the IPv4 netmask.
        SetV4Mask = 10 => "setting the tap interface's IPv4 netmask",
        /// Read the interface flags.
        ReadFlags = 11 => "reading the tap interface's flags",
        /// Bring the interface up.
        RaiseFlags = 12 => "bringing the tap interface up",
        /// Add the IPv4 default route.
        AddV4Route = 13 => "adding the IPv4 default route",
        /// Read the interface index.
        ReadIndex = 14 => "reading the tap interface's index",
        /// Open the IPv6 configuration socket.
        OpenInet6 = 15 => "opening the IPv6 configuration socket",
        /// Assign the IPv6 address.
        SetV6Addr = 16 => "assigning the tap interface's IPv6 address",
        /// Add the IPv6 default route.
        AddV6Route = 17 => "adding the IPv6 default route",
        /// Send the tap descriptor back to the caller.
        SendTap = 18 => "sending the tap descriptor back to the caller",
    }
}

/// The interface-request views below mirror `struct ifreq`: the 16-byte
/// interface name, then one member of the request union, padded to a fixed
/// 40 bytes. That is the kernel's own size on 64-bit targets; on 32-bit ones
/// `struct ifreq` is 32 bytes and the trailing padding simply goes unread,
/// since each ioctl copies its own size and every member used here lies within
/// the first 32. What must not drift is a member's offset, which the size
/// assertions pin along with the overall layout: a mismatch has to fail the
/// build rather than misissue the ioctl.
#[repr(C)]
struct IfreqFlags {
    name: [u8; 16],
    flags: i16,
    _pad: [u8; 22],
}

/// The MTU view of `struct ifreq`.
#[repr(C)]
struct IfreqMtu {
    name: [u8; 16],
    mtu: i32,
    _pad: [u8; 20],
}

/// The interface-index view of `struct ifreq` (`SIOCGIFINDEX`).
#[repr(C)]
struct IfreqIndex {
    name: [u8; 16],
    index: i32,
    _pad: [u8; 20],
}

/// The hardware-address view of `struct ifreq`: a `struct sockaddr` whose
/// family is the ARP hardware type and whose data carries the MAC's octets.
#[repr(C)]
struct IfreqHwaddr {
    name: [u8; 16],
    family: u16,
    data: [u8; 14],
    _pad: [u8; 8],
}

/// The IPv4-address view of `struct ifreq`: an embedded `sockaddr_in`.
#[repr(C)]
struct IfreqAddrV4 {
    name: [u8; 16],
    addr: SockaddrIn,
    _pad: [u8; 8],
}

const _: () = assert!(size_of::<IfreqFlags>() == 40);
const _: () = assert!(size_of::<IfreqMtu>() == 40);
const _: () = assert!(size_of::<IfreqIndex>() == 40);
const _: () = assert!(size_of::<IfreqHwaddr>() == 40);
const _: () = assert!(size_of::<IfreqAddrV4>() == 40);

/// `struct sockaddr_in`: the IPv4 socket address the address ioctls and the
/// route request embed. Address and port are big-endian on the wire; the
/// address and route ioctls ignore the port.
#[repr(C)]
struct SockaddrIn {
    family: u16,
    port: u16,
    addr: [u8; 4],
    zero: [u8; 8],
}

const _: () = assert!(size_of::<SockaddrIn>() == 16);

impl SockaddrIn {
    /// A `sockaddr_in` holding `addr`, family `AF_INET`, port zero.
    fn new(addr: Ipv4Addr) -> Self {
        SockaddrIn {
            family: AddressFamily::INET.as_raw(),
            port: 0,
            addr: addr.octets(),
            zero: [0; 8],
        }
    }
}

/// `struct rtentry` for `SIOCADDRT`: the IPv4 route request. The `unsigned
/// long` and pointer members are held as `usize`, which matches their size
/// on both 32- and 64-bit Linux ABIs; a size assertion pins each layout.
#[repr(C)]
struct Rtentry {
    pad1: usize,
    dst: SockaddrIn,
    gateway: SockaddrIn,
    genmask: SockaddrIn,
    flags: u16,
    pad2: i16,
    pad3: usize,
    pad4: usize,
    metric: i16,
    dev: usize,
    mtu: usize,
    window: usize,
    irtt: u16,
}

#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Rtentry>() == 120);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(size_of::<Rtentry>() == 84);

/// `struct in6_ifreq` for `SIOCSIFADDR` on an `AF_INET6` socket: the
/// address, its prefix length, and the interface index.
#[repr(C)]
struct In6Ifreq {
    addr: [u8; 16],
    prefixlen: u32,
    ifindex: i32,
}

const _: () = assert!(size_of::<In6Ifreq>() == 24);

/// `struct in6_rtmsg` for `SIOCADDRT` on an `AF_INET6` socket. A zero
/// `type_` reads as unspecified, which the kernel treats as a unicast
/// route.
#[repr(C)]
struct In6Rtmsg {
    dst: [u8; 16],
    src: [u8; 16],
    gateway: [u8; 16],
    type_: u32,
    dst_len: u16,
    src_len: u16,
    metric: u32,
    info: usize,
    flags: u32,
    ifindex: i32,
}

#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<In6Rtmsg>() == 80);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(size_of::<In6Rtmsg>() == 72);

/// Everything the helper needs, marshaled before the fork so the child
/// performs no allocating or fallible preparation of its own.
struct HelperContext<'a> {
    /// The sandbox's user namespace, joined first for its capabilities.
    userns: BorrowedFd<'a>,
    /// The sandbox's network namespace, where the tap is created.
    netns: BorrowedFd<'a>,
    /// The helper's end of the result socketpair.
    sock: BorrowedFd<'a>,
    /// The interface name, NUL-padded to the ifreq field size.
    name: [u8; 16],
    /// The address and interface plan.
    plan: &'a Plan,
    /// The per-interface `accept_dad` sysctl path.
    dad_interface: &'a CStr,
}

/// Creates and configures the tap device inside the sandbox's namespaces
/// and returns its descriptor, via the forked helper described in the
/// module documentation.
pub(super) fn create(
    userns: OwnedFd,
    netns: OwnedFd,
    plan: &Plan,
) -> Result<OwnedFd, NetStackError> {
    let dad_interface = CString::new(format!(
        "/proc/sys/net/ipv6/conf/{}/accept_dad",
        plan.interface
    ))
    .expect("a validated interface name has no NUL byte");
    let (parent_sock, child_sock) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|errno| NetStackError::Spawn {
        source: errno.into(),
    })?;
    let context = HelperContext {
        userns: userns.as_fd(),
        netns: netns.as_fd(),
        sock: child_sock.as_fd(),
        name: interface_name(&plan.interface),
        plan,
        dad_interface: &dad_interface,
    };

    // SAFETY: the child branch runs only `helper`, which performs no
    // allocation, takes no locks, and ends in `exit_group` — the post-fork
    // constraints documented in `crate::mechanism::child` — and all its
    // inputs were marshaled above.
    match unsafe { runtime::kernel_fork() } {
        Err(errno) => Err(NetStackError::Spawn {
            source: errno.into(),
        }),
        Ok(Fork::Child(_)) => helper(&context),
        Ok(Fork::ParentOf(child)) => {
            // Close this process's copy of the helper's end so the helper's
            // exit hangs the socket up, then collect the result and reap.
            drop(child_sock);
            let outcome = receive_tap(&parent_sock, plan);
            let _ = crate::mechanism::wait_for_exit(child);
            outcome
        }
    }
}

/// The helper process: joins the sandbox's namespaces, builds the tap,
/// sends the descriptor back, and exits. Failures are reported as a
/// step-and-errno record; there is no one to report a reporting failure to.
fn helper(context: &HelperContext<'_>) -> ! {
    match run_helper(context) {
        Ok(()) => runtime::exit_group(0),
        Err((step, errno)) => {
            let mut record = [0u8; 8];
            record[0..4].copy_from_slice(&(step as u32).to_le_bytes());
            record[4..8].copy_from_slice(&errno.raw_os_error().to_le_bytes());
            let _ = rustix::net::send(context.sock, &record, SendFlags::NOSIGNAL);
            runtime::exit_group(127)
        }
    }
}

/// The helper's work. Returns only on failure, naming the step.
fn run_helper(context: &HelperContext<'_>) -> Result<(), (Step, Errno)> {
    // Block every signal first: the copied address space still names the
    // caller's signal handlers, which must not run here. Fatal signals
    // still kill the helper, which the parent observes as a hangup.
    // SAFETY: replacing the whole mask is safe in a fresh, single-threaded
    // child; nothing here relies on receiving signals.
    let _ = unsafe { runtime::kernel_sigprocmask(How::SETMASK, Some(&KernelSigSet::all())) };

    // Then the descriptor table, before anything that can block. `kernel_fork`
    // copied the caller's whole table into this process, and an inherited copy
    // is not inert: it holds open a concurrently live sandbox's control socket
    // (which defers the supervisor's hangup detection), a concurrently
    // allocated pseudoterminal replica (which defers end-of-file on the
    // primary), and a concurrently open map gate. The helper's life is short
    // but bounded by nothing — a namespace join, a device open, a dozen ioctls
    // and two sysctl writes — so it sweeps like every other forked child. Only
    // the three channels it was given survive.
    sweep_fds_keeping(&[
        context.userns.as_raw_fd(),
        context.netns.as_raw_fd(),
        context.sock.as_raw_fd(),
    ])
    .map_err(|errno| (Step::SweepFds, errno))?;

    rustix::thread::move_into_link_name_space(context.userns, Some(LinkNameSpaceType::User))
        .map_err(|errno| (Step::JoinUser, errno))?;
    rustix::thread::move_into_link_name_space(context.netns, Some(LinkNameSpaceType::Network))
        .map_err(|errno| (Step::JoinNet, errno))?;

    // Open the clone device only now: a tun descriptor belongs to the
    // namespace its opener was in, and TUNSETIFF creates the interface
    // there. Nonblocking, as the pump's poll loop requires.
    let tap = rustix::fs::open(
        c"/dev/net/tun",
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|errno| (Step::OpenTun, errno))?;

    let mut request = IfreqFlags {
        name: context.name,
        flags: IFF_TAP | IFF_NO_PI,
        _pad: [0; 22],
    };
    // SAFETY: TUNSETIFF reads a `struct ifreq` carrying the requested name
    // and tun flags, and writes the accepted name back; `IfreqFlags` lays
    // out the 16-byte name and the flags at the start of the union, padded
    // to the kernel's 40-byte size.
    unsafe {
        ioctl::ioctl(
            &tap,
            ioctl::Updater::<TUNSETIFF, IfreqFlags>::new(&mut request),
        )
    }
    .map_err(|errno| (Step::CreateTap, errno))?;

    let inet = rustix::net::socket_with(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|errno| (Step::OpenInet, errno))?;

    set_hardware_address(&inet, context.name).map_err(|errno| (Step::SetHwaddr, errno))?;
    set_mtu(&inet, context.name, context.plan.mtu).map_err(|errno| (Step::SetMtu, errno))?;
    if context.plan.v6.is_some() {
        disable_duplicate_address_detection(context.dad_interface);
    }
    if let Some(v4) = &context.plan.v4 {
        set_v4_address(&inet, context.name, v4.guest).map_err(|errno| (Step::SetV4Addr, errno))?;
        let mask = Ipv4Addr::from(u32::MAX << (32 - u32::from(v4.prefix_len)));
        set_v4_netmask(&inet, context.name, mask).map_err(|errno| (Step::SetV4Mask, errno))?;
    }
    bring_up(&inet, context.name)?;
    if let Some(v4) = &context.plan.v4 {
        add_v4_default_route(&inet, v4).map_err(|errno| (Step::AddV4Route, errno))?;
    }
    if let Some(v6) = &context.plan.v6 {
        let index =
            interface_index(&inet, context.name).map_err(|errno| (Step::ReadIndex, errno))?;
        let inet6 = rustix::net::socket_with(
            AddressFamily::INET6,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|errno| (Step::OpenInet6, errno))?;
        set_v6_address(&inet6, index, v6).map_err(|errno| (Step::SetV6Addr, errno))?;
        add_v6_default_route(&inet6, index, v6).map_err(|errno| (Step::AddV6Route, errno))?;
    }

    send_tap(context.sock, tap.as_fd()).map_err(|errno| (Step::SendTap, errno))
}

/// Sends the success record with the tap descriptor attached.
fn send_tap(sock: BorrowedFd<'_>, tap: BorrowedFd<'_>) -> Result<(), Errno> {
    let payload = [0u8; 8];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    let fds = [tap];
    ancillary.push(SendAncillaryMessage::ScmRights(&fds));
    frame::retry_on_intr!(rustix::net::sendmsg(
        sock,
        &[std::io::IoSlice::new(&payload)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    ))
    .map(|_| ())
}

/// Receives the helper's one record: the tap descriptor on success, a
/// step-and-errno report on failure, or a hangup if the helper died.
fn receive_tap(sock: &OwnedFd, plan: &Plan) -> Result<OwnedFd, NetStackError> {
    let mut payload = [0u8; 8];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = frame::retry_on_intr!(rustix::net::recvmsg(
        sock,
        &mut [std::io::IoSliceMut::new(&mut payload)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    ))
    .map_err(|_| NetStackError::HelperLost)?;
    if received.bytes != payload.len() {
        return Err(NetStackError::HelperLost);
    }
    let step = u32::from_le_bytes(payload[0..4].try_into().expect("four bytes"));
    let errno = i32::from_le_bytes(payload[4..8].try_into().expect("four bytes"));
    if step != 0 {
        return Err(match Step::from_wire(step) {
            Some(step) => step_error(step, errno, plan),
            None => NetStackError::HelperLost,
        });
    }
    let mut tap = None;
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(fds) = message {
            tap = fds.into_iter().next();
        }
    }
    tap.ok_or(NetStackError::HelperLost)
}

/// Maps a reported step failure onto the public error.
fn step_error(step: Step, errno: i32, plan: &Plan) -> NetStackError {
    let source = || std::io::Error::from_raw_os_error(errno);
    let configure = |detail| NetStackError::TapConfigure {
        detail,
        source: source(),
    };
    match step {
        // The helper never reached its work: it could not read its own
        // descriptor table, which is a failure to start rather than a failure
        // of the tap.
        Step::SweepFds => NetStackError::Spawn { source: source() },
        Step::JoinUser => NetStackError::NamespaceJoin {
            which: "joining the sandbox's user namespace",
            source: Some(source()),
        },
        Step::JoinNet => NetStackError::NamespaceJoin {
            which: "joining the sandbox's network namespace",
            source: Some(source()),
        },
        Step::OpenTun => NetStackError::TapOpen { source: source() },
        Step::CreateTap => NetStackError::TapCreate {
            name: plan.interface.clone(),
            source: source(),
        },
        Step::OpenInet => configure("opening the IPv4 configuration socket"),
        Step::SetHwaddr => configure("setting the hardware address"),
        Step::SetMtu => configure("setting the MTU"),
        Step::SetV4Addr => configure("assigning the IPv4 address"),
        Step::SetV4Mask => configure("setting the IPv4 netmask"),
        Step::ReadFlags => configure("reading the interface flags"),
        Step::RaiseFlags => configure("bringing the interface up"),
        Step::AddV4Route => configure("adding the IPv4 default route"),
        Step::ReadIndex => configure("reading the interface index"),
        Step::OpenInet6 => configure("opening the IPv6 configuration socket"),
        Step::SetV6Addr => configure("assigning the IPv6 address"),
        Step::AddV6Route => configure("adding the IPv6 default route"),
        // Not a configuration failure: the interface is built and working, and
        // only the handoff of its descriptor failed.
        Step::SendTap => NetStackError::TapHandoff { source: source() },
    }
}

/// The interface name as the fixed-size, NUL-padded field every request
/// carries. The name's length is validated at build time.
fn interface_name(name: &str) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    bytes
}

/// Gives the guest interface its stable MAC address.
fn set_hardware_address(inet: &OwnedFd, name: [u8; 16]) -> Result<(), Errno> {
    let mut data = [0u8; 14];
    data[..6].copy_from_slice(&GUEST_MAC);
    let request = IfreqHwaddr {
        name,
        family: ARPHRD_ETHER,
        data,
        _pad: [0; 8],
    };
    // SAFETY: SIOCSIFHWADDR reads a `struct ifreq` whose union member is a
    // `struct sockaddr` — the hardware type in `sa_family`, the MAC in the
    // first six data octets; `IfreqHwaddr` lays those fields out at the
    // kernel's offsets and size.
    unsafe {
        ioctl::ioctl(
            inet,
            ioctl::Setter::<SIOCSIFHWADDR, IfreqHwaddr>::new(request),
        )
    }
}

/// Sets the interface MTU.
fn set_mtu(inet: &OwnedFd, name: [u8; 16], mtu: u16) -> Result<(), Errno> {
    let request = IfreqMtu {
        name,
        mtu: i32::from(mtu),
        _pad: [0; 20],
    };
    // SAFETY: SIOCSIFMTU reads a `struct ifreq` whose union member is the
    // `int` MTU; `IfreqMtu` lays it out at the kernel's offset and size.
    unsafe { ioctl::ioctl(inet, ioctl::Setter::<SIOCSIFMTU, IfreqMtu>::new(request)) }
}

/// Turns off IPv6 duplicate address detection for the interface, so the
/// guest address is usable the moment the sandbox's command runs.
///
/// Best effort: the sysctls may be absent (IPv6 compiled out) or denied,
/// and detection merely delays the address by about a second, so failure
/// is not an error. The kernel runs it unless both the `all` and the
/// per-interface `accept_dad` values are zero, so both are written. The
/// writes act on the sandbox's namespace: `/proc/sys/net` resolves against
/// the network namespace of the opening process, which has joined by now.
fn disable_duplicate_address_detection(dad_interface: &CStr) {
    for path in [DAD_ALL, dad_interface] {
        if let Ok(fd) = rustix::fs::open(path, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty()) {
            let _ = rustix::io::write(&fd, b"0");
        }
    }
}

/// Assigns the guest IPv4 address.
fn set_v4_address(inet: &OwnedFd, name: [u8; 16], addr: Ipv4Addr) -> Result<(), Errno> {
    let request = IfreqAddrV4 {
        name,
        addr: SockaddrIn::new(addr),
        _pad: [0; 8],
    };
    // SAFETY: SIOCSIFADDR on an AF_INET socket reads a `struct ifreq` whose
    // union member is a `sockaddr_in`; `IfreqAddrV4` lays it out at the
    // kernel's offsets and size.
    unsafe {
        ioctl::ioctl(
            inet,
            ioctl::Setter::<SIOCSIFADDR, IfreqAddrV4>::new(request),
        )
    }
}

/// Sets the IPv4 netmask.
fn set_v4_netmask(inet: &OwnedFd, name: [u8; 16], mask: Ipv4Addr) -> Result<(), Errno> {
    let request = IfreqAddrV4 {
        name,
        addr: SockaddrIn::new(mask),
        _pad: [0; 8],
    };
    // SAFETY: SIOCSIFNETMASK reads the same `sockaddr_in` view of
    // `struct ifreq` as SIOCSIFADDR.
    unsafe {
        ioctl::ioctl(
            inet,
            ioctl::Setter::<SIOCSIFNETMASK, IfreqAddrV4>::new(request),
        )
    }
}

/// Brings the interface up, preserving its other flags.
fn bring_up(inet: &OwnedFd, name: [u8; 16]) -> Result<(), (Step, Errno)> {
    let mut request = IfreqFlags {
        name,
        flags: 0,
        _pad: [0; 22],
    };
    // SAFETY: SIOCGIFFLAGS reads and writes a `struct ifreq` with the flags
    // at the start of the union; `IfreqFlags` lays that out at the kernel's
    // offsets and size.
    unsafe {
        ioctl::ioctl(
            inet,
            ioctl::Updater::<SIOCGIFFLAGS, IfreqFlags>::new(&mut request),
        )
    }
    .map_err(|errno| (Step::ReadFlags, errno))?;
    request.flags |= IFF_UP;
    // SAFETY: SIOCSIFFLAGS reads the same `struct ifreq` layout.
    unsafe {
        ioctl::ioctl(
            inet,
            ioctl::Setter::<SIOCSIFFLAGS, IfreqFlags>::new(request),
        )
    }
    .map_err(|errno| (Step::RaiseFlags, errno))
}

/// Installs the IPv4 default route via the gateway.
///
/// Runs after the interface is up: the gateway must resolve on the
/// connected subnet the address assignment created.
fn add_v4_default_route(inet: &OwnedFd, v4: &PlanV4) -> Result<(), Errno> {
    // Start from a fully zeroed struct so the implicit alignment padding
    // between fields is defined before the ioctl copies the struct into the
    // kernel, matching the zeroed-pad convention the ifreq views use. All
    // fields are integers or `sockaddr_in` views, for which all-zero is valid.
    // SAFETY: `Rtentry` is composed entirely of integer and `#[repr(C)]`
    // integer-and-array fields, so the all-zero bit pattern is a valid value.
    let mut request: Rtentry = unsafe { std::mem::zeroed() };
    request.dst = SockaddrIn::new(Ipv4Addr::UNSPECIFIED);
    request.gateway = SockaddrIn::new(v4.gateway);
    request.genmask = SockaddrIn::new(Ipv4Addr::UNSPECIFIED);
    request.flags = RTF_UP | RTF_GATEWAY;
    // SAFETY: SIOCADDRT on an AF_INET socket reads a `struct rtentry`;
    // `Rtentry` lays out its fields — `sockaddr_in` views in the three
    // `sockaddr` slots, `usize` for the word-sized members, a null `rt_dev`
    // — at the kernel's offsets, with the size asserted above.
    unsafe { ioctl::ioctl(inet, ioctl::Setter::<SIOCADDRT, Rtentry>::new(request)) }
}

/// Reads the interface's index, which the IPv6 requests identify it by.
fn interface_index(inet: &OwnedFd, name: [u8; 16]) -> Result<i32, Errno> {
    let mut request = IfreqIndex {
        name,
        index: 0,
        _pad: [0; 20],
    };
    // SAFETY: SIOCGIFINDEX reads the name from a `struct ifreq` and writes
    // the `int` index into the union; `IfreqIndex` lays both out at the
    // kernel's offsets and size.
    unsafe {
        ioctl::ioctl(
            inet,
            ioctl::Updater::<SIOCGIFINDEX, IfreqIndex>::new(&mut request),
        )
    }?;
    Ok(request.index)
}

/// Assigns the guest IPv6 address.
fn set_v6_address(inet6: &OwnedFd, index: i32, v6: &PlanV6) -> Result<(), Errno> {
    let request = In6Ifreq {
        addr: v6.guest.octets(),
        prefixlen: u32::from(v6.prefix_len),
        ifindex: index,
    };
    // SAFETY: SIOCSIFADDR on an AF_INET6 socket reads a `struct in6_ifreq`;
    // `In6Ifreq` matches its three fields exactly, with the size asserted
    // above.
    unsafe { ioctl::ioctl(inet6, ioctl::Setter::<SIOCSIFADDR, In6Ifreq>::new(request)) }
}

/// Installs the IPv6 default route via the gateway.
///
/// Runs after the IPv6 address assignment, whose prefix route makes the
/// gateway resolvable; the interface index pins the lookup to the tap.
fn add_v6_default_route(inet6: &OwnedFd, index: i32, v6: &PlanV6) -> Result<(), Errno> {
    // Zero the whole struct first so the implicit alignment padding is defined
    // before the ioctl copies it into the kernel, as with the IPv4 route.
    // SAFETY: `In6Rtmsg` is composed entirely of integer and byte-array fields,
    // so the all-zero bit pattern is a valid value.
    let mut request: In6Rtmsg = unsafe { std::mem::zeroed() };
    request.gateway = v6.gateway.octets();
    request.flags = u32::from(RTF_UP | RTF_GATEWAY);
    request.ifindex = index;
    // SAFETY: SIOCADDRT on an AF_INET6 socket reads a `struct in6_rtmsg`;
    // `In6Rtmsg` lays out its fields — the `unsigned long` member as
    // `usize` — at the kernel's offsets, with the size asserted above.
    unsafe { ioctl::ioctl(inet6, ioctl::Setter::<SIOCADDRT, In6Rtmsg>::new(request)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every step decodes back to itself, and every step names itself in prose.
    ///
    /// The round trip is structural now — the decoder's match arms are the same
    /// literals the variants are declared with, so a value used twice is a
    /// duplicate discriminant and a duplicate pattern, both of which the
    /// compiler refuses. What this still checks is that the list of steps and
    /// the encoding agree about which values exist, and that no step was left
    /// without a description.
    #[test]
    fn step_wire_round_trip() {
        for &step in Step::ALL {
            assert_eq!(Step::from_wire(step.wire()), Some(step));
            assert!(!step.describe().is_empty(), "{step:?} describes itself");
        }
    }

    /// Zero is the success record, and nothing past the last step is a step.
    #[test]
    fn unknown_wire_values_are_rejected() {
        assert_eq!(Step::from_wire(0), None);
        assert_eq!(Step::from_wire(Step::past_the_last()), None);
        assert_eq!(Step::from_wire(u32::MAX), None);
    }
}

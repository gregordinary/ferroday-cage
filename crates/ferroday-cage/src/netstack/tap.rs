//! Tap-device creation and configuration inside the sandbox's network
//! namespace.
//!
//! This module is one of the crate's three homes of `unsafe`; the others are
//! the launch mechanism and the terminal relay's signals. The unsafe surface
//! here is the interface-ioctl boundary, and the call that runs this module's
//! configuration on the helper process: each ioctl passes a `#[repr(C)]` view
//! of the kernel's request struct, laid out field-for-field with a
//! compile-time size assertion, and carries a SAFETY comment stating the layout
//! it relies on.
//!
//! The work happens on the forked, short-lived helper that
//! [`mechanism::netns`](crate::mechanism::netns) runs in the sandbox's network
//! namespace, which explains why a helper is needed. The helper's
//! configuration therefore runs under the same constraints as the launch
//! stages (see [`crate::mechanism::child`]): everything it needs is marshaled
//! before the fork, and it allocates nothing, takes no locks, and never panics.
//! Failures travel back as a step-and-errno record, and the parent turns them
//! into typed errors.
//!
//! Configuration runs in interface-down order first — hardware address and
//! MTU, then the sysctls that disable IPv6 duplicate address detection,
//! then the IPv4 address and netmask — and brings the interface up before
//! the pieces that need it live: the IPv4 default route (whose gateway
//! must resolve on the now-connected subnet), the IPv6 address, and the
//! IPv6 default route.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use rustix::ioctl;
use rustix::net::{AddressFamily, SocketFlags, SocketType};

use super::{GUEST_MAC, NetStackError, Plan, PlanV4, PlanV6};
use crate::mechanism::netns::{self, HelperFailure, JoinSteps, Namespaces};
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
    /// between the helper and its parent within one build.
    ///
    /// A configuration step's phrase is what [`NetStackError::TapConfigure`]
    /// carries as its `detail`, and a namespace join's what
    /// [`NetStackError::NamespaceJoin`] carries as its `which`, so each reads
    /// after the words those errors render it behind. The other steps fail as
    /// errors of their own, whose phrases name nothing further.
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
        SetHwaddr = 7 => "setting the hardware address",
        /// Set the MTU.
        SetMtu = 8 => "setting the MTU",
        /// Assign the IPv4 address.
        SetV4Addr = 9 => "assigning the IPv4 address",
        /// Set the IPv4 netmask.
        SetV4Mask = 10 => "setting the IPv4 netmask",
        /// Read the interface flags.
        ReadFlags = 11 => "reading the interface flags",
        /// Bring the interface up.
        RaiseFlags = 12 => "bringing the interface up",
        /// Add the IPv4 default route.
        AddV4Route = 13 => "adding the IPv4 default route",
        /// Read the interface index.
        ReadIndex = 14 => "reading the interface index",
        /// Open the IPv6 configuration socket.
        OpenInet6 = 15 => "opening the IPv6 configuration socket",
        /// Assign the IPv6 address.
        SetV6Addr = 16 => "assigning the IPv6 address",
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

/// Everything the helper's configuration needs, marshaled before the fork so
/// the helper performs no allocating or fallible preparation of its own.
struct HelperContext<'a> {
    /// The interface name, NUL-padded to the ifreq field size.
    name: [u8; 16],
    /// The address and interface plan.
    plan: &'a Plan,
    /// The per-interface `accept_dad` sysctl path.
    dad_interface: &'a CStr,
}

/// Creates and configures the tap device inside the sandbox's namespaces
/// and returns its descriptor, on the helper [`netns`] runs there.
pub(super) fn create(namespaces: &Namespaces, plan: &Plan) -> Result<OwnedFd, NetStackError> {
    let dad_interface = CString::new(format!(
        "/proc/sys/net/ipv6/conf/{}/accept_dad",
        plan.interface
    ))
    .expect("a validated interface name has no NUL byte");
    let context = HelperContext {
        name: interface_name(&plan.interface),
        plan,
        dad_interface: &dad_interface,
    };
    let steps = JoinSteps {
        sweep_fds: Step::SweepFds.wire(),
        join_user: Step::JoinUser.wire(),
        join_net: Step::JoinNet.wire(),
        send: Step::SendTap.wire(),
    };

    // SAFETY: `build_tap` makes raw syscalls and ioctls over the context
    // marshaled above, opening only what it creates itself once the helper has
    // joined; it performs no allocation, takes no locks, and cannot panic.
    let made = unsafe {
        netns::in_network_namespace(namespaces, &steps, || {
            build_tap(&context).map_err(|(step, errno)| (step.wire(), errno))
        })
    };
    made.map_err(|failure| match failure {
        HelperFailure::Spawn(errno) => NetStackError::Spawn {
            source: errno.into(),
        },
        HelperFailure::Step { wire, errno } => match Step::from_wire(wire) {
            Some(step) => step_error(step, errno.raw_os_error(), plan),
            None => NetStackError::HelperLost,
        },
        HelperFailure::Lost => NetStackError::HelperLost,
    })
}

/// The helper's configuration, in the sandbox's network namespace: creates
/// the tap, configures it, and returns its descriptor, or the step it failed
/// at.
fn build_tap(context: &HelperContext<'_>) -> Result<OwnedFd, (Step, Errno)> {
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

    Ok(tap)
}

/// Maps a reported step failure onto the public error.
fn step_error(step: Step, errno: i32, plan: &Plan) -> NetStackError {
    let source = || std::io::Error::from_raw_os_error(errno);
    match step {
        // The helper never reached its work: it could not read its own
        // descriptor table, which is a failure to start rather than a failure
        // of the tap.
        Step::SweepFds => NetStackError::Spawn { source: source() },
        Step::JoinUser | Step::JoinNet => NetStackError::NamespaceJoin {
            which: step.describe(),
            source: Some(source()),
        },
        Step::OpenTun => NetStackError::TapOpen { source: source() },
        Step::CreateTap => NetStackError::TapCreate {
            name: plan.interface.clone(),
            source: source(),
        },
        Step::OpenInet
        | Step::SetHwaddr
        | Step::SetMtu
        | Step::SetV4Addr
        | Step::SetV4Mask
        | Step::ReadFlags
        | Step::RaiseFlags
        | Step::AddV4Route
        | Step::ReadIndex
        | Step::OpenInet6
        | Step::SetV6Addr
        | Step::AddV6Route => NetStackError::TapConfigure {
            detail: step.describe(),
            source: source(),
        },
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

    /// Neither zero nor the success record is a step, and nothing past the
    /// last step is one either.
    #[test]
    fn unknown_wire_values_are_rejected() {
        assert_eq!(Step::from_wire(0), None);
        assert_eq!(Step::from_wire(crate::mechanism::frame::RECORD_DONE), None);
        assert_eq!(Step::from_wire(Step::past_the_last()), None);
        assert_eq!(Step::from_wire(u32::MAX), None);
    }
}

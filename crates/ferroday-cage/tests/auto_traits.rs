//! Auto-trait assertions for the public API.
//!
//! `Send` and `Sync` are part of a type's public contract, inferred from its
//! private fields, so an internal change can withdraw one with no error in this
//! crate and no diagnostic from a semver checker. These assertions pin what
//! each public type is, from outside the crate, exactly as a consumer sees it.
//!
//! The checks are `const`, so this file proves its claims at compile time; the
//! test body exists only so a failure is reported as a failing test rather than
//! a bare build error.
//!
//! Types that deliberately are *not* `Send` or `Sync` are recorded at the
//! bottom with the reason. Losing an auto trait is a breaking change; gaining
//! one is not, so those are documented rather than asserted — there is no
//! stable way to assert an auto trait's absence, and nothing would be protected
//! by doing so.

#![allow(dead_code)]

const fn assert_send<T: Send>() {}
const fn assert_sync<T: Sync>() {}
const fn assert_send_sync<T: Send + Sync>() {}
const fn assert_unpin<T: Unpin>() {}

// ---------------------------------------------------------------------------
// The core sandbox surface.
// ---------------------------------------------------------------------------

const _: () = assert_send_sync::<ferroday_cage::Cage>();
const _: () = assert_send_sync::<ferroday_cage::CageBuilder>();
const _: () = assert_send_sync::<ferroday_cage::Network>();
const _: () = assert_send_sync::<ferroday_cage::Overlay>();
const _: () = assert_send_sync::<ferroday_cage::Bind>();
const _: () = assert_send_sync::<ferroday_cage::Mount>();
const _: () = assert_send_sync::<ferroday_cage::RawMount>();
const _: () = assert_send_sync::<ferroday_cage::ResolvedInputs>();
const _: () = assert_send_sync::<ferroday_cage::ResolvedMount>();
const _: () = assert_send_sync::<ferroday_cage::ResolvedStreams>();
const _: () = assert_send_sync::<ferroday_cage::ResolvedStdio>();
const _: () = assert_send_sync::<ferroday_cage::Stdio>();
// A terminal launch hands back a live descriptor whose whole point is being
// driven from a second thread: a reader beside the wait, a resize beside both.
const _: () = assert_send_sync::<ferroday_cage::Terminal>();
const _: () = assert_send_sync::<ferroday_cage::Pty>();
const _: () = assert_send_sync::<ferroday_cage::ExitStatus>();
const _: () = assert_send_sync::<ferroday_cage::KillHandle>();

// Errors cross thread boundaries constantly — a worker returning one to a
// coordinator is the ordinary case — so every error type is `Send + Sync`.
const _: () = assert_send_sync::<ferroday_cage::Error>();
const _: () = assert_send_sync::<ferroday_cage::ConfigError>();
const _: () = assert_send_sync::<ferroday_cage::SetupStep>();
const _: () = assert_send_sync::<ferroday_cage::OverlayLayer>();
const _: () = assert_send_sync::<ferroday_cage::IdMapError>();

// Observability values.
const _: () = assert_send_sync::<ferroday_cage::Progress>();

// Identity.
const _: () = assert_send_sync::<ferroday_cage::Identity>();
const _: () = assert_send_sync::<ferroday_cage::IdRange>();
const _: () = assert_send_sync::<ferroday_cage::IdentityMap>();
const _: () = assert_send_sync::<ferroday_cage::ResolvedMap>();
const _: () = assert_send_sync::<ferroday_cage::DirectMapper>();
#[cfg(feature = "subid")]
const _: () = assert_send_sync::<ferroday_cage::SubidMapper>();

// The terminal relay. Every one of these holds descriptors, flags, and
// instants and nothing that is neither, so a program that builds a session on
// one thread and drives it on another is not stopped by the types.
const _: () = assert_send_sync::<ferroday_cage::relay::Relay<'_>>();
const _: () = assert_send_sync::<ferroday_cage::relay::Signals>();
const _: () = assert_send_sync::<ferroday_cage::relay::Escalation>();
const _: () = assert_send_sync::<ferroday_cage::relay::RelayError>();

// Host probes.
const _: () = assert_send_sync::<ferroday_cage::host::UsernsBlocker>();
const _: () = assert_send_sync::<ferroday_cage::host::RangeMapBlocker>();
const _: () = assert_send_sync::<ferroday_cage::host::OverlayBlocker>();

// ---------------------------------------------------------------------------
// Provisioning.
// ---------------------------------------------------------------------------

const _: () = assert_send_sync::<ferroday_cage::provision::Provisioned>();
const _: () = assert_send_sync::<ferroday_cage::provision::ProvisionError>();
const _: () = assert_send_sync::<ferroday_cage::provision::Remove<'_>>();
#[cfg(feature = "tarball")]
const _: () = assert_send_sync::<ferroday_cage::provision::Export<'_>>();
// The entry an export's filter is offered, and what it says the entry is. Both
// are plain data over a borrowed path, and `Export` above stays `Send + Sync`
// only because the predicate it holds is required to be, so these are the pair
// that would have to move for that bound to become questionable.
#[cfg(feature = "tarball")]
const _: () = assert_send_sync::<ferroday_cage::provision::ExportEntry<'_>>();
#[cfg(feature = "tarball")]
const _: () = assert_send_sync::<ferroday_cage::provision::ExportKind>();

// `Tarball::from_reader` stores its source, so the stored seam carries the
// `Send` bound the crate's rule asks of a stored seam. It is not `Sync`: a
// `Box<dyn Read + Send>` is not, and nothing would use one if it were, because
// provisioning takes `&mut self` — the same shape as `Debian` below.
#[cfg(feature = "tarball")]
const _: () = assert_send::<ferroday_cage::provision::Tarball>();

// ---------------------------------------------------------------------------
// What every userland provisioner shares: the transport seam, the overlay upper
// a layered build stages into, and the stream an in-cage command's output is
// attributed to.
// ---------------------------------------------------------------------------

#[cfg(any(feature = "debian", feature = "alpine"))]
mod shared {
    use ferroday_cage::provision::{BuildLayer, FetchError, FetchRequest, HttpFetch, Stream};

    use super::*;

    const _: () = assert_send_sync::<FetchError>();
    const _: () = assert_send_sync::<FetchRequest<'_>>();
    const _: () = assert_send_sync::<HttpFetch>();
    const _: () = assert_send_sync::<BuildLayer>();
    const _: () = assert_send_sync::<Stream>();
}

// ---------------------------------------------------------------------------
// The Debian provisioner.
// ---------------------------------------------------------------------------

#[cfg(feature = "debian")]
mod debian {
    use ferroday_cage::provision::debian;

    use super::*;

    const _: () = assert_send_sync::<debian::DebianError>();
    const _: () = assert_send_sync::<debian::Plan>();
    const _: () = assert_send_sync::<debian::PlannedPackage>();
    const _: () = assert_send_sync::<debian::Priority>();
    const _: () = assert_send_sync::<debian::Repository>();
    const _: () = assert_send_sync::<debian::RepositoryBuilder>();
    const _: () = assert_send_sync::<debian::Pool>();
    const _: () = assert_send_sync::<debian::DebianEvent<'_>>();

    // `Fetch` requires `Send` so that a provisioner, which owns its transport,
    // can be built on one thread and run on another. Neither is `Sync`: a
    // `Box<dyn Fetch + Send>` is not, and nothing would use one if it were,
    // because every operation on a `Debian` takes `&mut self`.
    const _: () = assert_send::<debian::Debian<'_>>();
    const _: () = assert_send::<debian::DebianBuilder<'_>>();
}

// ---------------------------------------------------------------------------
// The Alpine provisioner.
// ---------------------------------------------------------------------------

#[cfg(feature = "alpine")]
mod alpine {
    use ferroday_cage::provision::alpine;

    use super::*;

    const _: () = assert_send_sync::<alpine::AlpineError>();
    const _: () = assert_send_sync::<alpine::Available>();
    const _: () = assert_send_sync::<alpine::KeySet>();
    const _: () = assert_send_sync::<alpine::Repository>();
    const _: () = assert_send_sync::<alpine::RepositoryBuilder>();

    // Send and not Sync, for the reason the Debian provisioner is: the
    // provisioner owns its transport, and every operation on it takes
    // `&mut self`.
    const _: () = assert_send::<alpine::Alpine>();
    const _: () = assert_send::<alpine::AlpineBuilder>();
}

// ---------------------------------------------------------------------------
// The Gentoo provisioner.
// ---------------------------------------------------------------------------

#[cfg(feature = "gentoo")]
mod gentoo {
    use ferroday_cage::provision::gentoo;

    use super::*;

    const _: () = assert_send_sync::<gentoo::CertificateHorizon>();
    const _: () = assert_send_sync::<gentoo::GentooError>();
    const _: () = assert_send_sync::<gentoo::Stage3>();
    const _: () = assert_send_sync::<gentoo::Available>();
    const _: () = assert_send_sync::<gentoo::Catalogue>();
    const _: () = assert_send_sync::<gentoo::Installed>();
    const _: () = assert_send_sync::<gentoo::InstalledPackage>();
    const _: () = assert_send_sync::<gentoo::Plan>();
    const _: () = assert_send_sync::<gentoo::PlannedPackage>();
    // The Gentoo layer stages a build layer as the other two do, and its
    // handle is the shared one -- but `Stream` is not shared with it, since
    // nothing runs in a cage during a Gentoo bootstrap, so the assertion sits
    // here rather than in the block above.
    const _: () = assert_send_sync::<ferroday_cage::provision::BuildLayer>();

    // Send and not Sync, for the reason the Debian and Alpine provisioners
    // are: the provisioner owns its transport, and every operation that uses
    // one takes `&mut self`.
    const _: () = assert_send::<gentoo::Gentoo>();
    const _: () = assert_send::<gentoo::GentooBuilder>();
}

// ---------------------------------------------------------------------------
// Hardening.
// ---------------------------------------------------------------------------

#[cfg(feature = "hardening")]
mod hardening {
    use ferroday_cage as hardening;

    use super::*;

    const _: () = assert_send_sync::<hardening::Restriction>();
    const _: () = assert_send_sync::<hardening::RestrictionBuilder>();
    const _: () = assert_send_sync::<hardening::Capability>();
    const _: () = assert_send_sync::<hardening::FsAccess>();
    const _: () = assert_send_sync::<hardening::NetAccess>();
    const _: () = assert_send_sync::<hardening::SeccompAction>();
    const _: () = assert_send_sync::<hardening::SeccompArg>();
    const _: () = assert_send_sync::<hardening::SeccompArgLen>();
    const _: () = assert_send_sync::<hardening::SeccompCompare>();
    const _: () = assert_send_sync::<hardening::SeccompPolicy>();
    const _: () = assert_send_sync::<hardening::SeccompRules>();
    const _: () = assert_send_sync::<hardening::SockFilter>();
    const _: () = assert_send_sync::<hardening::ParseCapabilityError>();
    const _: () = assert_send_sync::<hardening::ParseFsAccessError>();
    const _: () = assert_send_sync::<hardening::ParseNetAccessError>();
}

// ---------------------------------------------------------------------------
// The native network stack.
// ---------------------------------------------------------------------------

#[cfg(feature = "netstack")]
mod netstack {
    use ferroday_cage as netstack;

    use super::*;

    const _: () = assert_send_sync::<netstack::NetStack>();
    const _: () = assert_send_sync::<netstack::NetStackBuilder>();
    const _: () = assert_send_sync::<netstack::NetStackError>();
    const _: () = assert_send_sync::<netstack::NetStackHandle>();
}

// ---------------------------------------------------------------------------
// Profiles.
// ---------------------------------------------------------------------------

#[cfg(feature = "serde")]
const _: () = assert_send_sync::<ferroday_cage::RestrictedProfile>();

// ---------------------------------------------------------------------------
// Deliberately neither `Send` nor `Sync`.
// ---------------------------------------------------------------------------
//
// - `Running<'obs>` and `Pending<'obs>` borrow a `&mut dyn Observer`, which
//   carries no thread bounds: the library delivers output on the caller's own
//   thread from inside the blocking wait, so the handle stays where it was
//   created. `KillHandle` is the piece that does cross threads, and is asserted
//   `Send + Sync` above.
//
// - `Observed<'o, 'a>` borrows a `&mut dyn FnMut` progress sink, for the same
//   reason: it lives only for the duration of the call it decorates.
//
// - `Provision<'obs>` and `ProvisionRequest<'a>` borrow a
//   `&mut dyn ProvisionObserver`, again for one call: the observer is called on
//   the provisioning thread, and the request exists only for the duration of
//   `Provisioner::provision`.
//
// The rule the crate follows is that a seam it *stores* carries thread bounds
// and a seam it merely *borrows* for one call does not. `Fetch` and `IdMapper`
// are stored, and are bounded; `Observer` and the progress sink are borrowed,
// and are not.
//
// A consumer that needs one of these across a thread boundary moves the inputs
// instead and constructs the value on the far side; `Cage`, asserted above, is
// `Send + Sync` precisely so a launch plan can be shared or moved freely.

#[test]
fn the_public_api_keeps_its_auto_traits() {
    // Every assertion above is a `const` item, so reaching this point means the
    // crate compiled with the auto-trait contract intact.
}

//! The identity map a provisioning child works inside.
//!
//! Three operations fork a child into a user namespace to touch a tree at the
//! ownership that tree intends: the export, the copy in, and the map-assisted
//! removal. Each has to answer the same question before the fork — who
//! establishes the map, and over what extents — and the answer is policy
//! rather than mechanism: the single-identity map is written by the child
//! itself under the kernel's one-id exception, and any range map is applied
//! from outside by a delegate, which is the caller's when one was supplied and
//! the bundled chain's otherwise.
//!
//! The answer is composed here so the three agree on it. What differs between
//! them is only the error each reports, so the failure leaves as the reason
//! text and each caller wraps it in its own variant.

use std::sync::Arc;

use crate::IdentityMap;
use crate::idmap::{IdMapper, ResolvedMap};
use crate::mechanism::ChildMap;

/// A resolved range-map delegate: the mapper that applies the map, and the
/// extents it resolved.
///
/// Held by the caller across the fork because a [`ChildMap`] borrows both. A
/// bundled delegate is owned here, since nothing else holds it.
pub(super) struct ResolvedDelegate<'a> {
    /// Where the mapper came from.
    source: Source<'a>,
    /// The extents the mapper resolved.
    map: ResolvedMap,
}

/// Where a [`ResolvedDelegate`]'s mapper came from, which decides whether this
/// holds it or borrows it.
enum Source<'a> {
    /// The caller supplied it.
    Caller(&'a dyn IdMapper),
    /// It came from the bundled chain, resolved here.
    Bundled(Arc<dyn IdMapper>),
}

impl ResolvedDelegate<'_> {
    /// The delegate that applies the map.
    fn mapper(&self) -> &dyn IdMapper {
        match &self.source {
            Source::Caller(mapper) => *mapper,
            Source::Bundled(mapper) => mapper.as_ref(),
        }
    }

    /// The extents to write.
    fn map(&self) -> &ResolvedMap {
        &self.map
    }
}

/// The child's identity map, together with the storage a [`ChildMap`] borrows
/// from: the formatted map lines, or the delegate and its extents.
pub(super) enum ChildMapSource<'a> {
    /// The single-identity map, which the child writes itself.
    SelfMap {
        /// The `uid_map` line.
        uid_line: Vec<u8>,
        /// The `gid_map` line.
        gid_line: Vec<u8>,
    },
    /// A range map, applied from outside by the delegate.
    Delegated(ResolvedDelegate<'a>),
}

impl ChildMapSource<'_> {
    /// The map to hand the child, borrowed from this.
    pub(super) fn child_map(&self) -> ChildMap<'_> {
        match self {
            ChildMapSource::SelfMap { uid_line, gid_line } => {
                ChildMap::SelfMap { uid_line, gid_line }
            }
            ChildMapSource::Delegated(delegate) => ChildMap::Delegated {
                mapper: delegate.mapper(),
                map: delegate.map(),
            },
        }
    }
}

/// Composes the child's map: the single map it writes itself, a range map a
/// delegate applies.
///
/// The self-map lines are formatted here, before the fork, as a launch formats
/// its own: the child allocates nothing.
///
/// The error is the reason the range map could not be resolved, for the caller
/// to wrap in the error its own operation reports.
pub(super) fn compose_child_map<'a>(
    map: &IdentityMap,
    mapper: Option<&'a dyn IdMapper>,
) -> Result<ChildMapSource<'a>, String> {
    match map {
        IdentityMap::Single => {
            let euid = rustix::process::geteuid().as_raw();
            let egid = rustix::process::getegid().as_raw();
            Ok(ChildMapSource::SelfMap {
                uid_line: format!("0 {euid} 1\n").into_bytes(),
                gid_line: format!("0 {egid} 1\n").into_bytes(),
            })
        }
        IdentityMap::Ranges { .. } | IdentityMap::Subordinate => {
            resolve_delegate(map, mapper).map(ChildMapSource::Delegated)
        }
    }
}

/// Resolves the delegate a range map is applied through: the caller's mapper
/// when one was supplied, and the bundled chain otherwise.
///
/// The error is the reason no delegate could satisfy the request — for the
/// bundled chain, every candidate's refusal in turn.
fn resolve_delegate<'a>(
    map: &IdentityMap,
    mapper: Option<&'a dyn IdMapper>,
) -> Result<ResolvedDelegate<'a>, String> {
    match mapper {
        Some(mapper) => {
            let resolved = mapper.resolve(map).map_err(|err| err.to_string())?;
            Ok(ResolvedDelegate {
                source: Source::Caller(mapper),
                map: resolved,
            })
        }
        None => {
            let (mapper, resolved) = crate::idmap::resolve_default_chain(map)?;
            Ok(ResolvedDelegate {
                source: Source::Bundled(mapper),
                map: resolved,
            })
        }
    }
}

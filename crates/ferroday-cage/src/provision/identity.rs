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
use crate::error::ConfigError;
use crate::failure::ErrorChain;
use crate::idmap::{IdMapper, ResolvedMap};
use crate::mechanism::ChildMap;

/// A resolved range-map delegate: the mapper that applies the map, and the
/// extents it resolved.
///
/// Held by the caller across the fork because a [`ChildMap`] borrows both.
pub(super) struct ResolvedDelegate {
    /// The delegate that applies the map: the caller's, or the bundled one that
    /// accepted the request.
    mapper: Arc<dyn IdMapper>,
    /// The extents the mapper resolved.
    map: ResolvedMap,
}

/// The child's identity map, together with the storage a [`ChildMap`] borrows
/// from: the formatted map lines, or the delegate and its extents.
pub(super) enum ChildMapSource {
    /// The single-identity map, which the child writes itself.
    SelfMap {
        /// The `uid_map` line.
        uid_line: Vec<u8>,
        /// The `gid_map` line.
        gid_line: Vec<u8>,
    },
    /// A range map, applied from outside by the delegate.
    Delegated(ResolvedDelegate),
}

impl ChildMapSource {
    /// The map to hand the child, borrowed from this.
    pub(super) fn child_map(&self) -> ChildMap<'_> {
        match self {
            ChildMapSource::SelfMap { uid_line, gid_line } => {
                ChildMap::SelfMap { uid_line, gid_line }
            }
            ChildMapSource::Delegated(delegate) => ChildMap::Delegated {
                mapper: delegate.mapper.as_ref(),
                map: &delegate.map,
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
pub(super) fn compose_child_map(
    map: &IdentityMap,
    mapper: Option<&Arc<dyn IdMapper>>,
) -> Result<ChildMapSource, String> {
    match map {
        IdentityMap::Single => {
            let (uid_line, gid_line) = crate::idmap::single_identity_lines();
            Ok(ChildMapSource::SelfMap { uid_line, gid_line })
        }
        IdentityMap::Ranges { .. } | IdentityMap::Subordinate => {
            // The step a build resolves its own range map with, so a malformed
            // request, or a malformed map from the delegate, is refused here by
            // name rather than reaching the kernel as an `EINVAL` at the write.
            // The caller's own error already says no delegate could establish
            // the map, so a refusal contributes its reason alone; an invalid
            // map says so.
            let (mapper, map) =
                crate::idmap::resolve_delegate(map, mapper).map_err(|err| match err {
                    ConfigError::IdentityMapUnavailable { reason, .. } => reason,
                    other => ErrorChain::new(&other).to_string(),
                })?;
            Ok(ChildMapSource::Delegated(ResolvedDelegate { mapper, map }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idmap::{IdMapError, IdRange};

    /// A delegate that would resolve any request to one valid map.
    #[derive(Debug)]
    struct Obliging;

    impl IdMapper for Obliging {
        fn resolve(&self, _request: &IdentityMap) -> Result<ResolvedMap, IdMapError> {
            let root = IdRange {
                inside: 0,
                outside: 1000,
                count: 1,
            };
            Ok(ResolvedMap::new(vec![root], vec![root]))
        }

        fn apply(&self, _pid: u32, _map: &ResolvedMap) -> Result<(), IdMapError> {
            Ok(())
        }
    }

    #[test]
    fn a_provisioning_child_map_is_validated_as_a_build_is() {
        // An export, a copy in, and a removal compose their map here, and a
        // malformed request is refused by name before a delegate is asked,
        // rather than reaching the kernel as an EINVAL at the write.
        let malformed = IdentityMap::ranges(Vec::new(), Vec::new());
        let obliging: Arc<dyn IdMapper> = Arc::new(Obliging);
        let reason = match compose_child_map(&malformed, Some(&obliging)) {
            Err(reason) => reason,
            Ok(_) => panic!("a malformed request is refused"),
        };
        assert!(reason.contains("the identity map is invalid"), "{reason}");
    }
}

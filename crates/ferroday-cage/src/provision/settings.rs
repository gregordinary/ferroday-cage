//! What a builder checks of its settings that the Debian and Alpine builders
//! check the same way: the architecture a build is for, the date it is stamped
//! with, and the settings a plan already decides.
//!
//! Each answer is a reason a builder wraps in its own configuration failure,
//! so the rule and its wording are stated once and each layer still says whose
//! configuration was refused.

use std::collections::HashMap;

use super::coordinate::{self, Nesting};

/// The architecture a build is for: the one the caller `named`, else the one
/// the plan or the pin it was given `stated`, else the `host`'s.
///
/// A plan states which architecture it is for, so a builder that names none
/// adopts it: refusing a plan the caller never contradicted, over a default the
/// caller never chose, would be a confusing rejection. A pin states one for the
/// same reason and is adopted the same way. It has to be the same rule for
/// every layer, because it is what decides whether a plan's architecture check
/// ever fires for a caller who simply did not say.
///
/// The architecture is a path segment of every index URL, so it is held to
/// [`coordinate::check`] as a single segment.
///
/// # Errors
///
/// Returns the reason the architecture settled on is not a coordinate.
pub(crate) fn settle_architecture(
    named: Option<&str>,
    stated: Option<&str>,
    host: impl FnOnce() -> String,
) -> Result<String, String> {
    let architecture = match (named, stated) {
        (Some(named), _) => named.to_string(),
        (None, Some(stated)) => stated.to_string(),
        (None, None) => host(),
    };
    coordinate::check(
        "the bootstrap's architecture",
        &architecture,
        Nesting::Single,
    )?;
    Ok(architecture)
}

/// Refuses a negative `SOURCE_DATE_EPOCH`.
///
/// The variable counts seconds since 1970, and the tools that read it date
/// from the clock instead when it is negative, as `/etc/shadow`, which counts
/// days since 1970, cannot record one. A build that was asked for a
/// reproducible date and quietly took the clock's is refused at `build` rather
/// than found out by comparing two roots.
///
/// # Errors
///
/// Returns the reason a negative `epoch` is refused.
pub(crate) fn check_source_date_epoch(epoch: Option<i64>) -> Result<(), String> {
    match epoch {
        Some(epoch) if epoch < 0 => Err(format!(
            "the source date epoch {epoch} is negative, and the tools that read \
             SOURCE_DATE_EPOCH date from the clock instead, as /etc/shadow records days since \
             1970"
        )),
        _ => Ok(()),
    }
}

/// Refuses a selection beside a plan, which already names every package to
/// install.
///
/// # Errors
///
/// Returns the reason an `include` or an `exclude` is refused.
pub(crate) fn plan_with_selection(includes: &[String], excludes: &[String]) -> Result<(), String> {
    if !includes.is_empty() {
        return Err(
            "a plan already names every package to install, so include() has nothing \
                    to add; drop one of the two"
                .to_string(),
        );
    }
    if !excludes.is_empty() {
        return Err(
            "a plan already names every package to install, so exclude() has nothing \
                    to remove; drop one of the two"
                .to_string(),
        );
    }
    Ok(())
}

/// Refuses a plan resolved for another architecture than the configured one.
///
/// The plan's value is quoted, since a document is a file the caller may have
/// taken from elsewhere; the configured one has passed [`coordinate::check`].
///
/// # Errors
///
/// Returns the reason the two differ.
pub(crate) fn plan_architecture(planned: &str, configured: &str) -> Result<(), String> {
    if planned == configured {
        return Ok(());
    }
    Err(format!(
        "the plan resolves architecture {planned:?} but the bootstrap is configured for \
         {configured}"
    ))
}

/// The first package `packages` names twice, as its two entries, or `None`
/// where every name appears once.
///
/// A root holds one package of a name, and everything that reads a plan keys
/// it by name: a pin holds each name to one version, and an install records one
/// package per name. So two entries for one name are a plan with no single
/// reading, whether or not they agree. A plan a layer resolved cannot contain
/// one; a hand-written document or an edited plan can.
pub(crate) fn named_twice<P>(packages: &[P], name: impl Fn(&P) -> &str) -> Option<(&P, &P)> {
    let mut seen: HashMap<&str, &P> = HashMap::with_capacity(packages.len());
    packages.iter().find_map(|package| {
        seen.insert(name(package), package)
            .map(|first| (first, package))
    })
}

/// The refusal of a plan naming the package `name` twice, at the two versions
/// its entries state.
pub(crate) fn plan_names_twice(name: &str, first: &str, again: &str) -> String {
    format!(
        "the plan names the package {name} twice, at {first} and at {again}, and a root holds \
         one package of each name"
    )
}

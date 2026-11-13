//! The guide's Rust code, compiled by `cargo test`.
//!
//! Every chapter of `docs/` is included here as documentation, so each of its
//! `rust` blocks is a doctest of this crate: it compiles against the library the
//! test run built, with the dev-dependencies a doctest already has, and a block
//! without `no_run` or `ignore` runs as any other doctest does. `mdbook build`
//! renders the guide and does not compile it, so this module is what holds the
//! guide's code to the library.
//!
//! The module exists only while doctests are being collected, so nothing here
//! reaches an ordinary build, the rendered API documentation, or the packaged
//! crate. It needs every feature, because the guide documents the whole library;
//! a selection missing one compiles the guide's blocks not at all rather than
//! partly.

/// Includes each chapter as a documented module, and records the list for the
/// test that holds it to what `docs/src` actually contains.
macro_rules! chapters {
    ($($file:literal => $chapter:ident),* $(,)?) => {
        /// The chapters compiled above, as file names under `docs/src`.
        #[cfg(test)]
        const CHAPTERS: &[&str] = &[$($file),*];

        $(
            #[cfg(doctest)]
            #[doc = include_str!(concat!("../../../docs/src/", $file))]
            mod $chapter {}
        )*
    };
}

// `SUMMARY.md` is the table of contents and carries no code, and the test below
// knows it. Everything else the guide publishes is here.
chapters! {
    "agent-tools.md" => agent_tools,
    "alpine.md" => alpine,
    "building-a-debian-package.md" => building_a_debian_package,
    "building-an-orchestrator.md" => building_an_orchestrator,
    "cross-architecture.md" => cross_architecture,
    "debian.md" => debian,
    "ebuild-sandbox.md" => ebuild_sandbox,
    "embedding.md" => embedding,
    "features.md" => features,
    "gentoo.md" => gentoo,
    "hardening.md" => hardening,
    "host-requirements.md" => host_requirements,
    "how-the-sandbox-is-built.md" => how_the_sandbox_is_built,
    "identity-maps.md" => identity_maps,
    "introduction.md" => introduction,
    "process-model.md" => process_model,
    "profiles.md" => profiles,
    "provisioning.md" => provisioning,
    "quick-start.md" => quick_start,
    "restriction-fallback.md" => restriction_fallback,
    "running-in-a-container.md" => running_in_a_container,
    "stability.md" => stability,
    "streaming.md" => streaming,
    "terminal.md" => terminal,
    "userspace-networking.md" => userspace_networking,
}

#[cfg(test)]
mod tests {
    use super::CHAPTERS;

    #[test]
    fn every_chapter_of_the_guide_is_compiled() {
        // The list above is written by hand, so a chapter added to the guide
        // and not to it would be documentation nothing compiles -- which is the
        // state this module exists to end. This is the only part of the gate a
        // doctest cannot assert about itself: a chapter that is never included
        // produces no test that could fail.
        let src = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/src");
        let mut published: Vec<String> = std::fs::read_dir(src)
            .expect("the guide's sources sit beside the crates in the repository")
            .map(|entry| entry.expect("the directory is readable").file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".md") && name != "SUMMARY.md")
            .collect();
        published.sort();

        let mut compiled: Vec<String> = CHAPTERS.iter().map(|file| file.to_string()).collect();
        compiled.sort();
        assert_eq!(
            compiled, published,
            "the chapters compiled as doctests and the chapters the guide publishes",
        );
    }
}

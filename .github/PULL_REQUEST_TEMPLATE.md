<!-- A change is best agreed in an issue before it is written; see
     CONTRIBUTING.md. Link that issue here if there is one. -->

## What this changes

<!-- The change in the repository's own terms: what the code now does. -->

## Why

<!-- The reasoning, where it is not obvious from the change itself. -->

## Checks

<!-- CI runs all of these; running them locally first is faster than a round
     trip. See CONTRIBUTING.md. -->

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] `cargo doc --workspace --all-features --no-deps` with `RUSTDOCFLAGS='-D warnings'`
- [ ] `mdbook build docs`, if the guide changed

## Public API

- [ ] The surface is unchanged, **or** `crates/ferroday-cage/public-api.txt` is
      regenerated and the diff is intentional
- [ ] `tests/auto_traits.rs` still holds, and records the reason for any
      deliberate absence
- [ ] `CHANGELOG.md` records the change

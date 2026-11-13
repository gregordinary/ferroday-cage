//! The keys a repository's signatures are verified against, and the sets the
//! crate bundles for Alpine and postmarketOS.
//!
//! An apk signature names the key that made it by file name, so a [`KeySet`] is
//! keyed the same way: `alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub` is
//! both what the signature spells and what the repository publishes the key
//! under.
//!
//! # A key set is the whole trust anchor
//!
//! An Alpine signing key is a bare RSA public key in PEM `SubjectPublicKeyInfo`
//! form. It carries no expiry, no self-signature, and no revocation, so none of
//! the validity and freshness rules an OpenPGP certificate is held to have an
//! analogue here: what the set holds is what is trusted, and the only way to
//! withdraw a key is to stop shipping it. A bundled set can therefore only be
//! refreshed by a release of this crate, and a caller who needs a different
//! answer sooner assembles one with [`KeySet::insert`].
//!
//! # The bundle is partitioned by architecture
//!
//! Alpine does not sign every architecture with one key. `alpine-keys` installs
//! three keys on x86_64, two entirely different ones on aarch64, two more on
//! armv7, and so on: eighteen distinct keys across ten architectures, with only
//! two of them serving more than one, `4a6a0840` for x86 and x86_64 and
//! `524d27bb` for armhf and armv7. A signature made for x86_64 does not verify
//! on an aarch64 root under `apk`, and it does not here either.
//!
//! [`ALPINE`] mirrors that partition rather than flattening it, and mirrors it
//! mechanically: it is the `usr/share/apk/keys/<architecture>/` tree of the
//! `alpine-keys` package, key for key. Refreshing the bundle is therefore
//! re-reading that package rather than deciding which architectures still
//! count, which is a rule a later reader can check rather than a judgement they
//! would have to reconstruct.
//!
//! # One key signs many releases
//!
//! Alpine does not rotate its keys per release. One key per architecture signs
//! every release over years: on x86_64, `4a6a0840` signs v3.0 through v3.14,
//! and `6165ee59` every release since v3.15 and `edge`. `alpine-keys` keeps the
//! superseded keys, so an architecture's set verifies every release the archive
//! still serves rather than only the current one. It follows that a verified
//! signature does not say which release an index belongs to. That binding is
//! the index's own signed `DESCRIPTION`, which [`release`](super::release)
//! checks.

mod spki;

use std::collections::BTreeMap;
use std::fmt;

use irongall::rsa::PublicKey;

use super::AlpineError;

/// One key of the bundle: the file name a signature spells it by, and the PEM
/// the crate ships.
pub(super) struct Bundled {
    /// The file name the repository publishes the key under, which is what a
    /// `.SIGN.` member's name carries.
    pub(super) name: &'static str,
    /// The key itself, PEM `SubjectPublicKeyInfo`.
    pub(super) pem: &'static str,
}

/// The prefix of every key name Alpine publishes, as a literal the macros below
/// can join onto.
///
/// [`ALPINE_KEY_PREFIX`] is the same text as a value; this is the one spelling
/// of it.
macro_rules! alpine_key_prefix {
    () => {
        "alpine-devel@lists.alpinelinux.org-"
    };
}

/// The prefix every key Alpine publishes carries in its name, followed by the
/// hexadecimal stem that tells the keys apart.
const ALPINE_KEY_PREFIX: &str = alpine_key_prefix!();

/// One Alpine key of the bundle, named by the hexadecimal stem `alpine-keys`
/// publishes it under.
///
/// The stem produces the file name and the contents both, so the two cannot
/// drift apart: a stem naming a file this directory does not hold fails to
/// compile.
macro_rules! alpine_key {
    ($stem:literal) => {
        Bundled {
            name: concat!(alpine_key_prefix!(), $stem, ".rsa.pub"),
            pem: include_str!(concat!(alpine_key_prefix!(), $stem, ".rsa.pub")),
        }
    };
}

/// Whether `name` is the name of a key Alpine publishes, bundled or not.
///
/// Read off the name rather than the bundle, so a key Alpine published after
/// this crate's release and a caller added with [`KeySet::insert`] counts too.
/// A signature names the key that made it, and verifying it against the set's
/// key of that name is what makes the name trustworthy here: an index this
/// answers for verified under a key held under Alpine's name.
pub(super) fn is_alpine(name: &str) -> bool {
    name.starts_with(ALPINE_KEY_PREFIX)
}

/// The Alpine signing keys the crate bundles, by the architecture each serves.
///
/// This is `alpine-keys`' own `usr/share/apk/keys/<architecture>/` partition,
/// mirrored key for key; see the module documentation for why it is a mirror
/// rather than a selection. The architectures are the ones that package covers,
/// which is a superset of what the archive publishes today: `mips64` was
/// dropped after Alpine 3.15 and its key is kept because the package keeps it,
/// so an archived mirror still verifies.
pub(super) const ALPINE: &[(&str, &[Bundled])] = &[
    (
        "aarch64",
        &[alpine_key!("58199dcc"), alpine_key!("616ae350")],
    ),
    ("armhf", &[alpine_key!("524d27bb"), alpine_key!("616a9724")]),
    ("armv7", &[alpine_key!("524d27bb"), alpine_key!("616adfeb")]),
    ("loongarch64", &[alpine_key!("66ba20fe")]),
    ("mips64", &[alpine_key!("5e69ca50")]),
    (
        "ppc64le",
        &[alpine_key!("58cbb476"), alpine_key!("616abc23")],
    ),
    (
        "riscv64",
        &[alpine_key!("60ac2099"), alpine_key!("616db30d")],
    ),
    ("s390x", &[alpine_key!("58e4f17d"), alpine_key!("616ac3bc")]),
    (
        "x86",
        &[
            alpine_key!("4a6a0840"),
            alpine_key!("5243ef4b"),
            alpine_key!("61666e3f"),
        ],
    ),
    (
        "x86_64",
        &[
            alpine_key!("4a6a0840"),
            alpine_key!("5261cecb"),
            alpine_key!("6165ee59"),
        ],
    ),
];

/// postmarketOS's signing key, which is one key for every architecture it
/// publishes.
const POSTMARKETOS: Bundled = Bundled {
    name: "build.postmarketos.org.rsa.pub",
    pem: include_str!("build.postmarketos.org.rsa.pub"),
};

/// The signing keys a repository's indexes are verified against.
///
/// A package is not verified against the set: it is bound to the verified index
/// that named it, through the control identity the index records.
///
/// Obtained from the bundle with [`alpine`](Self::alpine) or
/// [`postmarketos`](Self::postmarketos), or assembled from a caller's own keys
/// with [`insert`](Self::insert) — which is also how a set is extended, since a
/// repository publishing its own packages beside a distribution's signs them
/// with a key no bundle can know.
///
/// A set is the whole trust anchor for the repository it is attached to. An apk
/// signing key is a bare RSA public key: it carries no expiry, no
/// self-signature, and no revocation, so none of the validity rules an OpenPGP
/// certificate is held to have an analogue here, and nothing narrows a set after
/// it is built. A bundled set can only be refreshed by a release of this crate;
/// a caller who needs a different answer sooner assembles one with
/// [`insert`](Self::insert).
#[derive(Clone, Default)]
pub struct KeySet {
    keys: BTreeMap<String, Held>,
}

/// One trusted key: the parsed form a signature is verified against, and the
/// text it was given as.
///
/// The text is kept rather than re-encoded because a bootstrap writes the
/// repository's keys into the finished root, where `apk` reads them back — and
/// a key written back as it arrived is one a caller can diff against the file
/// they supplied.
#[derive(Clone)]
struct Held {
    key: PublicKey,
    pem: String,
}

impl fmt::Debug for KeySet {
    /// Names the keys rather than rendering them. A public key's modulus is
    /// bulky and says nothing a reader of a rendering can act on, while the
    /// names are exactly what a refused signature is diagnosed against.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySet")
            .field("keys", &self.keys.keys())
            .finish()
    }
}

impl KeySet {
    /// An empty key set, which accepts nothing.
    pub fn new() -> KeySet {
        KeySet::default()
    }

    /// The bundled Alpine keys that sign `architecture`.
    ///
    /// Alpine does not sign every architecture with one key: `alpine-keys`
    /// installs three keys on x86_64, two entirely different ones on aarch64,
    /// two more on armv7, and so on, with only two of the eighteen serving more
    /// than one architecture. A signature made for x86_64 does not verify on an
    /// aarch64 root under `apk`, and it does not here either, so this is the
    /// set for one architecture rather than the whole bundle.
    ///
    /// `architecture` is the repository's, so it is always a real one —
    /// `noarch` is a property of a package rather than an archive a set can be
    /// built for.
    ///
    /// # Errors
    ///
    /// Returns [`AlpineError::Config`] for an architecture the bundle holds no
    /// keys for, naming the ones it does. The architecture is not otherwise
    /// refused: a mirror may serve one this crate has never heard of, and the
    /// remedy is a set of the caller's own rather than a newer release of this
    /// crate.
    pub fn alpine(architecture: &str) -> Result<KeySet, AlpineError> {
        let Some((_, keys)) = ALPINE.iter().find(|(name, _)| *name == architecture) else {
            return Err(AlpineError::Config {
                reason: format!(
                    "the crate bundles no Alpine signing keys for the architecture \
                     {architecture:?}; it holds keys for {}. To provision an architecture the \
                     bundle does not cover, build a key set of your own with KeySet::insert",
                    ALPINE
                        .iter()
                        .map(|(name, _)| *name)
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            });
        };
        Ok(KeySet::bundled(keys))
    }

    /// The bundled postmarketOS signing key.
    ///
    /// postmarketOS signs every architecture it publishes with one key, so this
    /// takes none.
    pub fn postmarketos() -> KeySet {
        KeySet::bundled(std::slice::from_ref(&POSTMARKETOS))
    }

    /// The set holding every key of `bundled`.
    ///
    /// The keys are compiled into the crate, so one that does not parse is a
    /// defect in this crate rather than anything a caller did or can act on. A
    /// test parses every bundled key, which is where that would be caught.
    fn bundled(bundled: &[Bundled]) -> KeySet {
        let mut set = KeySet::new();
        for key in bundled {
            set.insert(key.name, key.pem)
                .expect("a key bundled with the crate is a usable RSA public key");
        }
        set
    }

    /// Adds the PEM-encoded public key `pem` under `name`.
    ///
    /// `name` is the file name the repository publishes the key under, which is
    /// what a signature member's name carries — for example
    /// `alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub`, or the
    /// `<name>.rsa.pub` that `abuild-sign` writes for a repository of the
    /// caller's own. A signature naming a key the set does not hold under
    /// exactly that name is refused, so the name matters as much as the bytes.
    ///
    /// A key added under a name already present replaces it.
    ///
    /// # Errors
    ///
    /// Returns [`AlpineError::Config`] for a key that is not a PEM
    /// `SubjectPublicKeyInfo` holding an RSA public key, or whose modulus is
    /// narrower than 2048 bits or wider than 8192: a key set is the
    /// configuration a repository is verified under, and no signature has been
    /// read yet.
    pub fn insert(&mut self, name: impl Into<String>, pem: &str) -> Result<(), AlpineError> {
        let name = name.into();
        let key = spki::rsa_public_key(pem).map_err(|reason| AlpineError::Config {
            reason: format!("the key {name} is not a usable RSA public key: {reason}"),
        })?;
        self.keys.insert(
            name,
            Held {
                key,
                pem: pem.to_string(),
            },
        );
        Ok(())
    }

    /// The names of the keys held, in order.
    ///
    /// These are the names a signature is matched against, so this is what a
    /// caller inspects to see what a repository is trusted on.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }

    /// The key held under `name`, or `None` where the set holds none.
    ///
    /// A signature names its key exactly, so this is an exact lookup: a set
    /// holding the same key under a different name verifies nothing.
    pub(super) fn get(&self, name: &str) -> Option<&PublicKey> {
        self.keys.get(name).map(|held| &held.key)
    }

    /// Every key as the name it is published under and the text it was given
    /// as, in name order.
    ///
    /// What a bootstrap writes into `/etc/apk/keys` for the repositories it
    /// installed from, so a later `apk` inside the root trusts what this one
    /// did.
    pub(super) fn pems(&self) -> impl Iterator<Item = (&str, &str)> {
        self.keys
            .iter()
            .map(|(name, held)| (name.as_str(), held.pem.as_str()))
    }

    /// Whether the set holds no keys at all, and so accepts nothing.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bundled_key_parses() {
        // `bundled` expects this, so the expectation is checked here rather
        // than discovered by a caller: a bundled key that does not parse is a
        // defect in this crate.
        for (architecture, keys) in ALPINE {
            let set = KeySet::alpine(architecture)
                .unwrap_or_else(|err| panic!("{architecture} is in the bundle: {err}"));
            assert_eq!(set.names().count(), keys.len(), "{architecture}");
        }
        assert_eq!(KeySet::postmarketos().names().count(), 1);
    }

    #[test]
    fn a_key_is_held_under_the_name_a_signature_spells() {
        // The whole scheme rests on this: a signature member names its key by
        // the file name the repository publishes it under.
        let set = KeySet::alpine("x86_64").expect("x86_64 is in the bundle");
        assert!(
            set.names()
                .any(|name| name == "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"),
            "the current x86_64 key is held under its published name: {:?}",
            set.names().collect::<Vec<_>>(),
        );
    }

    #[test]
    fn the_architecture_partitions_are_all_but_disjoint() {
        // The partition this bundle mirrors. Only two keys serve more than one
        // architecture, x86's and x86_64's oldest and armhf's and armv7's, so
        // an x86_64 signature does not verify on an aarch64 root.
        let x86_64 = KeySet::alpine("x86_64").expect("x86_64 is in the bundle");
        let aarch64 = KeySet::alpine("aarch64").expect("aarch64 is in the bundle");
        assert!(
            !x86_64
                .names()
                .any(|name| aarch64.names().any(|o| o == name)),
            "x86_64 and aarch64 share no key",
        );

        let mut shared = Vec::new();
        for (architecture, keys) in ALPINE {
            for key in *keys {
                if ALPINE.iter().any(|(other, keys)| {
                    other != architecture && keys.iter().any(|o| o.name == key.name)
                }) {
                    shared.push(key.name);
                }
            }
        }
        shared.sort_unstable();
        shared.dedup();
        assert_eq!(
            shared,
            [
                "alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub",
                "alpine-devel@lists.alpinelinux.org-524d27bb.rsa.pub",
            ],
            "only these two keys serve more than one architecture",
        );
    }

    #[test]
    fn an_architecture_the_bundle_does_not_cover_is_refused_by_name() {
        // Not because the architecture is invalid — a mirror may serve one this
        // crate has never heard of — but because there is nothing to trust it
        // on, and the message says what to do about that.
        let err = KeySet::alpine("sparc64").expect_err("the bundle has no sparc64 keys");
        let reason = err.to_string();
        assert!(reason.contains("sparc64"), "{reason}");
        assert!(
            reason.contains("x86_64"),
            "the covered set is named: {reason}"
        );
        assert!(reason.contains("KeySet::insert"), "{reason}");
    }

    #[test]
    fn a_key_that_is_not_a_public_key_is_refused() {
        let mut set = KeySet::new();
        assert!(set.is_empty());
        let err = set
            .insert("mine.rsa.pub", "-----BEGIN PUBLIC KEY-----\nnope\n")
            .expect_err("the key does not parse");
        // A key is configuration, and the refusal names it once.
        assert!(
            matches!(&err, AlpineError::Config { reason }
                if reason.matches("mine.rsa.pub").count() == 1),
            "{err}",
        );
        assert!(set.is_empty(), "a refused key is not held");
    }

    #[test]
    fn a_caller_key_extends_a_bundled_set() {
        // The route for a repository publishing its own packages beside a
        // distribution's: the bundle plus a key `abuild-sign` made.
        let mut set = KeySet::alpine("x86_64").expect("x86_64 is in the bundle");
        let bundled = set.names().count();
        set.insert("mine.rsa.pub", POSTMARKETOS.pem)
            .expect("a well-formed key is accepted");
        assert_eq!(set.names().count(), bundled + 1);
        assert!(set.names().any(|name| name == "mine.rsa.pub"));
    }

    #[test]
    fn every_bundled_alpine_key_is_named_as_alpine_publishes_it() {
        // The release binding is keyed on this: an index a key of this name
        // verified is one Alpine's builders signed.
        for (architecture, keys) in ALPINE {
            for key in *keys {
                assert!(is_alpine(key.name), "{architecture}: {}", key.name);
            }
        }
        assert!(!is_alpine(POSTMARKETOS.name));
        assert!(!is_alpine("build@example.com-64f0c0a1.rsa.pub"));
    }

    #[test]
    fn a_rendering_names_the_keys_rather_than_holding_them() {
        let rendered = format!("{:?}", KeySet::postmarketos());
        assert!(
            rendered.contains("build.postmarketos.org.rsa.pub"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("BEGIN PUBLIC KEY"),
            "the key itself is not in the rendering: {rendered}",
        );
    }
}

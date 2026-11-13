//! The merge: laying a package's files into the root, and registering the entry
//! portage reads back.
//!
//! A stage3 arrives with a populated `/var/db/pkg`, so a root this layer
//! installs into and does not register is a root whose database is a lie:
//! portage would rebuild what is already there, and `--depclean` would remove
//! it. So the merge writes an entry, and it is held to the standard
//! `alpine/installed.rs` set — compared against one portage merged the same way.
//!
//! # An entry is the container's metadata plus three files portage computes
//!
//! Compared file by file against a stage3's own entries, a vdb entry is exactly
//! the container's `metadata/` directory with three additions:
//!
//! | File | What it is | Where it comes from |
//! | --- | --- | --- |
//! | `CONTENTS` | every installed path, with a digest and mtime per file | computed while merging |
//! | `COUNTER` | the global merge ordinal | the root's `/var/cache/edb/counter`, and every entry's own |
//! | `BINPKGMD5` | the MD5 of the container it came from | the container, as portage takes it |
//!
//! `BINPKGMD5` is taken over the container as it was read, which the plan's MD5
//! has already been held to. `CONTENTS` is computed while merging, and its
//! `obj` lines carry an MD5 too — a bookkeeping checksum portage compares to
//! decide whether a file has been edited since it was merged, never a trust
//! decision.
//!
//! # The one deliberate difference
//!
//! A `sym` line's timestamp. Portage records the mtime the filesystem gave the
//! link when it created it, because its own merge does not carry a symbolic
//! link's mtime across; this layer's extractor does, so the timestamp recorded
//! here is the archive's and it matches what is on disk. That is what the field
//! is *for* — portage reads it to tell a link that has been replaced from one
//! that has not — so recording the true mtime serves the purpose better, and it
//! makes a root this layer builds reproducible where portage's is not.
//!
//! # Phase functions are not run
//!
//! Around 30% of packages define a `pkg_postinst` or `pkg_preinst`, and they
//! live in `environment.bz2` as a serialized bash environment: running one means
//! running portage's `ebuild.sh` with the eclasses it was built against. This
//! layer merges files and registers the entry, and does neither.
//!
//! What that costs is worth naming rather than discovering. An
//! `acct-user`/`acct-group` package ships a `sysusers.d` fragment and creates
//! the account in `pkg_preinst`, so the account is not created;
//! `ca-certificates` does not regenerate its bundle; icon and font caches are
//! not rebuilt. It is the same seam Debian's layer has and the opposite
//! decision: Debian's maintainer scripts are executables the layer can run
//! inside the sandbox, so it runs them, while Gentoo's are bash functions that
//! need the guest's package manager. A caller who needs them has a root portage
//! can act on, which is the strongest argument for registering the entry
//! properly.
//!
//! # `CONFIG_PROTECT` is not honoured
//!
//! An existing file under `/etc` is overwritten rather than given portage's
//! `._cfg0000_` treatment. The layer builds roots rather than upgrading live
//! systems, and a root whose configuration depends on merge order is not
//! reproducible.

use std::fmt::Write as _;
use std::path::Path;

use super::gpkg::{IMAGE_DIR, Package};
use super::plan::PlannedPackage;
use super::{DB_DIR, GentooError, MAX_CONTENTS_ENTRIES};
use crate::path;
use crate::provision::ProvisionError;
use crate::provision::digest::{self, Algorithm};
use crate::provision::extract::{Extraction, Placement};
use crate::provision::rooted::Rooted;

/// Where portage keeps the ordinal it stamps each merge with.
const COUNTER_FILE: &str = "var/cache/edb/counter";

/// The most of [`COUNTER_FILE`] this reads.
///
/// The ordinal is a `u64`, twenty digits at most; a file longer than this is
/// not a counter, and a root whose counter has been grown without being
/// written to is refused here rather than read into memory.
const MAX_COUNTER_BYTES: u64 = 64;

/// The three files a merge writes that the container does not carry.
const CONTENTS_FILE: &str = "CONTENTS";
const COUNTER_ENTRY: &str = "COUNTER";
const BINPKGMD5_FILE: &str = "BINPKGMD5";

/// One installed path, as the merge laid it down.
///
/// Collected while the image is extracted and rendered afterwards, because an
/// `obj` line carries the digest of what was written and the extractor's hook
/// runs before the bytes are.
enum Laid {
    /// A directory: `dir <path>`.
    Directory(String),
    /// A regular file, or anything the extractor writes as one: `obj <path>
    /// <md5> <mtime>`.
    File(String, i64),
    /// A symbolic link: `sym <path> -> <target> <mtime>`.
    Link(String, String, i64),
    /// A named pipe: `fif <path>`.
    ///
    /// Portage's own line type for one, and the reason this is a variant rather
    /// than an `obj`: a fifo has no contents to digest, and opening one to look
    /// for some blocks until something opens the write end — which, inside a
    /// provisioning run, nothing will. Recording it as a file would hang the
    /// merge rather than fail it.
    ///
    /// Character and block devices have a line type of portage's too, `dev`, and
    /// no variant here: the extractor skips them before the hook sees them,
    /// since laying one down needs privilege the layer does not have and the
    /// sandbox provides its own `/dev`.
    Fifo(String),
}

/// Merges `package` into the root and registers its database entry.
///
/// `over` is the base a layered build's root is an overlay upper over, which
/// the image is placed through ([`Extraction::over`]): an entry under `lib64/`,
/// over a base whose `lib64` is a link to `usr/lib64`, lands at `usr/lib64` in
/// the upper beside a copy of the link, rather than becoming a directory that
/// hides it. `CONTENTS` records each path as the image spells it, as portage
/// records a path it merged through a link to a directory, and the digest of
/// each file is read through the same link.
///
/// # Errors
///
/// Returns [`GentooError::Container`] for a container that ships something the
/// root's database cannot record: a metadata file whose name is not one path
/// component, more than [`MAX_CONTENTS_ENTRIES`] paths, or a path or a link
/// target that is not UTF-8 or that holds a line ending. Returns
/// [`GentooError::Io`] where the root could not be written or a merged file
/// could not be read back, and whatever the extractor reports for an image
/// archive it will not unpack.
pub(super) fn merge(
    root: &Path,
    over: Option<&Path>,
    rooted: &Rooted,
    container: &Path,
    package: &Package,
    planned: &PlannedPackage,
    counter: u64,
) -> Result<(), ProvisionError> {
    let entry = entry_dir(planned);
    let laid = extract_image(root, over, container, package)?;
    let contents = render_contents(root, rooted, &laid)?;

    // The metadata files first, then the three portage computes. Written after
    // the image rather than before: an entry that named files the root does not
    // have would be worse than no entry, and a failure part way through an
    // extraction leaves the staging tree that `provision::ensure` removes.
    for (name, bytes) in package.metadata_files() {
        // A metadata file is a name from inside a verified container, and it
        // becomes a leaf of a path. The container's reader has already held it
        // to one ordinary component; this is the boundary it crosses, so the
        // rule is asked again here.
        if !path::is_ordinary_component(name.as_bytes()) {
            return Err(GentooError::container(
                container,
                format!("names a metadata file {name:?}, which is not one path component"),
            )
            .into());
        }
        rooted
            .write(format!("{entry}/{name}"), bytes)
            .map_err(|err| GentooError::io("writing a package database entry", root, err))?;
    }
    rooted
        .write(format!("{entry}/{CONTENTS_FILE}"), contents.as_bytes())
        .map_err(|err| GentooError::io("writing a package database entry", root, err))?;
    // Newline-terminated, as portage writes it, where COUNTER is not.
    rooted
        .write(
            format!("{entry}/{BINPKGMD5_FILE}"),
            format!("{}\n", package.md5()).as_bytes(),
        )
        .map_err(|err| GentooError::io("writing a package database entry", root, err))?;
    // Written with no trailing newline, as portage writes it, where every other
    // one-line file it writes carries one.
    rooted
        .write(
            format!("{entry}/{COUNTER_ENTRY}"),
            counter.to_string().as_bytes(),
        )
        .map_err(|err| GentooError::io("writing a package database entry", root, err))?;
    // And the root's own counter advances with it, so the next merge -- this
    // layer's or portage's own, inside the finished sandbox -- takes the next
    // ordinal rather than reissuing this one.
    rooted
        .write(COUNTER_FILE, counter.to_string().as_bytes())
        .map_err(|err| GentooError::io("writing the merge counter", root, err))?;
    Ok(())
}

/// The database directory this package's entry belongs at.
///
/// Composed from the plan rather than from the container. The two say the same
/// thing — [`Package::read`](super::gpkg::Package::read) refuses a container
/// whose `CATEGORY`, `PF` and `BUILD_ID` are not the ones the plan named — and
/// composing from the plan is what makes that a statement about one reading
/// instead of two: the bytes the identity check held are the bytes the path is
/// built from, with no second parse of the metadata to keep in step with the
/// first.
///
/// `PF` is the package's name and version with no category and no build id,
/// which is exactly what portage names an entry directory. The plan holds the
/// two halves separately, so the entry directory is the pair rejoined.
fn entry_dir(planned: &PlannedPackage) -> String {
    // Both halves passed `PlannedPackage::unusable` on the way in: the name is a
    // package the atom grammar admits, so it is one category and one name with
    // neither able to be `.`, `..`, or carry a separator, and the version parses
    // under the Gentoo grammar.
    let (category, name) = planned
        .name
        .split_once('/')
        .expect("a planned package names a category and a name");
    format!("{DB_DIR}/{category}/{name}-{}", planned.version)
}

/// Extracts the container's image into the root, recording what it laid down.
fn extract_image(
    root: &Path,
    over: Option<&Path>,
    container: &Path,
    package: &Package,
) -> Result<Vec<Laid>, ProvisionError> {
    let mut image = package.image(container)?;
    let mut laid: Vec<Laid> = Vec::new();
    let mut extraction = Extraction::new(root)?
        .over(over)?
        .under(IMAGE_DIR.as_bytes());
    extraction.extract(&mut image, &mut |entry, components| {
        if laid.len() >= MAX_CONTENTS_ENTRIES {
            // The extraction stops here rather than at the end: a container
            // that ships more paths than this is not one to keep unpacking
            // into a root while deciding what to do about it.
            return Err(GentooError::container(
                container,
                format!("ships more than {MAX_CONTENTS_ENTRIES} paths"),
            )
            .into());
        }
        // A path is bytes and `CONTENTS` is a text file portage reads line by
        // line, so one it cannot read back as written cannot be recorded --
        // and a path in the database that does not describe what is on disk is
        // worse than a refusal. A link's target is recorded on the same line,
        // so it is held to the same rule.
        let path = recordable(components.join(&b'/').to_vec()).map_err(|why| {
            ProvisionError::from(GentooError::container(
                container,
                format!("ships a path that {why}"),
            ))
        })?;
        laid.push(match entry.typeflag {
            b'5' => Laid::Directory(path),
            b'2' => {
                let target = recordable(entry.link_target.clone()).map_err(|why| {
                    ProvisionError::from(GentooError::container(
                        container,
                        format!("ships a link at {path} whose target {why}"),
                    ))
                })?;
                Laid::Link(path, target, entry.mtime)
            }
            b'6' => Laid::Fifo(path),
            // Regular files, and the unknown typeflags POSIX says to treat as
            // regular files -- which is what the extractor does with them too.
            _ => Laid::File(path, entry.mtime),
        });
        Ok(Placement::Write)
    })?;
    extraction.finalize(root)?;
    Ok(laid)
}

/// `bytes` as text a `CONTENTS` line can hold, or why it cannot hold it.
///
/// Portage reads the file a line at a time, with Python's universal newlines,
/// so a carriage return ends a line as a newline does. A path or a target
/// holding either would be read back as two lines, the second whatever the
/// container spelled after it: `usr/lib/x\nobj /etc/shadow ...` registers the
/// package as the owner of a file it never shipped, which an unmerge then
/// removes. Portage's own merge refuses a package whose paths hold either,
/// for the same reason. The text must also be UTF-8, which is what the file
/// is read as.
fn recordable(bytes: Vec<u8>) -> Result<String, &'static str> {
    let text = String::from_utf8(bytes).map_err(|_| "is not UTF-8")?;
    if text.contains(['\n', '\r']) {
        return Err("holds a line ending, which a database line cannot hold");
    }
    Ok(text)
}

/// Renders the entry's `CONTENTS` from the paths the merge laid down.
///
/// A file's digest is taken from what is on disk rather than from the archive,
/// because that is what the field describes: portage compares it against the
/// file to decide whether it has been edited since it was merged, so a value
/// that described the archive instead would report every file as edited the
/// moment the two could differ. It is streamed, so a hundred-megabyte binary
/// costs what a shell script costs.
fn render_contents(root: &Path, rooted: &Rooted, laid: &[Laid]) -> Result<String, GentooError> {
    let mut out = String::new();
    for entry in laid {
        match entry {
            Laid::Directory(path) => {
                let _ = writeln!(out, "dir /{path}");
            }
            Laid::Link(path, target, mtime) => {
                let _ = writeln!(out, "sym /{path} -> {target} {mtime}");
            }
            Laid::Fifo(path) => {
                let _ = writeln!(out, "fif /{path}");
            }
            Laid::File(path, mtime) => {
                let mut file = rooted.reader(path).map_err(|err| {
                    GentooError::io("digesting a merged file", root.join(path), err)
                })?;
                let (md5, _) = digest::stream(Algorithm::Md5, &mut file).map_err(|err| {
                    GentooError::io("digesting a merged file", root.join(path), err)
                })?;
                let _ = writeln!(out, "obj /{path} {md5} {mtime}");
            }
        }
    }
    Ok(out)
}

/// The ordinal the root's counter file says the last merge into `root` was
/// stamped with, or zero where it holds none.
///
/// Portage keeps one number per root and hands each merge the next, so the
/// database records the order things were installed in. A stage3 arrives with
/// its own -- 391 for the roots this was measured against -- and an increment
/// staged over one has to continue that sequence rather than start again: two
/// packages sharing an ordinal is a database that cannot say which was merged
/// first.
///
/// The file is half of where the sequence continues from. Portage takes the
/// greater of it and every ordinal its database's entries record, so a counter
/// file removed or rolled back does not reissue one, and the install wave does
/// the same with [`Installed::last_counter`](super::Installed::last_counter).
/// A layered build asks this of the base as well as of the upper, which is the
/// merged view's answer.
///
/// A value that does not parse is read as zero rather than refused, as portage
/// reads one: it is a bookkeeping ordinal, and the entries' own still bound
/// where the sequence continues. A file past [`MAX_COUNTER_BYTES`] is refused,
/// since that is not a value at all.
pub(super) fn counter_of(root: &Path, rooted: &Rooted) -> Result<u64, GentooError> {
    match rooted.read_if_present(COUNTER_FILE, MAX_COUNTER_BYTES) {
        Ok(Some(bytes)) => Ok(String::from_utf8_lossy(&bytes).trim().parse().unwrap_or(0)),
        Ok(None) => Ok(0),
        Err(err) => Err(GentooError::io("reading the merge counter", root, err)),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::super::gpkg::fixture::{Built, CHOST, CPV, planned_for};
    use super::*;
    use crate::provision::openpgp::fixture;
    use crate::scratch::Scratch;

    /// Merges the fixture container into a fresh root and returns it.
    fn merged(tag: &str, counter: u64) -> Scratch {
        merged_container(tag, counter, Built::ordinary())
    }

    /// The same, for a container a test has bent.
    fn merged_container(tag: &str, counter: u64, built: Built) -> Scratch {
        let (dir, merged) = merging(tag, counter, built);
        merged.expect("the package merges");
        dir
    }

    /// Merges a container a test has bent, and reports what happened.
    fn merging(tag: &str, counter: u64, built: Built) -> (Scratch, Result<(), ProvisionError>) {
        let dir = Scratch::for_test("gentoo-vdb", tag);
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let container = dir.join("package.gpkg.tar");
        built.write(&container, &key);
        let root = dir.join("root");
        std::fs::create_dir_all(&root).expect("the root is created");
        let rooted = Rooted::open(&root).expect("the root opens");
        let planned = planned_for(CPV, 1, &container);
        let package = Package::read(
            std::fs::File::open(&container).expect("the container opens"),
            &container,
            &planned,
            &BTreeSet::from([CHOST.to_string()]),
            &fixture::keyring(&key),
        )
        .expect("the container opens");
        let merged = merge(
            &root, None, &rooted, &container, &package, &planned, counter,
        );
        (dir, merged)
    }

    /// The entry the fixture package registers.
    fn entry(dir: &Scratch) -> std::path::PathBuf {
        dir.join("root/var/db/pkg/sys-libs/zlib-1.3.2")
    }

    /// One file of that entry, as text.
    fn read(dir: &Scratch, name: &str) -> String {
        std::fs::read_to_string(entry(dir).join(name)).unwrap_or_else(|err| panic!("{name}: {err}"))
    }

    #[test]
    fn the_image_lands_in_the_root_with_its_wrapper_stripped() {
        let dir = merged("image", 1);
        let root = dir.join("root");
        assert_eq!(
            std::fs::read(root.join("usr/lib/libz.so.1.3.2")).expect("the file is merged"),
            b"ELF\n",
        );
        assert_eq!(
            std::fs::read_link(root.join("usr/lib/libz.so")).expect("the link is merged"),
            std::path::Path::new("libz.so.1.3.2"),
        );
        // The wrapper directory itself is not a path in the root.
        assert!(!root.join("image").exists());
    }

    #[test]
    fn the_entry_is_the_containers_metadata_plus_the_three_portage_computes() {
        let dir = merged("entry", 42);
        let mut written: Vec<String> = std::fs::read_dir(entry(&dir))
            .expect("the entry is written")
            .map(|found| {
                found
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        written.sort();
        assert_eq!(
            written,
            [
                "BINPKGMD5",
                "BUILD_ID",
                "BUILD_TIME",
                "CATEGORY",
                "CHOST",
                "CONTENTS",
                "COUNTER",
                "PF",
                "RDEPEND",
                "SLOT",
                "USE",
            ],
        );
        // The metadata is written through verbatim.
        assert_eq!(read(&dir, "CATEGORY"), "sys-libs\n");
        assert_eq!(read(&dir, "SLOT"), "0/1\n");
        // BINPKGMD5 carries the container's MD5 and a trailing newline;
        // COUNTER carries the ordinal and none, which is how portage writes
        // each of them.
        let container = std::fs::read(dir.join("package.gpkg.tar")).expect("the container");
        assert_eq!(
            read(&dir, "BINPKGMD5"),
            format!("{}\n", Algorithm::Md5.hex_of(&container)),
        );
        assert_eq!(read(&dir, "COUNTER"), "42");
        // And the root's own counter advances with it, so the next merge --
        // this layer's or portage's inside the finished sandbox -- takes the
        // next ordinal rather than reissuing this one.
        assert_eq!(
            std::fs::read_to_string(dir.join("root").join(COUNTER_FILE)).expect("the counter"),
            "42",
        );
    }

    #[test]
    fn contents_describes_every_path_the_merge_laid_down() {
        // The file portage's own `qcheck` walks: an `obj` line's digest is of
        // what is on disk, and its timestamp is the one the file actually has.
        let dir = merged("contents", 1);
        let contents = read(&dir, CONTENTS_FILE);
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(
            lines,
            [
                "dir /usr",
                "dir /usr/lib",
                // The MD5 of "ELF\n", which is what the file holds. Checked
                // against `md5sum` rather than against this layer's own
                // digester, so the test would catch the digester agreeing with
                // itself about the wrong algorithm.
                "obj /usr/lib/libz.so.1.3.2 c80b8c1c189e1d042d2eb8fce52af5f0 1700000000",
                "sym /usr/lib/libz.so -> libz.so.1.3.2 1700000000",
            ],
        );
    }

    #[test]
    fn a_named_pipe_is_recorded_as_a_fifo_and_never_opened() {
        // A fifo reaches the merge because the extractor lays one down, where
        // it skips the character and block devices that would need privilege.
        // Recording it as an `obj` would mean digesting it, and opening a fifo
        // for reading blocks until something opens the write end -- so this
        // test would hang rather than fail, which is the argument for having
        // it. Portage's own line type for one carries no digest and no
        // timestamp.
        let dir = merged_container(
            "fifo",
            1,
            Built {
                fifo: true,
                ..Built::ordinary()
            },
        );
        let contents = read(&dir, CONTENTS_FILE);
        assert!(
            contents
                .lines()
                .any(|line| line == "fif /usr/lib/zlib.pipe"),
            "{contents}",
        );
        // And it is on disk as a fifo rather than as an empty file.
        let laid = std::fs::metadata(dir.join("root/usr/lib/zlib.pipe")).expect("the fifo is laid");
        assert!(
            std::os::unix::fs::FileTypeExt::is_fifo(&laid.file_type()),
            "{laid:?}",
        );
    }

    #[test]
    fn a_path_or_a_link_target_the_database_cannot_record_is_the_containers_failure() {
        // `CONTENTS` is a text file portage reads line by line, and a link's
        // target is on the same line as its path. Either one that is not UTF-8,
        // or that holds a line ending, is what the container ships, so it is
        // the container that is refused. A line ending is the dangerous one:
        // what follows it reads back as a line of its own, here claiming a
        // file the package never shipped, which an unmerge would remove.
        for (raw, why) in [
            (
                (&b"image/usr/lib/libz-\xff"[..], b'0', &b""[..]),
                "a path that is not UTF-8",
            ),
            (
                (&b"image/usr/lib/libz.so.1"[..], b'2', &b"libz-\xff"[..]),
                "whose target is not UTF-8",
            ),
            (
                (
                    &b"image/usr/lib/libz\nobj /etc/shadow d41d8cd98f00b204e9800998ecf8427e 0"[..],
                    b'0',
                    &b""[..],
                ),
                "a path that holds a line ending",
            ),
            (
                (
                    &b"image/usr/lib/libz\robj /etc/shadow d41d8cd98f00b204e9800998ecf8427e 0"[..],
                    b'0',
                    &b""[..],
                ),
                "a path that holds a line ending",
            ),
            (
                (
                    &b"image/usr/lib/libz.so.1"[..],
                    b'2',
                    &b"libz\nobj /etc/shadow d41d8cd98f00b204e9800998ecf8427e 0"[..],
                ),
                "whose target holds a line ending",
            ),
            (
                (
                    &b"image/usr/lib/libz.so.1"[..],
                    b'2',
                    &b"libz\robj /etc/shadow d41d8cd98f00b204e9800998ecf8427e 0"[..],
                ),
                "whose target holds a line ending",
            ),
        ] {
            let (dir, merged) = merging(
                why,
                1,
                Built {
                    raw: vec![raw],
                    ..Built::ordinary()
                },
            );
            let err = merged.expect_err(why);
            let inner = std::error::Error::source(&err)
                .and_then(|inner| inner.downcast_ref::<GentooError>());
            assert!(
                matches!(inner, Some(GentooError::Container { .. })),
                "{why}: {err:?}",
            );
            assert!(
                crate::ErrorChain::new(&err).to_string().contains(why),
                "{why}: {err}"
            );
            // Refused before it was laid down, so the root holds nothing the
            // database could not describe, and no entry claims anything.
            let root = dir.join("root");
            let held: Vec<_> = std::fs::read_dir(root.join("usr/lib"))
                .expect("the ordinary entries are laid")
                .map(|found| found.expect("an entry").file_name())
                .collect();
            assert!(
                !held
                    .iter()
                    .any(|name| name.as_encoded_bytes().starts_with(b"libz")
                        && !["libz.so.1.3.2", "libz.so"].contains(&name.to_str().unwrap_or(""))),
                "{why}: {held:?}",
            );
            assert!(!entry(&dir).exists(), "{why}");
        }
    }

    #[test]
    fn a_roots_counter_is_read_before_it_is_advanced() {
        let dir = Scratch::for_test("gentoo-vdb", "counter");
        let root = dir.join("root");
        std::fs::create_dir_all(root.join("var/cache/edb")).expect("the root is created");
        let rooted = Rooted::open(&root).expect("the root opens");
        // A root nothing has merged into yet answers zero, so the first merge
        // takes one.
        assert_eq!(counter_of(&root, &rooted).expect("an absent counter"), 0);
        // A stage3 arrives with its own, and an increment continues it.
        std::fs::write(root.join(COUNTER_FILE), b"391").expect("the counter is written");
        assert_eq!(counter_of(&root, &rooted).expect("a counter"), 391);
        // A value a caller has damaged is continued from rather than refused:
        // it is a bookkeeping ordinal, not a trust decision.
        std::fs::write(root.join(COUNTER_FILE), b"not a number").expect("written");
        assert_eq!(counter_of(&root, &rooted).expect("a damaged counter"), 0);
    }
}

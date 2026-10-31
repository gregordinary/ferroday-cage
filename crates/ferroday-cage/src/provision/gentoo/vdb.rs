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
//! | `COUNTER` | the global merge ordinal | the root's `/var/cache/edb/counter` |
//! | `BINPKGMD5` | the MD5 of the container it came from | the index record, verbatim |
//!
//! `BINPKGMD5` needs no computation. `CONTENTS` does, and its `obj` lines carry
//! an MD5 — a bookkeeping checksum portage compares to decide whether a file
//! has been edited since it was merged, never a trust decision.
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
/// Returns the paths it laid down, which is what the entry's `CONTENTS`
/// records.
///
/// # Errors
///
/// Returns [`GentooError::Database`] for a container whose metadata does not
/// name a package, [`GentooError::Io`] where the root could not be written, and
/// whatever the extractor reports for an image archive it will not unpack.
pub(super) fn merge(
    root: &Path,
    rooted: &Rooted,
    container: &Path,
    package: &Package,
    planned: &PlannedPackage,
    counter: u64,
) -> Result<(), ProvisionError> {
    let entry = entry_dir(planned);
    let laid = extract_image(root, container, package)?;
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
            return Err(GentooError::database(
                root,
                format!("the container names a metadata file {name:?}"),
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
            format!("{}\n", planned.md5).as_bytes(),
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
/// thing — [`Package::open`](super::gpkg::Package::open) refuses a container
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
    container: &Path,
    package: &Package,
) -> Result<Vec<Laid>, ProvisionError> {
    let mut image = package.image(container)?;
    let mut laid: Vec<Laid> = Vec::new();
    let mut extraction = Extraction::new(root)?.under(IMAGE_DIR.as_bytes());
    extraction.extract(&mut image, &mut |entry, components| {
        if laid.len() >= MAX_CONTENTS_ENTRIES {
            // The extraction stops here rather than at the end: a container
            // that ships more paths than this is not one to keep unpacking
            // into a root while deciding what to do about it.
            return Err(GentooError::database(
                root,
                format!("a container ships more than {MAX_CONTENTS_ENTRIES} paths"),
            )
            .into());
        }
        // A path is bytes and `CONTENTS` is a text file portage reads line by
        // line, so one that is not UTF-8 cannot be recorded -- and a path in
        // the database that does not describe what is on disk is worse than a
        // refusal.
        let path = String::from_utf8(components.join(&b'/').to_vec()).map_err(|_| {
            ProvisionError::from(GentooError::database(
                root,
                "a container ships a path that is not UTF-8",
            ))
        })?;
        laid.push(match entry.typeflag {
            b'5' => Laid::Directory(path),
            b'2' => Laid::Link(
                path,
                String::from_utf8_lossy(&entry.link_target).into_owned(),
                entry.mtime,
            ),
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

/// The ordinal the last merge into `root` was stamped with, or zero for a root
/// nothing has merged into yet.
///
/// Portage keeps one number per root and hands each merge the next, so the
/// database records the order things were installed in. A stage3 arrives with
/// its own -- 391 for the roots this was measured against -- and an increment
/// staged over one has to continue that sequence rather than start again: two
/// packages sharing an ordinal is a database that cannot say which was merged
/// first.
///
/// A layered build therefore asks this of the base as well as of the upper and
/// takes the greater, which is the merged view's answer. An unreadable value is
/// read as zero rather than refused: it is a bookkeeping ordinal, and a root
/// whose counter a caller has damaged is better continued from than refused.
pub(super) fn counter_of(root: &Path, rooted: &Rooted) -> Result<u64, GentooError> {
    match rooted.read(COUNTER_FILE) {
        Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).trim().parse().unwrap_or(0)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(GentooError::io("reading the merge counter", root, err)),
    }
}

#[cfg(test)]
mod tests {
    use super::super::gpkg::fixture::{Built, CPV, planned};
    use super::*;
    use crate::provision::openpgp::fixture;
    use crate::scratch::Scratch;

    /// Merges the fixture container into a fresh root and returns it.
    fn merged(tag: &str, counter: u64) -> Scratch {
        merged_container(tag, counter, Built::ordinary())
    }

    /// The same, for a container a test has bent.
    fn merged_container(tag: &str, counter: u64, built: Built) -> Scratch {
        let dir = Scratch::for_test("gentoo-vdb", tag);
        let key = fixture::signing_key("releng <releng@test.invalid>");
        let container = dir.join("package.gpkg.tar");
        built.write(&container, &key);
        let root = dir.join("root");
        std::fs::create_dir_all(&root).expect("the root is created");
        let rooted = Rooted::open(&root).expect("the root opens");
        let planned = planned(CPV, 1);
        let package = Package::open(&container, &planned, &fixture::keyring(&key))
            .expect("the container opens");
        merge(&root, &rooted, &container, &package, &planned, counter).expect("the package merges");
        dir
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
                "CATEGORY",
                "CONTENTS",
                "COUNTER",
                "PF",
                "SLOT",
                "USE",
            ],
        );
        // The metadata is written through verbatim.
        assert_eq!(read(&dir, "CATEGORY"), "sys-libs\n");
        assert_eq!(read(&dir, "SLOT"), "0/1\n");
        // BINPKGMD5 carries the index's own value and a trailing newline;
        // COUNTER carries the ordinal and none, which is how portage writes
        // each of them.
        assert_eq!(
            read(&dir, "BINPKGMD5"),
            "3a61f698748c7323c87081584f383b3c\n"
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

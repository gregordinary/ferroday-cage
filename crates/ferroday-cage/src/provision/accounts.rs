//! The day each account's password last changed, as a bootstrap's install
//! scripts record it in `/etc/shadow` and the host side reads and dates it, and
//! the id each account and group is given in `/etc/passwd` and `/etc/group`.
//!
//! `shadow(5)` counts that day from 1970, and the tools that create accounts
//! write it from the clock, or from `SOURCE_DATE_EPOCH` where they read one. A
//! bootstrap given an epoch rewrites the days its run wrote wherever a tool
//! dated one otherwise. Which days those are is each format's to say, because
//! the tools differ. busybox's `adduser` reads only the clock, and
//! `systemd-sysusers` writes the epoch's first day as a zero, which `shadow(5)`
//! reads as a demand for a new password rather than as a date. This module is
//! the mechanism both formats share: reading the files from a tree that may be
//! an overlay's upper, and rewriting the days a run wrote.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use super::rooted::{AncestorLink, Merged, Rooted, merged_lookup};

/// The shadow file, and the copy of its previous version the account tools
/// leave beside it on every change.
pub(super) const SHADOW: [&str; 2] = ["etc/shadow", "etc/shadow-"];

/// The seconds in the unit `/etc/shadow` counts in, a day.
pub(super) const SECONDS_PER_DAY: i64 = 24 * 60 * 60;

/// The file a root names its users in, and the one it names its groups in.
#[cfg(feature = "alpine")]
pub(super) const ACCOUNTS: [&str; 2] = ["etc/passwd", "etc/group"];

/// The most of an accounts file a host-side step reads: a [`SHADOW`] file, or
/// one of [`ACCOUNTS`].
///
/// An account is one line of about a hundred bytes, so this is past a hundred
/// thousand of them. A script can make the file any length it likes without
/// writing to it, and this is what such a file meets.
pub(super) const MAX_SHADOW: u64 = 16 * 1024 * 1024;

/// Each account's last-change day, by account name, as a [`SHADOW`] file
/// records it.
pub(super) type Dates = HashMap<Vec<u8>, Vec<u8>>;

/// A step on an accounts file that failed: what it was doing, the file's host
/// path, and the cause. Each format reports it as its own error's `Io`.
#[derive(Debug)]
pub(super) struct Failure {
    /// What the step was doing.
    pub(super) op: &'static str,
    /// The file's host path.
    pub(super) path: PathBuf,
    /// The cause.
    pub(super) source: io::Error,
}

impl Failure {
    /// The same failure as a [`map_err`](Result::map_err) argument, for the
    /// file at `path` in `tree`.
    fn at(op: &'static str, tree: &Rooted, path: &str) -> impl FnOnce(io::Error) -> Failure {
        let path = tree.path(path);
        move |source| Failure { op, path, source }
    }
}

/// The accounts file at `path` as the root `tree` belongs to sees it: the
/// merged view of `tree` over `beneath`, where the tree is a layered build's
/// upper, or `tree` alone.
///
/// `None` is a root that holds no such file: no layer holds one, or the tree
/// hides the base's, by a whiteout at the file, which is a layered build's
/// scripts removing it, or by a whiteout or an opaque directory at `/etc`.
/// [`merged_lookup`] reads the view, with a symbolic link at an ancestor passing
/// the question down, since every layer of a root that carries such a link
/// carries the same one. Whatever the view shows that is not a regular file is
/// refused as [`Rooted::read`] refuses it.
fn read_accounts(
    tree: &Rooted,
    beneath: Option<&Rooted>,
    path: &str,
) -> Result<Option<Vec<u8>>, Failure> {
    let layers: Vec<&Rooted> = std::iter::once(tree).chain(beneath).collect();
    let merged = merged_lookup(&layers, Path::new(path), AncestorLink::PassesDown)
        .map_err(Failure::at("inspecting the accounts", tree, path))?;
    let Merged::Entry { layer } = merged else {
        return Ok(None);
    };
    let holder = layers[layer];
    holder.read(path, MAX_SHADOW).map(Some).map_err(Failure::at(
        "reading the accounts",
        holder,
        path,
    ))
}

/// Each account's last-change day as `/etc/shadow` records it before the
/// scripts run, in the file [`read_accounts`] reads: the tree's, or where the
/// tree holds none and hides none, the one beneath it in a layered build. No
/// file is no accounts.
///
/// The first line naming an account is the one that counts, as `getspnam(3)`
/// reads the file and as [`ids`] reads the other two. A later line naming the
/// same account is one nothing on the root reads.
pub(super) fn account_dates(tree: &Rooted, beneath: Option<&Rooted>) -> Result<Dates, Failure> {
    let [shadow, _] = SHADOW;
    let Some(contents) = read_accounts(tree, beneath, shadow)? else {
        return Ok(Dates::new());
    };
    let mut dates = Dates::new();
    for line in contents.split(|&byte| byte == b'\n') {
        let mut fields = line.split(|&byte| byte == b':');
        let (Some(name), Some(_password), Some(day)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        dates.entry(name.to_vec()).or_insert_with(|| day.to_vec());
    }
    Ok(dates)
}

/// The id each name in the accounts file at `path` is given, as the root sees
/// the file ([`read_accounts`]): the tree's, or where the tree holds none and
/// hides none, the one beneath it in a layered build. `path` is one of
/// [`ACCOUNTS`], both of which keep the id in a line's third field.
///
/// The first line naming an account is the one that counts, as `getpwnam(3)`
/// and `getgrnam(3)` read the files, and a line whose third field is not a
/// number names no id. No file is no accounts.
#[cfg(feature = "alpine")]
pub(super) fn ids(
    tree: &Rooted,
    beneath: Option<&Rooted>,
    path: &str,
) -> Result<HashMap<Vec<u8>, u32>, Failure> {
    let Some(contents) = read_accounts(tree, beneath, path)? else {
        return Ok(HashMap::new());
    };
    let mut ids = HashMap::new();
    for line in contents.split(|&byte| byte == b'\n') {
        let mut fields = line.split(|&byte| byte == b':');
        let (Some(name), Some(_password), Some(id)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Some(id) = super::number::digits::<u32>(id) else {
            continue;
        };
        ids.entry(name.to_vec()).or_insert(id);
    }
    Ok(ids)
}

/// The last-change field `/etc/shadow` records for a change at `epoch`: the
/// day it falls on, counted from 1970.
///
/// Except for day zero, which is empty. A last-change day of zero is not a
/// date to `shadow(5)` but a demand that the password be changed at the next
/// login, and an empty field disables password aging instead. That is what
/// shadow-utils' `useradd` writes for the same epoch.
pub(super) fn last_change_day(epoch: i64) -> String {
    match epoch / SECONDS_PER_DAY {
        0 => String::new(),
        day => day.to_string(),
    }
}

/// Rewrites to `day` every last-change field the run wrote that `rewrites`
/// accepts, in `/etc/shadow` and in the previous version beside it.
///
/// A field the run wrote is one `found` did not record for that account: every
/// account the scripts created, and any whose date they changed. The days the
/// run found stay as they were, so what a package shipped is not rewritten. A
/// file the tree does not hold, which in a layered build is one the
/// increment's scripts never touched, is left to the base, and one they
/// removed is left removed.
///
/// The files are rewritten in place through [`Rooted::overwrite`], keeping the
/// owner, group, and mode the scripts gave them. The host side writes them as
/// the calling user, which is the owner a file created by the sandbox's root
/// has under every identity map. A file a script made read-only is still the
/// calling user's to rewrite, and is given owner write only for as long as the
/// open takes. One a script gave to another account fails the bootstrap rather
/// than going undated.
pub(super) fn redate(
    tree: &Rooted,
    found: &Dates,
    day: &[u8],
    rewrites: impl Fn(&[u8]) -> bool,
) -> Result<(), Failure> {
    for path in SHADOW {
        // The tree's own file alone: what lies beneath is the base's, and
        // nothing this run wrote.
        let Some(contents) = read_accounts(tree, None, path)? else {
            continue;
        };
        if let Some(dated) = redated(&contents, found, day, &rewrites) {
            tree.overwrite(path, &dated)
                .map_err(Failure::at("dating the accounts", tree, path))?;
        }
    }
    Ok(())
}

/// `contents` with every last-change field the run wrote and `rewrites` accepts
/// replaced by `day`, or `None` where there is none to replace.
///
/// Only the third field of a line is touched. A line with fewer fields is not
/// an account, and neither is a later line naming an account an earlier line
/// names, which [`account_dates`] and `getspnam(3)` read past. One already
/// holding `day` has nothing to replace. Every other byte, line endings
/// included, is kept as it stands.
fn redated(
    contents: &[u8],
    found: &Dates,
    day: &[u8],
    rewrites: &impl Fn(&[u8]) -> bool,
) -> Option<Vec<u8>> {
    let mut changed = false;
    let mut named = HashSet::new();
    let lines: Vec<Vec<u8>> = contents
        .split(|&byte| byte == b'\n')
        .map(|line| {
            let mut fields: Vec<&[u8]> = line.split(|&byte| byte == b':').collect();
            let written = fields.len() >= 3
                && named.insert(fields[0])
                && rewrites(fields[2])
                && fields[2] != day
                && found.get(fields[0]).map(Vec::as_slice) != Some(fields[2]);
            if !written {
                return line.to_vec();
            }
            changed = true;
            fields[2] = day;
            fields.join(&b':')
        })
        .collect();
    changed.then(|| lines.join(&b'\n'))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::provision::rooted::scratch_tree;

    /// The accounts `found` in a shadow file, as `account_dates` records them.
    fn found(lines: &[(&str, &str)]) -> Dates {
        lines
            .iter()
            .map(|(name, day)| (name.as_bytes().to_vec(), day.as_bytes().to_vec()))
            .collect()
    }

    /// Any field that is not empty, standing in for a format's own rule.
    fn any_written(field: &[u8]) -> bool {
        !field.is_empty()
    }

    #[test]
    fn only_the_fields_the_run_wrote_are_rewritten() {
        // root as shipped with no date, bin with one the run left alone, and
        // daemon's and klogd's written by the run.
        let before = found(&[("root", ""), ("bin", "17000"), ("daemon", "19000")]);
        let after = b"root:::0:::::\nbin:!:17000:0:::::\ndaemon:!:20722:0:::::\n\
                      klogd:!:20722:0:99999:7:::\n";
        let dated = redated(after, &before, b"19675", &any_written).expect("the run wrote dates");
        assert_eq!(
            dated,
            b"root:::0:::::\nbin:!:17000:0:::::\ndaemon:!:19675:0:::::\n\
              klogd:!:19675:0:99999:7:::\n"
        );
        // Nothing left to rewrite is no rewrite.
        assert_eq!(redated(&dated, &before, b"19675", &any_written), None);
        // Nor is a field the rule declines.
        assert_eq!(redated(after, &before, b"19675", &|_: &[u8]| false), None);
    }

    #[test]
    fn an_account_named_twice_is_the_first_line_naming_it() {
        // `getspnam` reads the first line naming an account and never the
        // second. The day recorded is the first line's, so the run's untouched
        // account is not taken for one it dated, and the second line is not an
        // account to date.
        let (_staging, tree) = scratch_tree("accounts", "shadow-twice");
        let shipped = b"root:*:17000:0:::::\nroot:*:18000:0:::::\n";
        tree.write_mode("etc/shadow", shipped, 0o640).unwrap();
        let before = account_dates(&tree, None).expect("the accounts read");
        assert_eq!(before, found(&[("root", "17000")]));
        assert_eq!(redated(shipped, &before, b"19675", &any_written), None);

        // A run that changed the first line is dated there, and only there.
        let after = b"root:*:20722:0:::::\nroot:*:18000:0:::::\n";
        assert_eq!(
            redated(after, &before, b"19675", &any_written).as_deref(),
            Some(&b"root:*:19675:0:::::\nroot:*:18000:0:::::\n"[..]),
        );
    }

    #[test]
    fn a_line_that_is_not_an_account_is_kept_as_it_stands() {
        // Too few fields, an empty line, and no trailing newline: none is an
        // account, and the bytes around the one rewrite are untouched.
        let after = b"garbage\n\nnew:!:20722";
        assert_eq!(
            redated(after, &found(&[]), b"1", &any_written).as_deref(),
            Some(&b"garbage\n\nnew:!:1"[..]),
        );
    }

    #[test]
    fn the_first_day_of_1970_records_no_date() {
        // A day of zero would demand every account's password be changed at
        // its next login; an empty field disables aging, as useradd writes.
        assert_eq!(last_change_day(0), "");
        assert_eq!(last_change_day(86_399), "");
        assert_eq!(last_change_day(86_400), "1");
        assert_eq!(last_change_day(1_700_000_000), "19675");
    }

    #[test]
    fn the_accounts_are_dated_in_place_in_both_files() {
        let (staging, tree) = scratch_tree("accounts", "shadow");
        let shipped = b"root:::0:::::\n";
        tree.write_mode("etc/shadow", shipped, 0o640).unwrap();
        let before = account_dates(&tree, None).expect("the accounts read");

        // What an account tool leaves: the file with the new account, and the
        // previous version beside it.
        tree.overwrite("etc/shadow", b"root:::0:::::\nklogd:!:20722:0:99999:7:::\n")
            .unwrap();
        tree.write_mode(
            "etc/shadow-",
            b"root:::0:::::\nklogd:!:20722:0:99999:7:::\n",
            0o640,
        )
        .unwrap();
        use std::os::unix::fs::MetadataExt;
        let inode = std::fs::metadata(staging.join("etc/shadow")).unwrap().ino();

        redate(&tree, &before, b"19675", any_written).expect("the accounts are dated");

        for path in SHADOW {
            assert_eq!(
                std::fs::read(staging.join(path)).unwrap(),
                b"root:::0:::::\nklogd:!:19675:0:99999:7:::\n",
                "{path}",
            );
        }
        assert_eq!(
            std::fs::metadata(staging.join("etc/shadow")).unwrap().ino(),
            inode
        );
    }

    #[test]
    fn a_layered_build_reads_the_accounts_of_the_base_beneath_it() {
        // The upper holds no shadow file until a script writes one, so what the
        // run found is the base's.
        let (_base_dir, base) = scratch_tree("accounts", "shadow-base");
        base.write("etc/shadow", b"root:::0:::::\nklogd:!:19000:0:99999:7:::\n")
            .unwrap();
        let (_upper_dir, upper) = scratch_tree("accounts", "shadow-upper");
        let before = account_dates(&upper, Some(&base)).expect("the accounts read");
        assert_eq!(before, found(&[("root", ""), ("klogd", "19000")]));

        // An upper that holds none after the run is left to the base.
        redate(&upper, &before, b"19675", any_written).expect("nothing to date");
        assert!(!upper.exists("etc/shadow").unwrap());
    }

    #[cfg(feature = "alpine")]
    #[test]
    fn a_name_is_given_the_id_its_first_line_states() {
        // As getpwnam reads the file: the first line naming an account counts,
        // and a line whose third field is no number names no id.
        let (_dir, tree) = scratch_tree("accounts", "ids");
        let [passwd, group] = ACCOUNTS;
        tree.write(
            passwd,
            b"root:x:0:0:root:/root:/bin/sh\nmessagebus:x:100:101::/:/sbin/nologin\n\
              messagebus:x:7:7::/:/bin/sh\nbroken:x:+5:0::/:\nempty:x::0::/:\nshort:x\n",
        )
        .unwrap();
        let users = ids(&tree, None, passwd).expect("the file reads");
        let id = |name: &str| users.get(name.as_bytes()).copied();
        assert_eq!(id("root"), Some(0));
        assert_eq!(id("messagebus"), Some(100));
        assert_eq!((id("broken"), id("empty"), id("short")), (None, None, None));

        // No file is no names, and a layered build reads its base's where the
        // upper holds none.
        assert!(ids(&tree, None, group).expect("no file").is_empty());
        let (_upper_dir, upper) = scratch_tree("accounts", "ids-upper");
        tree.write(group, b"messagebus:x:101:\n").unwrap();
        let groups = ids(&upper, Some(&tree), group).expect("the base's file reads");
        assert_eq!(groups.get(&b"messagebus"[..]), Some(&101));
    }

    /// Records an overlay whiteout at `relative` in `staging`, as an overlay
    /// upper does for a name a script removed from the merged root, or
    /// answers `false` where the host refuses one.
    fn whiteout(staging: &Path, relative: &str) -> bool {
        let path = staging.join(relative);
        std::fs::create_dir_all(crate::path::parent_of(&path)).unwrap();
        ferroday_cage_testkit::overlay::whiteout(&path)
    }

    #[test]
    fn a_whiteout_at_the_accounts_is_a_root_with_none() {
        // A layered build whose scripts removed the base's files: the merged
        // root holds neither, so the run found no accounts and has none to date.
        let (_base_dir, base) = scratch_tree("accounts", "whiteout-base");
        base.write("etc/shadow", b"root:::0:::::\nklogd:!:19000:0:99999:7:::\n")
            .unwrap();
        let (upper_dir, upper) = scratch_tree("accounts", "whiteout-upper");
        for path in SHADOW {
            if !whiteout(&upper_dir, path) {
                return;
            }
        }

        let before = account_dates(&upper, Some(&base)).expect("the accounts read");
        assert_eq!(before, Dates::new(), "the base's file is not consulted");
        redate(&upper, &before, b"19675", any_written).expect("nothing to date");
        for path in SHADOW {
            let stat = upper.stat(path).unwrap().expect("the whiteout is kept");
            assert!(Rooted::is_whiteout(&stat), "{path}");
        }

        // Beside a file the scripts did write, the whiteout is still none.
        upper.remove("etc/shadow").unwrap();
        upper
            .write("etc/shadow", b"klogd:!:20722:0:99999:7:::\n")
            .unwrap();
        redate(&upper, &before, b"19675", any_written).expect("the accounts are dated");
        assert_eq!(
            upper.read("etc/shadow", MAX_SHADOW).unwrap(),
            b"klogd:!:19675:0:99999:7:::\n"
        );
    }

    #[test]
    fn an_etc_the_upper_hides_hides_the_bases_accounts() {
        // The merged root shows nothing of the base beneath a whiteout or an
        // opaque directory at `/etc`, so neither does a read of its accounts:
        // the base's `/etc/shadow` and `/etc/passwd` are not the root's.
        let (_base_dir, base) = scratch_tree("accounts", "hidden-etc-base");
        base.write("etc/shadow", b"klogd:!:19000:0:99999:7:::\n")
            .unwrap();
        base.write("etc/passwd", b"klogd:x:100:101::/:/sbin/nologin\n")
            .unwrap();
        let [shadow, _] = SHADOW;

        let (whited_dir, whited) = scratch_tree("accounts", "hidden-etc-whiteout");
        if !whiteout(&whited_dir, "etc") {
            return;
        }
        let (opaque_dir, opaque) = scratch_tree("accounts", "hidden-etc-opaque");
        opaque.write("etc/hostname", b"recreated\n").unwrap();
        if let Err(errno) = rustix::fs::setxattr(
            opaque_dir.join("etc"),
            super::super::containment::OPAQUE,
            b"y",
            rustix::fs::XattrFlags::empty(),
        ) {
            ferroday_cage_testkit::require::OVERLAY
                .skip(format!("this filesystem refuses user attributes ({errno})"));
            return;
        }

        for upper in [&whited, &opaque] {
            let dates = account_dates(upper, Some(&base)).expect("the accounts read");
            assert_eq!(dates, Dates::new(), "the base's shadow is hidden");
            assert!(read_accounts(upper, Some(&base), shadow).unwrap().is_none());
            #[cfg(feature = "alpine")]
            assert!(
                ids(upper, Some(&base), "etc/passwd").unwrap().is_empty(),
                "the base's passwd is hidden",
            );
        }

        // A plain `/etc` in the upper hides nothing: the base's file shows.
        let (_plain_dir, plain) = scratch_tree("accounts", "hidden-etc-plain");
        plain.write("etc/hostname", b"kept\n").unwrap();
        assert_eq!(
            account_dates(&plain, Some(&base)).unwrap(),
            found(&[("klogd", "19000")]),
        );
    }
}

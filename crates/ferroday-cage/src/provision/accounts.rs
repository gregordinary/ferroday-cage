//! The day each account's password last changed, as a bootstrap's install
//! scripts record it in `/etc/shadow` and the host side reads and dates it.
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

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

use super::rooted::Rooted;

/// The shadow file, and the copy of its previous version the account tools
/// leave beside it on every change.
pub(super) const SHADOW: [&str; 2] = ["etc/shadow", "etc/shadow-"];

/// The seconds in the unit `/etc/shadow` counts in, a day.
pub(super) const SECONDS_PER_DAY: i64 = 24 * 60 * 60;

/// The most of a [`SHADOW`] file a host-side step reads.
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

/// What an accounts file holds, as the root the tree belongs to sees it.
enum Accounts {
    /// The tree holds the file, with these contents.
    Held(Vec<u8>),
    /// The tree holds an overlay whiteout there. A layered build's scripts
    /// removed the base's file, so the merged root holds none.
    Removed,
    /// Nothing occupies the name in the tree.
    Absent,
}

impl Accounts {
    /// Reads the accounts file at `path`, stating what occupies it first.
    ///
    /// A whiteout is a character device, and opening one fails, so the kind is
    /// told apart before anything is opened. Whatever else is there that is not
    /// a regular file is refused as [`Rooted::read`] refuses it.
    fn read(tree: &Rooted, path: &str) -> Result<Accounts, Failure> {
        let held = tree
            .stat(path)
            .map_err(Failure::at("inspecting the accounts", tree, path))?;
        match held {
            None => Ok(Accounts::Absent),
            Some(stat) if Rooted::is_whiteout(&stat) => Ok(Accounts::Removed),
            Some(_) => tree
                .read(path, MAX_SHADOW)
                .map(Accounts::Held)
                .map_err(Failure::at("reading the accounts", tree, path)),
        }
    }
}

/// Each account's last-change day as `/etc/shadow` records it before the
/// scripts run: the file in the tree, or where the tree holds none, the one
/// beneath it in a layered build. No file is no accounts, and neither is a
/// whiteout, which removes the base's file from the merged root.
pub(super) fn account_dates(tree: &Rooted, beneath: Option<&Rooted>) -> Result<Dates, Failure> {
    let [shadow, _] = SHADOW;
    let held = match (Accounts::read(tree, shadow)?, beneath) {
        (Accounts::Absent, Some(beneath)) => Accounts::read(beneath, shadow)?,
        (held, _) => held,
    };
    let Accounts::Held(contents) = held else {
        return Ok(Dates::new());
    };
    Ok(contents
        .split(|&byte| byte == b'\n')
        .filter_map(|line| {
            let mut fields = line.split(|&byte| byte == b':');
            let name = fields.next()?;
            let _password = fields.next()?;
            Some((name.to_vec(), fields.next()?.to_vec()))
        })
        .collect())
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
/// The files are rewritten in place, keeping the owner, group, and mode the
/// scripts gave them. The host side writes them as the calling user, which is
/// the owner a file created by the sandbox's root has under every identity map.
/// So each must leave its owner write permission, as the `0640` the
/// distributions ship does. One a script made read-only, or gave to another
/// account, fails the bootstrap rather than going undated.
pub(super) fn redate(
    tree: &Rooted,
    found: &Dates,
    day: &[u8],
    rewrites: impl Fn(&[u8]) -> bool,
) -> Result<(), Failure> {
    for path in SHADOW {
        let Accounts::Held(contents) = Accounts::read(tree, path)? else {
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
/// an account, and one already holding `day` has nothing to replace. Every
/// other byte, line endings included, is kept as it stands.
fn redated(
    contents: &[u8],
    found: &Dates,
    day: &[u8],
    rewrites: &impl Fn(&[u8]) -> bool,
) -> Option<Vec<u8>> {
    let mut changed = false;
    let lines: Vec<Vec<u8>> = contents
        .split(|&byte| byte == b'\n')
        .map(|line| {
            let mut fields: Vec<&[u8]> = line.split(|&byte| byte == b':').collect();
            let written = fields.len() >= 3
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
    use crate::scratch::Scratch;

    /// A scratch tree, and the same tree opened as the scripts' host side
    /// opens it.
    fn rooted_tree(tag: &str) -> (Scratch, Rooted) {
        let scratch = Scratch::for_test("accounts", tag);
        let tree = Rooted::open(&scratch).expect("the scratch tree opens");
        (scratch, tree)
    }

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
        let (staging, tree) = rooted_tree("shadow");
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
        let (_base_dir, base) = rooted_tree("shadow-base");
        base.write("etc/shadow", b"root:::0:::::\nklogd:!:19000:0:99999:7:::\n")
            .unwrap();
        let (_upper_dir, upper) = rooted_tree("shadow-upper");
        let before = account_dates(&upper, Some(&base)).expect("the accounts read");
        assert_eq!(before, found(&[("root", ""), ("klogd", "19000")]));

        // An upper that holds none after the run is left to the base.
        redate(&upper, &before, b"19675", any_written).expect("nothing to date");
        assert!(!upper.exists("etc/shadow").unwrap());
    }

    /// Records an overlay whiteout at `relative` in `tree`, as an overlay
    /// upper does for a name a script removed from the merged root, or reports
    /// why the host refused to.
    fn whiteout(staging: &Path, relative: &str) -> Result<(), rustix::io::Errno> {
        let parent = staging.join(relative).parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&parent).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            staging.join(relative),
            rustix::fs::FileType::CharacterDevice,
            rustix::fs::Mode::from_raw_mode(0),
            0,
        )
    }

    #[test]
    fn a_whiteout_at_the_accounts_is_a_root_with_none() {
        // A layered build whose scripts removed the base's files: the merged
        // root holds neither, so the run found no accounts and has none to date.
        let (_base_dir, base) = rooted_tree("whiteout-base");
        base.write("etc/shadow", b"root:::0:::::\nklogd:!:19000:0:99999:7:::\n")
            .unwrap();
        let (upper_dir, upper) = rooted_tree("whiteout-upper");
        for path in SHADOW {
            if let Err(errno) = whiteout(&upper_dir, path) {
                // Linux 5.8 is the first to let an unprivileged caller record
                // one.
                ferroday_cage_testkit::require::OVERLAY.skip(format!(
                    "the host refused an unprivileged whiteout: {errno}"
                ));
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
}

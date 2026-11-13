//! Choosing what to install: which builds answer the caller's atoms, and in
//! what order they merge.
//!
//! The algorithm is deliberately predictable, and its whole value is that a
//! reader can say what it will do:
//!
//! 1. Seed a queue with the caller's atoms.
//! 2. An atom already satisfied — by the root's installed set, or by something
//!    the resolution has already chosen — is done.
//! 3. Otherwise take the index's builds of the atom's package that the atom
//!    admits, keep those at the highest version among them, and rank the rest.
//! 4. Queue the chosen build's `RDEPEND` and `PDEPEND`.
//! 5. An `|| ( ... )` group with a satisfied alternative is done; otherwise its
//!    first alternative is taken whose every atom is answered, or answered by a
//!    build that takes no slot anything already holds. An alternative is what
//!    the group lists together, so `|| ( a ( b c ) )` takes `b` and `c` both or
//!    neither.
//! 6. A blocker is checked against the finished set, and a match is a conflict.
//!    That is a blocker a chosen build states against the root or the
//!    resolution, and one a package the root already has states against the
//!    resolution.
//! 7. An atom nothing answers is unsatisfiable, and the refusal says which of
//!    the name, the version, the slot or a USE flag was the wall.
//!
//! # Which build, and why it decides the outcome
//!
//! The archive publishes a version more than once — 2,774 of them, up to
//! twenty-four times — and the builds differ in the USE flags they were
//! compiled with, and so in what they depend on. Choosing among them is
//! therefore not a tie-break. Measured over four hundred sampled package names
//! against an `amd64-openrc` stage3:
//!
//! | Rule | Resolves cleanly | Unsatisfiable atoms | Conflicts | p90 closure |
//! | --- | --- | --- | --- | --- |
//! | newest build time | 262/400 | 884 | 129 | 173 |
//! | fewest dependencies | 338/400 | 206 | 74 | 148 |
//! | fewest USE flags | 361/400 | 26 | 50 | 126 |
//!
//! Fewest USE flags wins every column at once, which is the argument for it: it
//! is not a trade. Portage makes the same choice from a profile's computed USE;
//! this layer has no profile, so it needs a rule of its own, and the rule is
//! the one the numbers chose.
//!
//! # A preference reorders; it cannot refuse
//!
//! A caller who needs a flag states it in the atom, where it is a constraint:
//! `dev-vcs/git[keyring]` removes every build without the flag, and if none is
//! left the atom is unsatisfiable and says so. A caller who has a taste states
//! it as a preference, which sorts the candidates and removes none — so it
//! cannot turn a resolvable request into an unresolvable one. Over the same
//! four hundred seeds the unsatisfiable count is 26 with no preference and 26
//! under every preference tried, including one broad enough to halve the clean
//! resolutions. What a broad preference costs is a larger closure, which meets
//! more of the archive's own conflicts.
//!
//! # No backtracking
//!
//! A conflict is reported rather than resolved around, on the evidence: an
//! any-of policy that preferred a non-conflicting alternative changed nothing
//! over the same four hundred seeds, and the conflicts that remain are ones
//! portage refuses too — a desktop stack asked for in a root built against the
//! other init system. Backtracking is additive if measurement later disagrees.
//!
//! An any-of group passing over an alternative whose build would take an
//! occupied slot is not backtracking. The slot is held before the group is
//! read, so the group chooses among its alternatives with that already known,
//! and no choice made earlier is revisited.
//!
//! # What an index can make it spend
//!
//! Nothing signs the index, so a resolution is bounded in the work it does as
//! well as in what it chooses. It takes at most [`MAX_CLOSURE`] builds, reads
//! at most [`MAX_DEPENDENCIES`] atoms from them, and holds atoms against at
//! most [`MAX_COMPARISONS`] candidates, reading at most
//! [`MAX_COMPARED_BYTES`] of them to do it. It records at most
//! [`MAX_REFUSALS`] refusals. Each is far past what resolving the whole
//! archive takes, and reaching one stops the resolution where it stands. What
//! the index offers for an atom is worked out once per spelling, so a
//! dependency the archive's builds repeat is paid for once.
//!
//! The comparisons are bounded in what each one reads, and not only in their
//! number, because the index decides that too. The fields of a record are held
//! to lengths as they are read (see [`index`](super::index)), and an atom to a
//! `CPV`'s length and to 64 USE dependencies (see [`atom`](super::atom)), so
//! one comparison with a record reads at most about two MiB: a USE dependency
//! is answered by scanning the candidate's flag lists. That is far from what a
//! real one reads, so each comparison is also charged what it reads before it
//! is made, and the one that would take the resolution past
//! [`MAX_COMPARED_BYTES`] is not made. The same field lengths bound what a
//! refusal copies out of a record.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::rc::Rc;

use super::atom::{self, Atom, Candidate, Dependency, Unmet};
use super::index::{Index, Record};
use super::installed::{Installed, InstalledPackage, slot_of};
use super::plan::PlannedPackage;
use super::version;

/// A USE flag the caller would rather a build carried, or rather it did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Preference {
    /// The flag's name.
    flag: String,
    /// Whether the caller prefers it on or off.
    wanted: bool,
}

impl Preference {
    /// Reads one preference, `flag` or `-flag`.
    ///
    /// # Errors
    ///
    /// Returns the reason where the text does not name a flag.
    pub(super) fn parse(text: &str) -> Result<Preference, String> {
        let (wanted, flag) = match text.strip_prefix('-') {
            Some(flag) => (false, flag),
            None => (true, text),
        };
        // The atom grammar's own rule, not a second one: a preference naming a
        // flag an atom could not name would silently never be met.
        if !atom::is_flag(flag) {
            return Err(format!("{text:?} does not name a USE flag"));
        }
        Ok(Preference {
            flag: flag.to_string(),
            wanted,
        })
    }

    /// Whether `record` is the way this preference would have it.
    fn met_by(&self, record: &Record) -> bool {
        record.has_use(&self.flag) == self.wanted
    }
}

/// What a resolution produced.
pub(super) struct Resolved {
    /// The chosen builds, in the order they merge.
    pub packages: Vec<Record>,
    /// Every runtime-dependency cycle the order broke, each naming the
    /// packages that form it, in name order.
    pub cycles: Vec<Vec<String>>,
}

/// Why an atom could not be satisfied.
///
/// Carried out of the resolver so the wave can report each one before the run
/// fails, rather than a caller learning only that something did not resolve.
pub(super) struct Unsatisfied {
    /// The atom, as it was written.
    pub atom: String,
    /// Who asked for it: the caller, or the package whose dependency it is.
    ///
    /// Shared with every other refusal of a dependency the same package
    /// states, rather than copied into each.
    pub wanted_by: Rc<str>,
    /// What the wall was, in the sentence "no build ...".
    pub reason: String,
}

/// A blocker that matched something the root has or the resolution chose.
pub(super) struct Conflict {
    /// The blocker atom, as it was written.
    pub atom: String,
    /// The package that states it, as `category/name-version`, shared with
    /// every other conflict a blocker it states makes.
    pub stated_by: Rc<str>,
    /// Whether the package stating it is already in the root, rather than a
    /// build this resolution chose.
    pub stated_in_root: bool,
    /// What it matched, as `category/name-version`.
    pub blocks: String,
    /// Whether what it matched is already in the root or would be installed.
    pub installed: bool,
}

/// A build a resolution chose that would occupy a slot of a package something
/// already holds.
///
/// Portage keeps one instance per `(package, slot)` and refuses to create a
/// second, so a root holding two is a root `emerge` reports as a conflict. A
/// resolution that produced one and merged it anyway would lay both images down
/// with the second overwriting the first's shared paths, and report success.
///
/// The holder is another build this resolution chose, or a package the root
/// already has: a merge registers a database entry beside whatever is there and
/// unmerges nothing, so a same-slot upgrade over the root produces exactly the
/// state two chosen builds would.
pub(super) struct Occupied {
    /// The package, as `category/name`.
    pub name: String,
    /// The slot both would occupy, without a sub-slot.
    pub slot: String,
    /// What already holds the slot, as `category/name-version` — and which
    /// build of it, where it is one this resolution chose. An installed package
    /// has no build to name.
    pub held: String,
    /// Whether what holds the slot is already in the root or would be installed
    /// by this same resolution.
    pub installed: bool,
    /// The build the second atom would have chosen, spelled the same way.
    pub second: String,
    /// The atom that asked for the second, as it was written.
    pub atom: String,
    /// Who asked for it: the caller, or the package whose dependency it is,
    /// shared as [`Unsatisfied::wanted_by`] is.
    pub wanted_by: Rc<str>,
}

/// Everything one resolution refused, in the order it met them, up to
/// [`MAX_REFUSALS`] of them.
#[derive(Default)]
pub(super) struct Refusals {
    pub unsatisfied: Vec<Unsatisfied>,
    pub conflicts: Vec<Conflict>,
    pub occupied: Vec<Occupied>,
    /// The bound the resolution reached, which stopped it where it stood.
    pub exceeded: Option<Bound>,
}

/// A bound one resolution reached.
///
/// Each bounds what an index nothing signs can make a run spend before any
/// signature is consulted, and each is set well past what resolving against
/// the whole archive spends. A resolution reaching one is resolving against an
/// index this layer does not resolve against, so it stops and refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Bound {
    /// The closure grew past [`MAX_CLOSURE`] builds.
    Closure,
    /// The builds chosen stated more than [`MAX_DEPENDENCIES`] atoms.
    Dependencies,
    /// Atoms were held against more than [`MAX_COMPARISONS`] candidates.
    Comparisons,
    /// Holding atoms against candidates would read more than
    /// [`MAX_COMPARED_BYTES`] of them.
    ComparedBytes,
    /// The resolution met a refusal past the [`MAX_REFUSALS`] it records.
    Refusals,
}

impl Refusals {
    /// Whether one more refusal may be recorded.
    ///
    /// Where it may not, the resolution has met more than [`MAX_REFUSALS`],
    /// which is recorded as the bound it reached.
    fn has_room(&mut self) -> bool {
        let recorded = self.unsatisfied.len() + self.conflicts.len() + self.occupied.len();
        if recorded < MAX_REFUSALS {
            return true;
        }
        self.exceeded.get_or_insert(Bound::Refusals);
        false
    }

    /// Whether the resolution can be acted on.
    pub(super) fn is_empty(&self) -> bool {
        self.unsatisfied.is_empty()
            && self.conflicts.is_empty()
            && self.occupied.is_empty()
            && self.exceeded.is_none()
    }

    /// The whole refusal as one sentence a caller reads.
    pub(super) fn describe(&self) -> String {
        let mut parts = Vec::new();
        match self.exceeded {
            None => {}
            Some(Bound::Closure) => parts.push(format!(
                "the closure grew past {MAX_CLOSURE} builds, more than twice every package slot \
                 the archive publishes, so the index is not one this layer resolves against",
            )),
            Some(Bound::Dependencies) => parts.push(format!(
                "the builds chosen state more than {MAX_DEPENDENCIES} dependency atoms, more \
                 than twice every one the archive publishes, so the index is not one this layer \
                 resolves against",
            )),
            Some(Bound::Comparisons) => parts.push(format!(
                "the resolution held atoms against more than {MAX_COMPARISONS} candidate builds, \
                 far more than resolving the whole archive takes, so the index is not one this \
                 layer resolves against",
            )),
            Some(Bound::ComparedBytes) => parts.push(format!(
                "holding atoms against candidate builds would read more than \
                 {MAX_COMPARED_BYTES} bytes of their versions, slots and USE flags, far more \
                 than resolving the whole archive reads, so the index is not one this layer \
                 resolves against",
            )),
            Some(Bound::Refusals) => parts.push(format!(
                "the resolution stopped after {MAX_REFUSALS} refusals, more than asking for every \
                 package the archive publishes meets, and these are the ones it met",
            )),
        }
        for unmet in &self.unsatisfied {
            parts.push(format!(
                "{} requires {}, and no build {}",
                unmet.wanted_by, unmet.atom, unmet.reason,
            ));
        }
        for conflict in &self.conflicts {
            parts.push(format!(
                "{}{} blocks {} with {}, and {} would {}",
                conflict.stated_by,
                if conflict.stated_in_root {
                    ", which the root has,"
                } else {
                    ""
                },
                conflict.blocks,
                conflict.atom,
                conflict.blocks,
                if conflict.installed {
                    "have to be removed from the root first"
                } else {
                    "be installed by this same resolution"
                },
            ));
        }
        for taken in &self.occupied {
            parts.push(format!(
                "{} requires {}, and {} would occupy slot {:?} of {}, which {} already takes {}",
                taken.wanted_by,
                taken.atom,
                taken.second,
                taken.slot,
                taken.name,
                taken.held,
                if taken.installed {
                    "in the root"
                } else {
                    "in this same resolution"
                },
            ));
        }
        parts.join("; ")
    }
}

/// One atom waiting to be resolved, and who asked for it.
struct Pending {
    dependency: Dependency,
    /// Who asked for it, shared by every dependency one build states.
    wanted_by: Rc<str>,
    /// The chosen build whose merge this dependency orders, where it orders
    /// one: a plain atom of that build's `RDEPEND`.
    ///
    /// `None` for the caller's own atoms, for a `PDEPEND`, and for an any-of
    /// group, whose alternatives were resolved as a choice rather than as a
    /// requirement of the build that states them.
    orders: Option<usize>,
}

/// The most builds one resolution chooses before it refuses the index it is
/// resolving against.
///
/// A closure holds at most one build in each slot of each package, and the
/// archive publishes about seven and a half thousand package slots in all
/// (7,440 when this was measured), so a resolution reaching this has chosen
/// more than twice the whole archive. A real closure is far smaller: over the
/// four hundred sampled package names above, the p90 is 126.
///
/// What it bounds is what an index nothing signs can make a run spend before
/// any signature is consulted: a package cache directory created for every
/// chosen build, a download scheduled for each, and a plan and an install
/// order holding them all.
const MAX_CLOSURE: usize = 16_384;

/// The most dependency atoms the builds one resolution chooses may state
/// between them.
///
/// The closure bound counts builds, and a build's dependency classes are what
/// it costs once chosen: each atom is queued to be settled and may be refused,
/// and a parsed atom is several times the four bytes `a/b ` takes to write
/// one. Asking for every package name the live index publishes at once, over
/// an empty root, reads 35,178. The index states 99,201 across all of its
/// builds, and this is two and a half times that.
const MAX_DEPENDENCIES: usize = 256 * 1024;

/// The most candidates one resolution holds atoms against.
///
/// Every question asked of an atom is asked of the builds published, chosen or
/// installed under its name, and the index decides how many there are: one
/// name can carry as many builds as the index has room for, and as many slots
/// as the closure. An atom nothing answers is not bounded by the closure, so
/// an index publishing many builds of one name, and many distinct atoms naming
/// it, would cost their product. Counting each candidate bounds how many
/// comparisons that shape can make, and [`MAX_COMPARED_BYTES`] what they read.
/// Two versions compared to choose between builds, a build ranked among those
/// of its version, and a slot compared to find what holds one count as
/// comparisons too.
///
/// Asking for every package name the live index publishes at once, over an
/// empty root, makes 83,879 comparisons. This is fifty times that, and a
/// fraction of a second of comparing versions.
const MAX_COMPARISONS: usize = 4 * 1024 * 1024;

/// The most bytes the comparisons of one resolution may read.
///
/// What one comparison reads is [`Atom::reads`]: the two versions, the slot,
/// and for every USE dependency the candidate's two flag lists. Those are
/// bounded, but by lengths far past what the archive publishes, so one
/// comparison an index shapes can read thousands of times what a real one
/// does: up to two MiB, against the 89 bytes the live index's comparisons
/// average. Each is charged what it reads before it is made, so a resolution
/// reaching this has read no more than this, and the comparison that would
/// have taken it past is the one not made.
///
/// Asking for every package name the live index publishes at once, over an
/// empty root, reads 7,491,768 bytes. This is nearly eighteen times that, and a
/// fraction of a second of reading even the costliest bytes there are to read:
/// versions as long as a `CPV` allows, each parsed again for every comparison.
const MAX_COMPARED_BYTES: usize = 128 * 1024 * 1024;

/// The most refusals one resolution records.
///
/// Every refusal is recorded and reported rather than only the first, which is
/// what a caller fixing an install list wants. A refusal costs what it names:
/// the atom, the build and the slot, copies of what a record states, each held
/// to a length. And how many there are is the index's to decide. One build can
/// state thousands of atoms nothing answers, and every blocker the chosen
/// builds state is held against every build chosen under its name, so their
/// conflicts grow with the product of the two. A resolution that meets more
/// than this stops where it stands, and reports these.
///
/// Asking for every package name the live index publishes at once, over an
/// empty root, meets 1,544. This is over ten times that.
const MAX_REFUSALS: usize = 16 * 1024;

/// Resolves `wanted` against `index` and what `installed` already holds.
///
/// Reports every refusal rather than stopping at the first: a caller fixing an
/// install list wants the whole list of what the archive cannot give them, and
/// an atom nothing answers only stops the branch below it. The one exception is
/// a [`Bound`] reached, which stops the resolution where it stands.
pub(super) fn resolve(
    index: &Index,
    installed: &Installed,
    wanted: &[Atom],
    prefer: &[Preference],
) -> (Resolved, Refusals) {
    let run = settle(index, installed, wanted, prefer);
    let (packages, cycles) = order(run.chosen.all, run.needs);
    (Resolved { packages, cycles }, run.refusals)
}

/// Everything [`resolve`] does but order what it chose: settles every
/// dependency, and holds every blocker met to what was chosen.
fn settle<'a>(
    index: &'a Index,
    installed: &'a Installed,
    wanted: &[Atom],
    prefer: &'a [Preference],
) -> Resolution<'a> {
    let caller: Rc<str> = Rc::from("the install list");
    let mut run = Resolution {
        index,
        installed,
        prefer,
        queue: wanted
            .iter()
            .map(|atom| Pending {
                dependency: Dependency::One(atom.clone()),
                wanted_by: Rc::clone(&caller),
                orders: None,
            })
            .collect(),
        chosen: Builds::default(),
        needs: Vec::new(),
        blockers: Vec::new(),
        offers: HashMap::new(),
        stated: 0,
        compared: Comparisons::bounded(),
        refusals: Refusals::default(),
    };
    // Reversed so the queue pops in the order the caller wrote them, which is
    // what makes a resolution reproducible from an install list rather than
    // from a set.
    run.queue.reverse();

    while !run.stopped()
        && let Some(pending) = run.queue.pop()
    {
        match &pending.dependency {
            Dependency::One(atom) => run.require(atom, &pending.wanted_by, pending.orders),
            Dependency::AnyOf(alternatives) => run.any_of(alternatives, &pending.wanted_by),
        }
    }

    if !run.stopped() {
        conflicts(
            &run.blockers,
            installed,
            &run.chosen,
            &mut run.compared,
            &mut run.refusals,
        );
        run.stopped();
    }
    run
}

/// One resolution part way through.
struct Resolution<'a> {
    index: &'a Index,
    installed: &'a Installed,
    prefer: &'a [Preference],
    /// The dependencies still to settle, popped from the end.
    queue: Vec<Pending>,
    /// The builds chosen so far, in the order they were chosen.
    chosen: Builds<Record>,
    /// `needs[i]`: the chosen builds `chosen[i]` merges after, which are the
    /// ones that answered its runtime atoms.
    ///
    /// Recorded as each atom is answered rather than worked out again from the
    /// atoms afterwards. The resolution has already said which build answers
    /// an atom, and an order that asked again of every build the atom admits
    /// would hold an edge for each pair of them: a set that grows with the
    /// square of the closure, for an index that publishes many builds an atom
    /// admits.
    needs: Vec<Vec<usize>>,
    /// Every blocker met, and who stated it.
    ///
    /// Collected and checked at the end rather than as they arrive: a blocker
    /// met early would pass against a set the resolution had not finished
    /// choosing, and the package it refuses may be chosen later.
    blockers: Vec<(Atom, Rc<str>)>,
    /// What the index offers for each atom asked of it, by the atom as written.
    ///
    /// An offer depends on nothing the resolution changes as it goes, only on
    /// the index and the preferences, so it is worked out once per spelling.
    /// The archive's dependencies repeat: thousands of builds state
    /// `dev-libs/glib:2`.
    offers: HashMap<String, Offer<'a>>,
    /// How many dependency atoms the builds chosen so far state.
    stated: usize,
    /// How many candidates atoms have been held against so far.
    compared: Comparisons,
    refusals: Refusals,
}

/// What the index offers for one atom.
#[derive(Clone, Copy)]
enum Offer<'a> {
    /// The build to install.
    Build(&'a Record),
    /// No build it publishes under the name answers the atom, and the one
    /// that got furthest failed here.
    Unmet(Unmet),
    /// It publishes nothing under the name.
    Unpublished,
}

/// How many comparisons a resolution has made and what they read, and how
/// many and how much they may.
struct Comparisons {
    /// How many comparisons have been charged.
    made: usize,
    /// How many bytes they read, as [`Atom::reads`] counts them.
    read: usize,
    /// The most comparisons, past which the next is not made.
    most: usize,
    /// The most bytes, past which the next comparison is not made.
    most_read: usize,
}

impl Comparisons {
    /// None made, and at most [`MAX_COMPARISONS`] comparisons reading at most
    /// [`MAX_COMPARED_BYTES`] between them to make.
    fn bounded() -> Comparisons {
        Comparisons::up_to(MAX_COMPARISONS, MAX_COMPARED_BYTES)
    }

    /// None made, and as many to make as there are.
    ///
    /// For holding a caller's own plan to a root, which no mirror composed.
    fn unbounded() -> Comparisons {
        Comparisons::up_to(usize::MAX, usize::MAX)
    }

    /// None made, and at most `most` comparisons reading at most `most_read`
    /// bytes between them to make.
    fn up_to(most: usize, most_read: usize) -> Comparisons {
        Comparisons {
            made: 0,
            read: 0,
            most,
            most_read,
        }
    }

    /// Charges one comparison reading `bytes`, and answers whether the bounds
    /// allow it to be made.
    ///
    /// Charged before the comparison rather than after, so one the bounds
    /// refuse is never made: a comparison an index makes expensive costs its
    /// charge and nothing more.
    #[must_use]
    fn charge(&mut self, bytes: usize) -> bool {
        self.made = self.made.saturating_add(1);
        self.read = self.read.saturating_add(bytes);
        !self.spent()
    }

    /// Whether the comparisons charged have passed a bound.
    fn spent(&self) -> bool {
        self.exceeded().is_some()
    }

    /// The bound the comparisons charged have passed, where they have.
    fn exceeded(&self) -> Option<Bound> {
        if self.made > self.most {
            Some(Bound::Comparisons)
        } else if self.read > self.most_read {
            Some(Bound::ComparedBytes)
        } else {
            None
        }
    }
}

/// Where one atom stands against a resolution so far.
enum Answer<'a> {
    /// Answered already: by the root, or by the chosen build at this index.
    Held(Option<usize>),
    /// Answered by this build the index publishes, which takes no slot
    /// anything already holds.
    Free(&'a Record),
    /// The build the index would answer it with takes a slot something already
    /// holds: the build, what holds the slot as a refusal names it, and whether
    /// that is in the root.
    Taken(&'a Record, String, bool),
    /// Nothing the index publishes answers it.
    Unmet,
    /// The comparisons reached a bound before an answer was found, so the
    /// resolution stops here and the atom is neither answered nor refused.
    Stopped,
}

impl<'a> Resolution<'a> {
    /// Whether the resolution has reached a [`Bound`].
    ///
    /// The comparisons are charged wherever an atom meets a candidate, so
    /// their two bounds are noticed here; the others are recorded where they
    /// are reached.
    fn stopped(&mut self) -> bool {
        if self.refusals.exceeded.is_none() {
            self.refusals.exceeded = self.compared.exceeded();
        }
        self.refusals.exceeded.is_some()
    }

    /// What already answers `atom`: the root (`Some(None)`), the chosen build
    /// at an index, or nothing.
    ///
    /// The root first, which is the whole reason resolution here starts from a
    /// populated root.
    ///
    /// Where the comparisons reach a bound part way, this answers nothing, and
    /// the caller, which asks [`stopped`](Self::stopped) before it acts on an
    /// answer, stops.
    fn held(&mut self, atom: &Atom) -> Option<Option<usize>> {
        for package in self.installed.under(atom.name()) {
            if !self.compared.charge(atom.reads(package)) {
                return None;
            }
            if atom.matches(package) {
                return Some(None);
            }
        }
        for (at, build) in self.chosen.under(atom.name()) {
            if !self.compared.charge(atom.reads(build)) {
                return None;
            }
            if atom.matches(build) {
                return Some(Some(at));
            }
        }
        None
    }

    /// What the index offers for `atom`, worked out once per spelling, or
    /// `None` where the comparisons reached a bound before it was.
    ///
    /// An offer cut short is not kept, so nothing later reads one as the
    /// index's answer.
    fn offer(&mut self, atom: &Atom) -> Option<Offer<'a>> {
        if let Some(offer) = self.offers.get(atom.text()) {
            return Some(*offer);
        }
        let offer = offer(self.index, atom, self.prefer, &mut self.compared)?;
        self.offers.insert(atom.text().to_string(), offer);
        Some(offer)
    }

    /// Where `atom` stands: answered, answerable, or not.
    ///
    /// One instance per slot is the invariant portage's own database keeps, so
    /// a build sharing a slot with anything already chosen or installed is not
    /// an answer: the atom is answered by neither -- [`held`](Self::held) asked
    /// that first -- so the two would be two versions of one package in one
    /// slot. Merging both would lay two images down with the second overwriting
    /// the first's shared paths, and leave a `/var/db/pkg` portage reads as a
    /// conflict.
    ///
    /// The root holds a slot as firmly as the resolution does. A merge
    /// registers its entry beside what is already there and unmerges nothing,
    /// so a same-slot upgrade over a stage3 is the same defect reached from the
    /// other side: the caller's answer is a root whose version the atom admits,
    /// not a second copy of the package.
    fn answer(&mut self, atom: &Atom) -> Answer<'a> {
        if let Some(at) = self.held(atom) {
            return Answer::Held(at);
        }
        if self.stopped() {
            return Answer::Stopped;
        }
        let record = match self.offer(atom) {
            Some(Offer::Build(record)) => record,
            Some(Offer::Unmet(_) | Offer::Unpublished) => return Answer::Unmet,
            None => return Answer::Stopped,
        };
        let held = occupant(record, &self.chosen, self.installed, &mut self.compared);
        if self.stopped() {
            return Answer::Stopped;
        }
        match held {
            Some((held, installed)) => Answer::Taken(record, held, installed),
            None => Answer::Free(record),
        }
    }

    /// Settles one plain atom `wanted_by` asked for: records it as a blocker,
    /// or answers it, choosing a build where nothing chosen or installed
    /// already does.
    ///
    /// `orders` is the chosen build that merges after whatever answers it,
    /// where the atom is one of that build's runtime dependencies.
    ///
    /// A collision with an occupied slot is reported rather than resolved
    /// around, which is the module's stance on a conflict generally: nothing
    /// here backtracks, and the caller's atoms are what would have to change.
    fn require(&mut self, atom: &Atom, wanted_by: &Rc<str>, orders: Option<usize>) {
        if atom.blocker().is_some() {
            self.blockers.push((atom.clone(), Rc::clone(wanted_by)));
            return;
        }
        match self.answer(atom) {
            Answer::Held(at) => self.order_after(orders, at),
            Answer::Free(record) => {
                let at = self.choose(record);
                self.order_after(orders, at);
            }
            Answer::Taken(record, held, installed) => {
                self.refuse_occupied(record, held, installed, atom.to_string(), wanted_by);
            }
            Answer::Unmet => {
                if self.refusals.has_room() {
                    let reason = self.wall(&[atom]);
                    self.refusals.unsatisfied.push(Unsatisfied {
                        atom: atom.to_string(),
                        wanted_by: Rc::clone(wanted_by),
                        reason,
                    });
                }
            }
            Answer::Stopped => {}
        }
    }

    /// Settles an any-of group `wanted_by` asked for.
    ///
    /// A group of one alternative asks for exactly that alternative's atoms,
    /// blockers included, which is the plain-atom case. In a group of several,
    /// a blocker is one alternative among several and binds nothing on its
    /// own, so an alternative is satisfied when every atom in it that names
    /// something to install is.
    ///
    /// A group with a satisfied alternative is done. Otherwise its first
    /// alternative is taken whose every atom is answered or answerable without
    /// taking an occupied slot: an alternative that would collide is passed
    /// over for the next, which is a choice the group offers rather than
    /// backtracking.
    ///
    /// A group can be as long as a dependency class, so the resolution's
    /// bounds are consulted atom by atom rather than only between groups.
    fn any_of(&mut self, alternatives: &[Vec<Atom>], wanted_by: &Rc<str>) {
        if let [only] = alternatives {
            for atom in only {
                if self.stopped() {
                    return;
                }
                self.require(atom, wanted_by, None);
            }
            return;
        }
        let installs = |atom: &&Atom| atom.blocker().is_none();
        for together in alternatives {
            let mut held = true;
            for atom in together.iter().filter(installs) {
                if self.stopped() {
                    return;
                }
                if self.held(atom).is_none() {
                    held = false;
                    break;
                }
            }
            if held {
                return;
            }
        }
        let mut taken = None;
        let mut unmet = Vec::new();
        for together in alternatives {
            let mut answerable = true;
            for atom in together.iter().filter(installs) {
                if self.stopped() {
                    return;
                }
                match self.answer(atom) {
                    Answer::Held(_) | Answer::Free(_) => {}
                    Answer::Taken(record, held, installed) => {
                        answerable = false;
                        taken.get_or_insert((record, held, installed));
                    }
                    Answer::Unmet => {
                        answerable = false;
                        unmet.push(atom);
                    }
                    Answer::Stopped => return,
                }
            }
            if answerable {
                for atom in together.iter().filter(installs) {
                    self.require(atom, wanted_by, None);
                }
                return;
            }
        }
        // Nothing answers the group. A build that was there and collided is
        // the wall a caller can act on, so it is reported over the atoms
        // nothing publishes.
        let written = written(alternatives);
        match taken {
            Some((record, held, installed)) => {
                self.refuse_occupied(record, held, installed, written, wanted_by);
            }
            None => {
                if self.refusals.has_room() {
                    let reason = self.wall(&unmet);
                    self.refusals.unsatisfied.push(Unsatisfied {
                        atom: written,
                        wanted_by: Rc::clone(wanted_by),
                        reason,
                    });
                }
            }
        }
    }

    /// Chooses `record`, queueing its own dependencies, and returns where it
    /// sits, or `None` where that would take the resolution past
    /// [`MAX_CLOSURE`] or [`MAX_DEPENDENCIES`].
    ///
    /// The build's dependency classes are parsed here, for the builds chosen
    /// and no others, and each dependency is queued once and settled once.
    fn choose(&mut self, record: &Record) -> Option<usize> {
        if self.chosen.all.len() >= MAX_CLOSURE {
            self.refusals.exceeded = Some(Bound::Closure);
            return None;
        }
        let runtime = record.runtime();
        let post_merge = record.post_merge();
        self.stated += runtime
            .iter()
            .chain(&post_merge)
            .map(Dependency::atoms)
            .sum::<usize>();
        if self.stated > MAX_DEPENDENCIES {
            self.refusals.exceeded = Some(Bound::Dependencies);
            return None;
        }
        let wanted_by: Rc<str> = Rc::from(record.cpv());
        let at = self.chosen.push(record.clone());
        self.needs.push(Vec::new());
        for dependency in runtime {
            let orders = matches!(dependency, Dependency::One(_)).then_some(at);
            self.queue.push(Pending {
                dependency,
                wanted_by: Rc::clone(&wanted_by),
                orders,
            });
        }
        for dependency in post_merge {
            self.queue.push(Pending {
                dependency,
                wanted_by: Rc::clone(&wanted_by),
                orders: None,
            });
        }
        Some(at)
    }

    /// What stopped `alternatives`, in the sentence "no build ...".
    ///
    /// The four walls are separated because they call for different answers: a
    /// name the archive does not publish is a package to install another way,
    /// a flag no build carries is a build nobody produced, and a slot or a
    /// version is a request the archive has moved past.
    ///
    /// A name the binhost publishes in no version is named with what the root
    /// has of it, where the root has anything. That is the measured case rather
    /// than an edge: the stage3 ships packages the binhost publishes in no
    /// version at all, so an atom on one of them walls on the archive's silence
    /// *and* on the version the root happens to hold, and the second is the
    /// half a caller can act on.
    ///
    /// Each atom's wall is the one its [`offer`](Self::offer) found, so a wall
    /// costs no pass over the index of its own.
    fn wall(&mut self, alternatives: &[&Atom]) -> String {
        let mut furthest: Option<Unmet> = None;
        let mut unpublished = Vec::new();
        for atom in alternatives {
            // Each was answered already, so each offer is one worked out and
            // kept, and asking again compares nothing.
            match self.offer(atom) {
                Some(Offer::Unmet(unmet)) => {
                    if furthest.is_none_or(|held| unmet.ordinal() > held.ordinal()) {
                        furthest = Some(unmet);
                    }
                }
                Some(Offer::Unpublished) => {
                    unpublished.push(unserved(self.installed, atom.name()));
                }
                // Not an atom nothing answers, so not one with a wall.
                Some(Offer::Build(_)) | None => {}
            }
        }
        match furthest {
            Some(unmet) => format!("published for it {}", unmet.describe()),
            None => format!(
                "of {} is published by this binhost at all",
                unpublished.join(" or "),
            ),
        }
    }

    /// Records that the chosen build `dependent` merges after the chosen build
    /// `needed`, where both are chosen builds and they are not one build.
    fn order_after(&mut self, dependent: Option<usize>, needed: Option<usize>) {
        if let (Some(dependent), Some(needed)) = (dependent, needed)
            && dependent != needed
        {
            self.needs[dependent].push(needed);
        }
    }

    /// Records that `record`, which `atom` asked for on behalf of `wanted_by`,
    /// would take a slot `held` already holds.
    fn refuse_occupied(
        &mut self,
        record: &Record,
        held: String,
        installed: bool,
        atom: String,
        wanted_by: &Rc<str>,
    ) {
        if self.refusals.has_room() {
            self.refusals.occupied.push(Occupied {
                name: record.name().to_string(),
                slot: slot_of(record.slot()).to_string(),
                held,
                installed,
                second: record.describe(),
                atom,
                wanted_by: Rc::clone(wanted_by),
            });
        }
    }
}

/// How a refusal names an any-of group: its alternatives, `or` between them,
/// and an alternative of several atoms in parentheses with `and` between
/// those.
fn written(alternatives: &[Vec<Atom>]) -> String {
    alternatives
        .iter()
        .map(|together| match together.as_slice() {
            [one] => one.to_string(),
            several => format!(
                "({})",
                several
                    .iter()
                    .map(Atom::to_string)
                    .collect::<Vec<_>>()
                    .join(" and "),
            ),
        })
        .collect::<Vec<_>>()
        .join(" or ")
}

/// A build a resolution or a replayed plan would install, as a refusal names
/// it.
trait Build: Candidate {
    /// Its `CPV` and which build of it.
    ///
    /// The build id is part of the name here where it is not elsewhere,
    /// because the two builds a slot collision names can be two builds of one
    /// version -- and a message naming them both `dev-vcs/git-2.54.0` would read
    /// as a bug in the refusal rather than as the collision it is.
    fn describe(&self) -> String;
}

impl Build for Record {
    fn describe(&self) -> String {
        format!("{} build {}", self.cpv(), self.build_id)
    }
}

/// Builds about to be installed, found by package name.
///
/// Every question asked of them is about one name -- does anything chosen
/// answer this atom, hold this slot, match this blocker -- so it is asked of
/// that name's builds rather than of every build. Asked of every build, each
/// question costs the whole set, and a closure's cost grows with its square.
struct Builds<C> {
    /// The builds, in the order they arrived.
    all: Vec<C>,
    /// Where each package name's builds sit in [`all`](Self::all).
    by_name: HashMap<String, Vec<usize>>,
}

impl<C> Default for Builds<C> {
    fn default() -> Self {
        Builds {
            all: Vec::new(),
            by_name: HashMap::new(),
        }
    }
}

impl<C: Candidate> Builds<C> {
    /// Adds `build`, returning where it sits.
    fn push(&mut self, build: C) -> usize {
        let at = self.all.len();
        self.by_name
            .entry(build.name().to_string())
            .or_default()
            .push(at);
        self.all.push(build);
        at
    }

    /// Every build published under `name`, with where it sits.
    fn under(&self, name: &str) -> impl Iterator<Item = (usize, &C)> {
        self.by_name
            .get(name)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .map(|&at| (at, &self.all[at]))
    }
}

/// What already holds the slot `build` would occupy, as a refusal names it,
/// and whether that is in the root rather than among `chosen`.
///
/// The one-instance-per-slot check, asked the same way of a build a resolution
/// would choose and of one a replayed plan names.
///
/// Each slot compared is charged to `compared`, as the two slots' lengths.
/// Where that reaches a bound part way, this answers that nothing holds the
/// slot, and the caller, which asks whether the comparisons are spent before
/// it acts on an answer, stops.
fn occupant<C: Build>(
    build: &impl Candidate,
    chosen: &Builds<C>,
    installed: &Installed,
    compared: &mut Comparisons,
) -> Option<(String, bool)> {
    let slot = slot_of(build.slot());
    for (_, held) in chosen.under(build.name()) {
        if !compared.charge(held.slot().len() + slot.len()) {
            return None;
        }
        if slot_of(held.slot()) == slot {
            return Some((held.describe(), false));
        }
    }
    for held in installed.under(build.name()) {
        if !compared.charge(held.slot().len() + slot.len()) {
            return None;
        }
        if slot_of(held.slot()) == slot {
            return Some((held.cpv(), true));
        }
    }
    None
}

/// Records every conflict `blockers`, and the root's own, make with the root
/// and with `chosen`.
///
/// `blockers` are the ones the builds being installed state, each with who
/// stated it; they bind against the root and against each other. The root
/// states blockers too, and a build being installed is as blocked by one as by
/// its own: portage will not merge a package an installed one refuses to share
/// the root with. Those are held to `chosen` only, since what the root's own
/// packages say of each other is the state it arrived in rather than something
/// this install did.
///
/// Every blocker is held against each candidate under its name, and how many
/// candidates that is, and how many conflicts it finds, is the index's to
/// decide. So the check stops where `compared` reaches a bound or `refusals`
/// has no room left, and the caller reports whichever it was.
fn conflicts<C: Candidate>(
    blockers: &[(Atom, Rc<str>)],
    installed: &Installed,
    chosen: &Builds<C>,
    compared: &mut Comparisons,
    refusals: &mut Refusals,
) {
    for (blocker, stated_by) in blockers {
        let conflict = |blocks: String, installed: bool| Conflict {
            atom: blocker.to_string(),
            stated_by: Rc::clone(stated_by),
            stated_in_root: false,
            blocks,
            installed,
        };
        for package in installed.under(blocker.name()) {
            if !compared.charge(blocker.reads(package)) {
                return;
            }
            if blocker.matches(package) {
                if !refusals.has_room() {
                    return;
                }
                refusals.conflicts.push(conflict(package.cpv(), true));
            }
        }
        for (_, build) in chosen.under(blocker.name()) {
            if !compared.charge(blocker.reads(build)) {
                return;
            }
            if blocker.matches(build) {
                if !refusals.has_room() {
                    return;
                }
                refusals.conflicts.push(conflict(build.cpv(), false));
            }
        }
    }
    for package in installed.packages() {
        // Made once the package is found to block something, and shared by
        // every conflict it makes.
        let mut stated_by: Option<Rc<str>> = None;
        for blocker in package.blockers() {
            for (_, build) in chosen.under(blocker.name()) {
                if !compared.charge(blocker.reads(build)) {
                    return;
                }
                if blocker.matches(build) {
                    if !refusals.has_room() {
                        return;
                    }
                    refusals.conflicts.push(Conflict {
                        atom: blocker.to_string(),
                        stated_by: Rc::clone(
                            stated_by.get_or_insert_with(|| Rc::from(package.cpv())),
                        ),
                        stated_in_root: true,
                        blocks: build.cpv(),
                        installed: false,
                    });
                }
            }
        }
    }
}

/// A build a replayed plan names, as its own verified metadata describes it.
pub(super) struct Arriving {
    /// What the root's database will say of it once it is merged.
    pub package: InstalledPackage,
    /// Which build of its version it is, so a refusal names it as a
    /// resolution's refusal would.
    pub build_id: u64,
    /// What it requires of the root it lands in: its runtime and post-merge
    /// dependencies, but for the blockers [`package`](Self::package) carries.
    pub requires: Vec<Dependency>,
}

impl Candidate for Arriving {
    fn name(&self) -> &str {
        self.package.name()
    }

    fn version(&self) -> &str {
        self.package.version()
    }

    fn slot(&self) -> &str {
        self.package.slot()
    }

    fn flag_lists(&self) -> (&str, &str) {
        self.package.flag_lists()
    }
}

impl Build for Arriving {
    fn describe(&self) -> String {
        format!("{} build {}", self.cpv(), self.build_id)
    }
}

/// The packages of a plan that replaying it over `installed` would install:
/// every one but those the root already has at exactly the version named.
///
/// A plan names the builds a resolution chose against one root, and it is
/// replayed over another -- normally a newer stage3, since the autobuilds tree
/// keeps a build about five weeks. The resolver's first question of an atom is
/// whether the root answers it already, and a package the root holds at the
/// plan's own version answers the plan's, so it is skipped as a resolution
/// would skip it.
pub(super) fn missing(installed: &Installed, planned: &[PlannedPackage]) -> Vec<PlannedPackage> {
    planned
        .iter()
        .filter(|planned| {
            !installed.under(&planned.name).any(|held| {
                version::compare(held.version(), &planned.version)
                    == Some(std::cmp::Ordering::Equal)
            })
        })
        .cloned()
        .collect()
}

/// Holds the builds a replayed plan names to the root they are about to be
/// merged into, with the checks a resolution holds its own choices to.
///
/// `arriving` describes each build from its verified metadata, the files a
/// merge writes out as its database entry, which the plan's own record of the
/// build was held to as the container was read. Each is refused where
/// something in the root or earlier in the plan holds its slot. The blockers
/// each states, and those the root states, are held to the rest. And each
/// dependency it requires must be answered by the root or by a build the plan
/// installs, as a resolution requires of every build it chooses, an any-of
/// group by one of its alternatives whole.
///
/// Without this a plan resolved against one stage3 and replayed over a newer
/// one registers its version beside the newer version of the same package in
/// one slot, or installs a package without a dependency the older root
/// supplied and the newer one does not, and reports success.
pub(super) fn admit(installed: &Installed, arriving: Vec<Arriving>) -> Refusals {
    let mut refusals = Refusals::default();
    let mut admitted = Builds::default();
    let mut blockers = Vec::new();
    // Nothing here is a mirror's to compose: the plan is the caller's own
    // document and the blockers are the signed metadata's, so what admitting
    // them costs is not bounded.
    let mut compared = Comparisons::unbounded();
    let plan: Rc<str> = Rc::from("the plan");
    for build in arriving {
        if let Some((held, in_root)) = occupant(&build, &admitted, installed, &mut compared) {
            if refusals.has_room() {
                refusals.occupied.push(Occupied {
                    name: build.name().to_string(),
                    slot: slot_of(build.slot()).to_string(),
                    held,
                    installed: in_root,
                    second: build.describe(),
                    // The atom a plan's entry amounts to: this package, at
                    // exactly this version.
                    atom: format!("={}", build.cpv()),
                    wanted_by: Rc::clone(&plan),
                });
            }
            continue;
        }
        let stated_by: Rc<str> = Rc::from(build.cpv());
        blockers.extend(
            build
                .package
                .blockers()
                .iter()
                .map(|blocker| (blocker.clone(), Rc::clone(&stated_by))),
        );
        admitted.push(build);
    }
    conflicts(
        &blockers,
        installed,
        &admitted,
        &mut compared,
        &mut refusals,
    );
    requirements(installed, &admitted, &mut compared, &mut refusals);
    refusals
}

/// Records every dependency of `admitted` that neither the root nor another of
/// `admitted` answers.
///
/// What answers is the root and the whole of what the plan installs, whatever
/// order it merges in: a resolution's closure is a set, and its order breaks
/// the cycles the archive's runtime graph has. An any-of group is answered by
/// any one of its alternatives, every atom of it that names something to
/// install answered, as [`Resolution::any_of`] reads one.
fn requirements(
    installed: &Installed,
    admitted: &Builds<Arriving>,
    compared: &mut Comparisons,
    refusals: &mut Refusals,
) {
    let mut answered = |atom: &Atom| {
        installed
            .under(atom.name())
            .any(|package| compared.charge(atom.reads(package)) && atom.matches(package))
            || admitted
                .under(atom.name())
                .any(|(_, build)| compared.charge(atom.reads(build)) && atom.matches(build))
    };
    for build in &admitted.all {
        let wanted_by: Rc<str> = Rc::from(build.cpv());
        for dependency in &build.requires {
            let (met, atom) = match dependency {
                // A blocker binds through `conflicts`, and answers nothing.
                Dependency::One(atom) if atom.blocker().is_some() => continue,
                Dependency::One(atom) => (answered(atom), atom.to_string()),
                Dependency::AnyOf(alternatives) => (
                    alternatives.iter().any(|together| {
                        together
                            .iter()
                            .filter(|atom| atom.blocker().is_none())
                            .all(&mut answered)
                    }),
                    written(alternatives),
                ),
            };
            if met {
                continue;
            }
            if !refusals.has_room() {
                return;
            }
            refusals.unsatisfied.push(Unsatisfied {
                atom,
                wanted_by: Rc::clone(&wanted_by),
                reason: "in the root or in the plan answers it".to_string(),
            });
        }
    }
}

/// What `index` offers for `atom`: the build to install, or how far the build
/// that got furthest got.
///
/// The build is the highest version among the builds the atom admits, then
/// the ranking the module documentation defends. The atom's own USE
/// dependencies have already removed what they exclude, since they are part of
/// admitting a build at all.
///
/// One pass over the name's builds answers both halves, so an atom nothing
/// answers costs no second pass to say why.
///
/// Every step is charged to `compared` before it is taken: each build held to
/// the atom, each two versions compared, and each build ranked, which reads
/// its `USE` once for its count and once for every preference. Where that
/// reaches a bound, this answers `None`.
fn offer<'i>(
    index: &'i Index,
    atom: &Atom,
    prefer: &[Preference],
    compared: &mut Comparisons,
) -> Option<Offer<'i>> {
    let mut admitted: Vec<&Record> = Vec::new();
    let mut furthest: Option<Unmet> = None;
    for record in index.builds(atom.name()) {
        if !compared.charge(atom.reads(record)) {
            return None;
        }
        match atom.unmet_by(record) {
            Unmet::Nothing => admitted.push(record),
            unmet => {
                if furthest.is_none_or(|held| unmet.ordinal() > held.ordinal()) {
                    furthest = Some(unmet);
                }
            }
        }
    }
    let mut highest: Option<&Record> = None;
    for &candidate in &admitted {
        highest = match highest {
            None => Some(candidate),
            Some(best) => {
                if !compared.charge(candidate.version().len() + best.version().len()) {
                    return None;
                }
                match version::compare(candidate.version(), best.version()) {
                    Some(std::cmp::Ordering::Greater) => Some(candidate),
                    _ => Some(best),
                }
            }
        };
    }
    let Some(highest) = highest else {
        return Some(furthest.map_or(Offer::Unpublished, Offer::Unmet));
    };
    // The last of the best-ranked, as `max_by_key` would take it.
    let mut best: Option<(&Record, Rank)> = None;
    for record in admitted
        .into_iter()
        .filter(|record| record.version() == highest.version())
    {
        let reads = record.use_flags().len().saturating_mul(prefer.len() + 1);
        if !compared.charge(reads) {
            return None;
        }
        let ranked = rank(record, prefer);
        if best.as_ref().is_none_or(|(_, held)| ranked >= *held) {
            best = Some((record, ranked));
        }
    }
    Some(best.map_or(Offer::Unpublished, |(record, _)| Offer::Build(record)))
}

/// How good a build is, as [`rank`] orders it, greater being better.
type Rank = (usize, std::cmp::Reverse<usize>, i64, u64);

/// How good a build is, greater being better.
///
/// The keys, in order: how many of the caller's preferences it meets, then how
/// few USE flags it carries, then how recently it was built, then its build id.
/// With no preference configured the first key is constant across the
/// candidates and the rule is the measured default exactly.
///
/// The build id is a final key rather than a real preference. Two builds of one
/// version can share a build time, and a resolution that chose between them by
/// iteration order would not be the same resolution twice.
fn rank(record: &Record, prefer: &[Preference]) -> Rank {
    let met = prefer
        .iter()
        .filter(|preference| preference.met_by(record))
        .count();
    (
        met,
        std::cmp::Reverse(record.use_count()),
        record.build_time,
        record.build_id,
    )
}

/// How a refusal names a package the binhost publishes in no version: the name,
/// and what the root has of it where the root has anything.
fn unserved(installed: &Installed, name: &str) -> String {
    let held: Vec<&str> = installed
        .under(name)
        .map(InstalledPackage::version)
        .collect();
    match held.is_empty() {
        true => name.to_string(),
        false => format!("{name}, which the root has at {}", held.join(" and ")),
    }
}

/// Puts the chosen builds in an order each can be merged in.
///
/// A topological sort over runtime dependencies alone, each build merging after
/// the chosen builds that answered its `RDEPEND` atoms (`needs`). `PDEPEND` is
/// left out on purpose: it is what portage satisfies *after* a package is
/// merged, so it belongs to the closure and not to the order, and treating it
/// as an edge would manufacture cycles the archive deliberately avoids.
///
/// Of the builds ready to merge, the first in name order goes next, so the
/// order is the same every time.
///
/// Where a real cycle remains — Gentoo's runtime graph has them, and portage
/// breaks them too — it is broken once nothing else can merge, and only inside
/// a cycle that waits on nothing outside itself: the first of its packages in
/// name order goes next, ahead of what it needs from the rest of the cycle. An
/// edge a cycle does not hold is never broken, so a package that merely
/// depends on a cycle still merges after it.
///
/// A cycle is reported once, naming its members: the packages that depend on
/// each other, directly or through one another, which are the graph's strongly
/// connected components. The whole sort is linear in the closure and its
/// edges, apart from a heap's logarithm.
fn order(chosen: Vec<Record>, mut needs: Vec<Vec<usize>>) -> (Vec<Record>, Vec<Vec<String>>) {
    let count = chosen.len();
    // Two atoms answered by one build are one edge.
    for edges in &mut needs {
        edges.sort_unstable();
        edges.dedup();
    }
    // Each build's place in name order, which is the order the heaps below
    // yield in. The sort is stable, so two builds of one name -- two slots --
    // keep the order they were chosen in.
    let mut by_name: Vec<usize> = (0..count).collect();
    by_name.sort_by(|a, b| chosen[*a].name().cmp(chosen[*b].name()));
    let mut rank = vec![0; count];
    for (place, &at) in by_name.iter().enumerate() {
        rank[at] = place;
    }

    let component = components(&needs);
    let components = component.iter().max().map_or(0, |last| last + 1);
    // Each component's members, in name order.
    let mut members: Vec<Vec<usize>> = vec![Vec::new(); components];
    for &at in &by_name {
        members[component[at]].push(at);
    }

    // What each build still waits on, split by whether the build it waits on
    // is in its own component, and what each component still waits on from
    // outside itself. A cycle may be broken only once that last reaches zero.
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); count];
    let mut inside = vec![0_usize; count];
    let mut outside = vec![0_usize; count];
    let mut waiting = vec![0_usize; components];
    for (at, edges) in needs.iter().enumerate() {
        for &needed in edges {
            dependents[needed].push(at);
            if component[needed] == component[at] {
                inside[at] += 1;
            } else {
                outside[at] += 1;
                waiting[component[at]] += 1;
            }
        }
    }
    let cyclic = |of: usize| members[of].len() > 1;

    // Both heaps hold places in name order, smallest first. `ready` holds the
    // builds waiting on nothing; `breakable` the members of cycles waiting on
    // nothing outside themselves, which may hold builds already merged.
    let mut ready: BinaryHeap<Reverse<usize>> = (0..count)
        .filter(|&at| needs[at].is_empty())
        .map(|at| Reverse(rank[at]))
        .collect();
    let mut breakable: BinaryHeap<Reverse<usize>> = (0..components)
        .filter(|&of| cyclic(of) && waiting[of] == 0)
        .flat_map(|of| members[of].iter().map(|&at| Reverse(rank[at])))
        .collect();

    let mut merged = Vec::with_capacity(count);
    let mut done = vec![false; count];
    let mut reported = vec![false; components];
    let mut cycles = Vec::new();
    while merged.len() < count {
        let next = match ready.pop() {
            Some(Reverse(place)) => by_name[place],
            None => {
                // Nothing is ready and something is left, so something left is
                // in a cycle. Of what is left, the components nothing outside
                // them holds back form at least one cycle -- a graph of
                // components has one waiting on no other -- and their members
                // are what `breakable` holds.
                let next = std::iter::from_fn(|| breakable.pop())
                    .map(|Reverse(place)| by_name[place])
                    .find(|&at| !done[at])
                    .expect("a cycle waiting on nothing outside itself remains");
                let of = component[next];
                if !reported[of] {
                    reported[of] = true;
                    cycles.push(members[of].iter().map(|&at| chosen[at].cpv()).collect());
                }
                next
            }
        };
        done[next] = true;
        merged.push(next);
        for &dependent in &dependents[next] {
            let of = component[dependent];
            if of == component[next] {
                inside[dependent] -= 1;
            } else {
                outside[dependent] -= 1;
                waiting[of] -= 1;
                if waiting[of] == 0 && cyclic(of) {
                    breakable.extend(members[of].iter().map(|&at| Reverse(rank[at])));
                }
            }
            // A member of a cycle broken ahead of it has merged already.
            if !done[dependent] && inside[dependent] == 0 && outside[dependent] == 0 {
                ready.push(Reverse(rank[dependent]));
            }
        }
    }
    let mut chosen: Vec<Option<Record>> = chosen.into_iter().map(Some).collect();
    (
        merged
            .into_iter()
            .filter_map(|at| chosen[at].take())
            .collect(),
        cycles,
    )
}

/// Each node's strongly connected component in the graph `needs` describes:
/// the sets in which every node reaches every other.
///
/// Tarjan's algorithm, with its recursion held in a stack of its own. The
/// depth it recurses to is the length of the longest dependency chain, which
/// an index nothing signs decides, and a chain long enough would overflow the
/// thread's stack, which aborts the process rather than failing the call.
///
/// Components are numbered from zero, in the order they are completed.
fn components(needs: &[Vec<usize>]) -> Vec<usize> {
    const UNSEEN: usize = usize::MAX;
    let count = needs.len();
    // When each node was first reached, and the earliest node still on the
    // stack it reaches.
    let mut reached = vec![UNSEEN; count];
    let mut low = vec![0; count];
    let mut on_stack = vec![false; count];
    let mut stack = Vec::new();
    let mut component = vec![UNSEEN; count];
    let mut next_reached = 0;
    let mut next_component = 0;
    // The walk's own call stack: a node, and how many of its edges it has
    // followed.
    let mut walk: Vec<(usize, usize)> = Vec::new();
    for start in 0..count {
        if reached[start] != UNSEEN {
            continue;
        }
        reached[start] = next_reached;
        low[start] = next_reached;
        next_reached += 1;
        stack.push(start);
        on_stack[start] = true;
        walk.push((start, 0));
        while let Some(&(node, followed)) = walk.last() {
            if let Some(&next) = needs[node].get(followed) {
                let top = walk.len() - 1;
                walk[top].1 += 1;
                if reached[next] == UNSEEN {
                    reached[next] = next_reached;
                    low[next] = next_reached;
                    next_reached += 1;
                    stack.push(next);
                    on_stack[next] = true;
                    walk.push((next, 0));
                } else if on_stack[next] {
                    low[node] = low[node].min(reached[next]);
                }
                continue;
            }
            walk.pop();
            if let Some(&(caller, _)) = walk.last() {
                low[caller] = low[caller].min(low[node]);
            }
            if low[node] == reached[node] {
                while let Some(member) = stack.pop() {
                    on_stack[member] = false;
                    component[member] = next_component;
                    if member == node {
                        break;
                    }
                }
                next_component += 1;
            }
        }
    }
    component
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision::gentoo::plan::Plan;
    use crate::provision::gentoo::{atom, index};

    /// The fixture archive every test below resolves against.
    ///
    /// It holds the shapes the design's measurement separates: a package the
    /// root already has, a version published as two builds differing in USE, an
    /// any-of group, a blocker, and one of each unsatisfiable kind.
    const ARCHIVE: &str = "\
TIMESTAMP: 1787145736

BUILD_ID: 5
BUILD_TIME: 100
CPV: dev-vcs/git-2.54.0
IUSE: +curl keyring
MD5: 6a539af72c5577fdce267834d3dfd2f1
PATH: dev-vcs/git/git-2.54.0-5.gpkg.tar
RDEPEND: >=sys-libs/zlib-1.3 || ( app-crypt/gnupg app-crypt/pinentry )
SIZE: 10
USE: amd64 curl

BUILD_ID: 8
BUILD_TIME: 200
CPV: dev-vcs/git-2.54.0
IUSE: +curl keyring
MD5: dadac993dfc5d6e6c0fbefbbb4093e0e
PATH: dev-vcs/git/git-2.54.0-8.gpkg.tar
RDEPEND: >=sys-libs/zlib-1.3 app-crypt/libsecret || ( app-crypt/gnupg app-crypt/pinentry )
SIZE: 10
USE: amd64 curl keyring

BUILD_ID: 1
BUILD_TIME: 50
CPV: sys-libs/zlib-1.3.1
MD5: 3a61f698748c7323c87081584f383b3c
PATH: sys-libs/zlib/zlib-1.3.1-1.gpkg.tar
SIZE: 10
SLOT: 0/1
USE: amd64

BUILD_ID: 1
BUILD_TIME: 60
CPV: sys-libs/zlib-1.3.2
MD5: b3ae71ef373f5aa4405e637a2d263f51
PATH: sys-libs/zlib/zlib-1.3.2-1.gpkg.tar
SIZE: 10
SLOT: 0/1
USE: amd64

BUILD_ID: 1
BUILD_TIME: 70
CPV: app-crypt/libsecret-0.21.7
MD5: 49c242775827cc9cdb5e308933d97d18
PATH: app-crypt/libsecret/libsecret-0.21.7-1.gpkg.tar
RDEPEND: dev-libs/glib:2
SIZE: 10
USE: amd64

BUILD_ID: 1
BUILD_TIME: 80
CPV: dev-libs/glib-2.86.0
MD5: 1fea75aab3015c66c56ca3efe50f0b9b
PATH: dev-libs/glib/glib-2.86.0-1.gpkg.tar
SIZE: 10
SLOT: 2
USE: amd64

BUILD_ID: 1
BUILD_TIME: 90
CPV: app-crypt/gnupg-2.4.9
MD5: ed8f7e7c5c4aa5dda85165f0dca871fd
PATH: app-crypt/gnupg/gnupg-2.4.9-1.gpkg.tar
SIZE: 10
USE: amd64

BUILD_ID: 1
BUILD_TIME: 95
CPV: www-client/firefox-145.0
MD5: 66dcb7730c8bcf40774639146d39fbf6
PATH: www-client/firefox/firefox-145.0-1.gpkg.tar
RDEPEND: !sys-apps/sysvinit
SIZE: 10
USE: amd64

BUILD_ID: 1
BUILD_TIME: 96
CPV: app-editors/vim-9.1
IUSE: +python
MD5: d742bb6b8540666df485536830c8fe25
PATH: app-editors/vim/vim-9.1-1.gpkg.tar
SIZE: 10
SLOT: 0
USE: amd64 python

BUILD_ID: 1
BUILD_TIME: 97
CPV: dev-lang/ruby-3.4.9
MD5: 3a61f698748c7323c87081584f383b3d
PATH: dev-lang/ruby/ruby-3.4.9-1.gpkg.tar
SIZE: 10
SLOT: 3.4
USE: amd64

BUILD_ID: 1
BUILD_TIME: 98
CPV: dev-lang/python-3.11.14
MD5: 4a61f698748c7323c87081584f383b3d
PATH: dev-lang/python/python-3.11.14-1.gpkg.tar
SIZE: 10
SLOT: 3.11
USE: amd64

BUILD_ID: 1
BUILD_TIME: 99
CPV: dev-lang/python-3.12.12
MD5: 5a61f698748c7323c87081584f383b3d
PATH: dev-lang/python/python-3.12.12-1.gpkg.tar
SIZE: 10
SLOT: 3.12
USE: amd64

BUILD_ID: 1
BUILD_TIME: 101
CPV: dev-python/two-slot-1.0
MD5: 6a61f698748c7323c87081584f383b3d
PATH: dev-python/two-slot/two-slot-1.0-1.gpkg.tar
RDEPEND: dev-lang/python:3.11 dev-lang/python:3.12
SIZE: 10
USE: amd64
";

    /// The fixture index.
    fn archive() -> Index {
        Index::parse(ARCHIVE)
    }

    /// A root holding `entries`, each `category/name-version` in slot `0`.
    fn root(entries: &[&str]) -> Installed {
        Installed::of(
            entries
                .iter()
                .map(|cpv| {
                    let (category, package, version) =
                        version::split_cpv(cpv).expect("a fixture CPV");
                    (
                        format!("{category}/{package}"),
                        version.to_string(),
                        "0".to_string(),
                        String::new(),
                    )
                })
                .collect(),
        )
    }

    /// Resolves `atoms` against the fixture archive and `installed`.
    #[track_caller]
    fn run(installed: &Installed, atoms: &[&str], prefer: &[&str]) -> (Resolved, Refusals) {
        let parsed: Vec<Atom> = atoms
            .iter()
            .map(|text| atom::parse(text).expect("a fixture atom"))
            .collect();
        let prefer: Vec<Preference> = prefer
            .iter()
            .map(|text| Preference::parse(text).expect("a fixture preference"))
            .collect();
        resolve(&archive(), installed, &parsed, &prefer)
    }

    /// The `CPV`s a resolution chose, in install order.
    fn installing(resolved: &Resolved) -> Vec<String> {
        resolved.packages.iter().map(Record::cpv).collect()
    }

    #[test]
    fn an_atom_the_root_already_answers_pulls_nothing() {
        // The whole reason resolution starts from the root: the median closure
        // over the real archive is five packages because everything else is
        // already there.
        let installed = root(&["dev-vcs/git-2.54.0", "sys-libs/zlib-1.3.2"]);
        let (resolved, refusals) = run(&installed, &["dev-vcs/git"], &[]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        assert!(installing(&resolved).is_empty());
    }

    #[test]
    fn a_dependency_the_binhost_does_not_publish_is_answered_by_the_root() {
        // The measured case: the stage3 ships app-crypt/pinentry and the
        // binhost publishes it in no version. A resolver reading only the index
        // would refuse an install the root already satisfies.
        let installed = root(&["app-crypt/pinentry-1.3.2"]);
        let (resolved, refusals) = run(&installed, &["dev-vcs/git"], &[]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        // gnupg is not pulled in: the any-of group's other alternative is
        // already satisfied by the root.
        assert_eq!(
            installing(&resolved),
            ["sys-libs/zlib-1.3.2", "dev-vcs/git-2.54.0"],
        );
    }

    #[test]
    fn the_default_rule_takes_the_highest_version_and_then_the_fewest_flags() {
        // Two builds of one version differing in `keyring`: the one without it
        // pulls nothing extra, the one with it pulls libsecret and glib. The
        // measured rule takes the first, and it is what decides whether a
        // resolution stays small.
        let (resolved, refusals) = run(&root(&[]), &["dev-vcs/git"], &[]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        let installing = installing(&resolved);
        assert!(installing.contains(&"dev-vcs/git-2.54.0".to_string()));
        assert!(
            !installing
                .iter()
                .any(|cpv| cpv.starts_with("app-crypt/libsecret"))
        );
        // The highest version of a dependency, not the first one published.
        assert!(installing.contains(&"sys-libs/zlib-1.3.2".to_string()));
    }

    #[test]
    fn a_preference_reorders_the_candidates_and_a_constraint_removes_them() {
        // The distinction the API is built around. Both reach the keyring
        // build; only the constraint can fail.
        let preferred = run(&root(&[]), &["dev-vcs/git"], &["keyring"]).0;
        assert!(
            installing(&preferred)
                .iter()
                .any(|cpv| cpv.starts_with("app-crypt/libsecret")),
            "a preference reaches the build the default rule would not choose",
        );
        let constrained = run(&root(&[]), &["dev-vcs/git[keyring]"], &[]).0;
        assert!(
            installing(&constrained)
                .iter()
                .any(|cpv| cpv.starts_with("app-crypt/libsecret")),
        );
        // A constraint no build can meet is unsatisfiable, and says so.
        let refusals = run(&root(&[]), &["dev-vcs/git[bindist]"], &[]).1;
        assert_eq!(refusals.unsatisfied.len(), 1);
        assert!(
            refusals.describe().contains("USE flags"),
            "{}",
            refusals.describe(),
        );
    }

    #[test]
    fn a_preference_never_makes_an_atom_unsatisfiable() {
        // The guarantee stated as a property rather than as a case, and the one
        // test that would catch a preference quietly becoming a filter. Every
        // preference drawn from the flags the fixture archive carries resolves
        // the same atoms as no preference at all.
        let atoms = ["dev-vcs/git", "app-editors/vim", "www-client/firefox"];
        let installed = root(&["sys-apps/sysvinit-3.15"]);
        let baseline = run(&installed, &atoms, &[]).1;
        for flag in ["curl", "keyring", "python", "amd64", "bindist"] {
            for preference in [flag.to_string(), format!("-{flag}")] {
                let refusals = run(&installed, &atoms, &[&preference]).1;
                assert_eq!(
                    refusals.unsatisfied.len(),
                    baseline.unsatisfied.len(),
                    "the preference {preference:?} changed what could be satisfied",
                );
            }
        }
    }

    #[test]
    fn an_any_of_group_takes_its_first_viable_alternative() {
        let (resolved, refusals) = run(&root(&[]), &["dev-vcs/git"], &[]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        // gnupg is the first alternative and the archive publishes it;
        // pinentry it does not publish at all.
        assert!(installing(&resolved).contains(&"app-crypt/gnupg-2.4.9".to_string()));
    }

    #[test]
    fn a_blocker_that_matches_is_a_conflict_naming_both_sides() {
        // The measured shape: a desktop package blocking the init system an
        // openrc stage3 ships. Portage refuses the same request for the same
        // reason.
        let installed = root(&["sys-apps/sysvinit-3.15"]);
        let (_, refusals) = run(&installed, &["www-client/firefox"], &[]);
        assert_eq!(refusals.conflicts.len(), 1);
        let conflict = &refusals.conflicts[0];
        assert_eq!(&*conflict.stated_by, "www-client/firefox-145.0");
        assert_eq!(conflict.blocks, "sys-apps/sysvinit-3.15");
        assert!(conflict.installed);
        assert!(
            refusals.describe().contains("removed from the root first"),
            "{}",
            refusals.describe(),
        );
        // With nothing to block, the same request resolves.
        assert!(run(&root(&[]), &["www-client/firefox"], &[]).1.is_empty());
    }

    #[test]
    fn a_blocker_the_root_states_against_a_chosen_build_is_a_conflict() {
        // The other direction: a package already in the root refuses what the
        // resolution would install beside it. Portage refuses the merge, so a
        // resolution that held only its own choices' blockers would install
        // what the root forbids.
        let installed = root(&["sys-apps/openrc-0.62"])
            .blocking("sys-apps/openrc", &["!app-editors/vim", "!<dev-vcs/git-2"]);
        let (_, refusals) = run(&installed, &["app-editors/vim"], &[]);
        assert_eq!(refusals.conflicts.len(), 1, "{}", refusals.describe());
        let conflict = &refusals.conflicts[0];
        assert_eq!(conflict.atom, "!app-editors/vim");
        assert_eq!(&*conflict.stated_by, "sys-apps/openrc-0.62");
        assert!(conflict.stated_in_root, "the root states it");
        assert_eq!(conflict.blocks, "app-editors/vim-9.1");
        assert!(!conflict.installed, "what it blocks would be installed");
        assert!(
            refusals
                .describe()
                .contains("sys-apps/openrc-0.62, which the root has, blocks app-editors/vim-9.1"),
            "{}",
            refusals.describe(),
        );

        // A blocker the chosen build does not match is no conflict: git 2.54 is
        // not below 2.
        let (resolved, refusals) = run(&installed, &["dev-vcs/git"], &[]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        assert!(
            resolved
                .packages
                .iter()
                .any(|record| record.name() == "dev-vcs/git")
        );
    }

    #[test]
    fn each_unsatisfiable_kind_says_which_wall_it_hit() {
        let installed = root(&[]);
        for (atoms, expected) in [
            (["app-misc/jq"], "is published by this binhost at all"),
            ([">=dev-vcs/git-3.0"], "has a version the atom admits"),
            (["dev-lang/ruby:3.3"], "is in the slot the atom names"),
            (["dev-vcs/git[bindist]"], "carries the USE flags"),
        ] {
            let refusals = run(&installed, &atoms, &[]).1;
            assert_eq!(refusals.unsatisfied.len(), 1, "{}", atoms[0]);
            assert!(
                refusals.describe().contains(expected),
                "{}: {}",
                atoms[0],
                refusals.describe(),
            );
        }
    }

    #[test]
    fn a_package_merges_after_what_it_needs_at_run_time() {
        let (resolved, refusals) = run(&root(&[]), &["dev-vcs/git[keyring]"], &[]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        let order = installing(&resolved);
        let position = |cpv: &str| {
            order
                .iter()
                .position(|held| held == cpv)
                .unwrap_or_else(|| panic!("{cpv} is installed"))
        };
        assert!(position("sys-libs/zlib-1.3.2") < position("dev-vcs/git-2.54.0"));
        assert!(position("dev-libs/glib-2.86.0") < position("app-crypt/libsecret-0.21.7"));
        assert!(position("app-crypt/libsecret-0.21.7") < position("dev-vcs/git-2.54.0"));
        assert!(resolved.cycles.is_empty());
    }

    #[test]
    fn a_resolution_is_the_same_resolution_twice() {
        // Two builds can share everything the ranking looks at, and a choice
        // made by iteration order would not be reproducible; so would an
        // install order taken from a hash map's walk.
        let installed = root(&["app-crypt/pinentry-1.3.2"]);
        let first = installing(&run(&installed, &["dev-vcs/git", "app-editors/vim"], &[]).0);
        for _ in 0..8 {
            assert_eq!(
                installing(&run(&installed, &["dev-vcs/git", "app-editors/vim"], &[]).0),
                first,
            );
        }
    }

    #[test]
    fn a_runtime_cycle_is_broken_by_a_stable_rule_and_reported() {
        // Gentoo's runtime graph has cycles and portage breaks them too. What
        // matters is that the break is the same one every time.
        let cyclic = "\
TIMESTAMP: 1

BUILD_ID: 1
CPV: dev-lang/perl-5.42
MD5: 1fea75aab3015c66c56ca3efe50f0b9b
PATH: dev-lang/perl/perl-5.42-1.gpkg.tar
RDEPEND: dev-perl/Module-Build
SIZE: 10
USE: amd64

BUILD_ID: 1
CPV: dev-perl/Module-Build-0.42
MD5: ed8f7e7c5c4aa5dda85165f0dca871fd
PATH: dev-perl/Module-Build/Module-Build-0.42-1.gpkg.tar
RDEPEND: dev-lang/perl
SIZE: 10
USE: amd64
";
        let index = Index::parse(cyclic);
        let wanted = [atom::parse("dev-lang/perl").expect("a fixture atom")];
        let installed = Installed::default();
        let (resolved, refusals) = resolve(&index, &installed, &wanted, &[]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        assert_eq!(resolved.cycles.len(), 1);
        assert_eq!(
            resolved
                .packages
                .iter()
                .map(Record::cpv)
                .collect::<Vec<_>>(),
            ["dev-lang/perl-5.42", "dev-perl/Module-Build-0.42"],
        );
    }

    #[test]
    fn two_versions_of_one_package_in_one_slot_are_refused() {
        // The state portage will not create and reports as a conflict when it
        // finds one. Two atoms constraining `sys-libs/zlib` from opposite
        // directions both select, and merging both would lay two images down
        // with the second overwriting the first's shared paths -- into a
        // `/var/db/pkg` that says the root holds two instances of one slot.
        let (resolved, refusals) = run(
            &root(&[]),
            &["<sys-libs/zlib-1.3.2", ">=sys-libs/zlib-1.3.2"],
            &[],
        );
        assert_eq!(refusals.occupied.len(), 1, "{}", refusals.describe());
        let taken = &refusals.occupied[0];
        assert_eq!(taken.name, "sys-libs/zlib");
        assert_eq!(taken.slot, "0");
        assert_eq!(taken.held, "sys-libs/zlib-1.3.1 build 1");
        assert_eq!(taken.second, "sys-libs/zlib-1.3.2 build 1");
        assert!(!taken.installed, "both are builds this resolution chose");
        assert!(
            refusals
                .describe()
                .contains("would occupy slot \"0\" of sys-libs/zlib"),
            "{}",
            refusals.describe(),
        );
        // The refusal is the outcome; what resolved before it is not installed.
        assert!(!refusals.is_empty());
        // The first of the two is still chosen, so the refusal names one pair
        // rather than reporting the same collision from both sides.
        assert_eq!(installing(&resolved), ["sys-libs/zlib-1.3.1"]);
    }

    #[test]
    fn a_same_slot_upgrade_over_the_root_is_refused() {
        // A merge registers its database entry beside what the root already has
        // and unmerges nothing, so installing a second version into an occupied
        // slot leaves two entries with overlapping CONTENTS -- the state the
        // refusal above exists to stop, reached from the root rather than from
        // a second chosen build. The atom is one no installed version answers,
        // which is what makes the collision reachable at all.
        let (resolved, refusals) = run(
            &root(&["sys-libs/zlib-1.3.1"]),
            &[">=sys-libs/zlib-1.3.2"],
            &[],
        );
        assert_eq!(refusals.occupied.len(), 1, "{}", refusals.describe());
        let taken = &refusals.occupied[0];
        assert_eq!(taken.name, "sys-libs/zlib");
        assert_eq!(taken.slot, "0");
        // No build to name: the root records what is installed, not which build
        // of it was published.
        assert_eq!(taken.held, "sys-libs/zlib-1.3.1");
        assert_eq!(taken.second, "sys-libs/zlib-1.3.2 build 1");
        assert!(taken.installed, "the root holds the slot");
        assert!(
            refusals.describe().contains("already takes in the root"),
            "{}",
            refusals.describe(),
        );
        // Nothing is installed: the refusal is the outcome.
        assert!(
            installing(&resolved).is_empty(),
            "{:?}",
            installing(&resolved)
        );
    }

    #[test]
    fn a_version_the_root_already_answers_is_no_collision() {
        // The guard fires only where the atom is genuinely unanswered. An atom
        // the root's own version satisfies is done two steps earlier, so a root
        // holding a package is not by itself a refusal to install alongside.
        let (resolved, refusals) = run(
            &root(&["sys-libs/zlib-1.3.2"]),
            &[">=sys-libs/zlib-1.3.1"],
            &[],
        );
        assert!(refusals.is_empty(), "{}", refusals.describe());
        assert!(
            installing(&resolved).is_empty(),
            "{:?}",
            installing(&resolved)
        );
    }

    #[test]
    fn two_slots_of_one_package_both_resolve_and_both_carry_their_edge() {
        // The archive publishes `dev-lang/python` in `3.11` and `3.12` and
        // Gentoo installs them side by side, so a closure holding both is not a
        // conflict -- and the dependent must merge after each of them, which is
        // what an install order keyed by name alone would get wrong for
        // whichever slot lost.
        let (resolved, refusals) = run(&root(&[]), &["dev-python/two-slot"], &[]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        let order = installing(&resolved);
        let position = |cpv: &str| {
            order
                .iter()
                .position(|held| held == cpv)
                .unwrap_or_else(|| panic!("{cpv} is installed: {order:?}"))
        };
        assert!(position("dev-lang/python-3.11.14") < position("dev-python/two-slot-1.0"));
        assert!(position("dev-lang/python-3.12.12") < position("dev-python/two-slot-1.0"));
        assert!(resolved.cycles.is_empty());
    }

    #[test]
    fn an_atom_the_root_holds_and_the_binhost_does_not_publish_names_the_version() {
        // The measured shape, one version further on: the stage3 ships
        // `app-crypt/pinentry` and the binhost publishes it in no version, so
        // an atom asking for more than the root has walls on both at once. The
        // absence alone is not actionable -- what a caller can act on is that
        // the root has it, and at what.
        let installed = root(&["app-crypt/pinentry-1.3.2"]);
        let refusals = run(&installed, &[">=app-crypt/pinentry-1.4"], &[]).1;
        assert_eq!(refusals.unsatisfied.len(), 1);
        let described = refusals.describe();
        assert!(
            described.contains("app-crypt/pinentry, which the root has at 1.3.2"),
            "{described}",
        );
        assert!(
            described.contains("is published by this binhost at all"),
            "{described}"
        );
    }

    /// An index publishing `a/p000001` to `a/p{count}`, each depending on the
    /// next, and the last on `closing` where a cycle is wanted.
    fn chain(count: usize, closing: Option<usize>) -> Index {
        let mut text = String::from("TIMESTAMP: 1\n\n");
        for at in 1..=count {
            let next = if at < count { Some(at + 1) } else { closing };
            let rdepend = next.map_or(String::new(), |next| format!("RDEPEND: a/p{next:06}\n"));
            text.push_str(&format!(
                "BUILD_ID: 1\nCPV: a/p{at:06}-1\nMD5: d41d8cd98f00b204e9800998ecf8427e\n\
                 PATH: a/p{at:06}/p{at:06}-1-1.gpkg.tar\n{rdepend}SIZE: 1\nUSE: amd64\n\n"
            ));
        }
        Index::parse(&text)
    }

    #[test]
    fn a_slot_the_index_states_reaches_a_refusal_with_its_control_characters_escaped() {
        // Nothing signs the index, and a slot is held to a length rather than
        // to an alphabet, so the slot a collision names is the mirror's string.
        let slot = crate::failure::hostile::TEXT;
        let index = Index::parse(&format!(
            "TIMESTAMP: 1\n\n\
             BUILD_ID: 1\nCPV: a/b-1\nMD5: d41d8cd98f00b204e9800998ecf8427e\n\
             PATH: a/b/b-1-1.gpkg.tar\nSIZE: 1\nSLOT: {slot}\n\n\
             BUILD_ID: 1\nCPV: a/b-2\nMD5: d41d8cd98f00b204e9800998ecf8427e\n\
             PATH: a/b/b-2-1.gpkg.tar\nSIZE: 1\nSLOT: {slot}\n\n"
        ));
        assert_eq!(index.records().len(), 2, "both builds are kept");
        let (_, refusals) = run_over(&index, &Installed::default(), &["<a/b-2", ">=a/b-2"]);
        assert_eq!(refusals.occupied.len(), 1, "{}", refusals.describe());
        crate::failure::hostile::assert_escaped(&refusals.describe());
    }

    /// Resolves `atoms` against `index` over an empty root.
    #[track_caller]
    fn run_over(index: &Index, installed: &Installed, atoms: &[&str]) -> (Resolved, Refusals) {
        let parsed: Vec<Atom> = atoms
            .iter()
            .map(|text| atom::parse(text).expect("a fixture atom"))
            .collect();
        resolve(index, installed, &parsed, &[])
    }

    #[test]
    fn a_long_chain_closed_by_a_two_member_loop_reports_the_loop_and_nothing_else() {
        // `a/p0001 -> ... -> a/pN`, with `a/pN` depending back on the package
        // before it. Only those two depend on each other. A sort that reported
        // everything still waiting whenever it was stuck reported every package
        // left, once per package, which over an unsigned index is memory
        // growing with the square of the closure.
        const COUNT: usize = 10_000;
        let (resolved, refusals) = run_over(
            &chain(COUNT, Some(COUNT - 1)),
            &Installed::default(),
            &["a/p000001"],
        );
        assert!(refusals.is_empty(), "{}", refusals.describe());
        assert_eq!(
            resolved.cycles,
            [vec![
                format!("a/p{:06}-1", COUNT - 1),
                format!("a/p{COUNT:06}-1"),
            ]],
        );
        // Every package merges once, and after the package it needs, but for
        // the one edge the loop forced the order to break.
        let order = installing(&resolved);
        assert_eq!(order.len(), COUNT);
        let position: HashMap<&str, usize> = order
            .iter()
            .enumerate()
            .map(|(at, cpv)| (cpv.as_str(), at))
            .collect();
        for at in 1..COUNT {
            let dependent = format!("a/p{at:06}-1");
            let needed = format!("a/p{:06}-1", at + 1);
            if at + 1 == COUNT {
                // The loop's own edge is the one broken: the first of its two
                // members in name order goes first.
                assert!(position[dependent.as_str()] < position[needed.as_str()]);
            } else {
                assert!(
                    position[needed.as_str()] < position[dependent.as_str()],
                    "{dependent} merged before {needed}",
                );
            }
        }
    }

    #[test]
    fn a_package_that_needs_a_cycle_merges_after_it_rather_than_being_broken_into_it() {
        // `a/p000001` needs the loop and is not part of it. It is first in
        // name order, so a rule that took the first package left whenever
        // nothing was ready would merge it ahead of what it needs.
        let (resolved, refusals) =
            run_over(&chain(3, Some(2)), &Installed::default(), &["a/p000001"]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        assert_eq!(
            installing(&resolved),
            ["a/p000002-1", "a/p000001-1", "a/p000003-1"],
        );
        assert_eq!(resolved.cycles, [vec!["a/p000002-1", "a/p000003-1"]]);
    }

    #[test]
    fn a_chain_deeper_than_any_stack_is_ordered_without_recursing_down_it() {
        // The components are found by a walk whose depth is the chain's
        // length. Recursing down it would overflow the stack, which aborts the
        // process, so the walk keeps a stack of its own.
        const COUNT: usize = 1_000_000;
        let needs: Vec<Vec<usize>> = (0..COUNT)
            .map(|at| {
                if at + 1 < COUNT {
                    vec![at + 1]
                } else {
                    vec![0]
                }
            })
            .collect();
        let component = components(&needs);
        assert!(component.iter().all(|&of| of == component[0]), "one cycle");
        let chain: Vec<Vec<usize>> = (0..COUNT)
            .map(|at| {
                if at + 1 < COUNT {
                    vec![at + 1]
                } else {
                    Vec::new()
                }
            })
            .collect();
        let component = components(&chain);
        // Completed from the far end of the chain back.
        assert_eq!(component[COUNT - 1], 0);
        assert_eq!(component[0], COUNT - 1);
    }

    #[test]
    fn a_closure_past_the_bound_is_refused_where_it_stands() {
        let (resolved, refusals) = run_over(
            &chain(MAX_CLOSURE + 1, None),
            &Installed::default(),
            &["a/p000001"],
        );
        assert_eq!(refusals.exceeded, Some(Bound::Closure));
        assert!(!refusals.is_empty());
        assert!(
            refusals
                .describe()
                .contains(&format!("grew past {MAX_CLOSURE} builds")),
            "{}",
            refusals.describe(),
        );
        assert_eq!(resolved.packages.len(), MAX_CLOSURE);
        // One short of it resolves.
        let (_, refusals) = run_over(
            &chain(MAX_CLOSURE, None),
            &Installed::default(),
            &["a/p000001"],
        );
        assert!(refusals.is_empty(), "{}", refusals.describe());
    }

    /// An index publishing `builds` builds of `b/q`, one per slot, and a chain
    /// of `links` packages from `a/p000001`, each depending on the next and on
    /// whatever `depends(link)` names.
    fn crowded(builds: usize, links: usize, depends: impl Fn(usize) -> String) -> Index {
        let mut text = String::from("TIMESTAMP: 1\n\n");
        for slot in 0..builds {
            text.push_str(&format!(
                "BUILD_ID: {slot}\nCPV: b/q-1\nMD5: d41d8cd98f00b204e9800998ecf8427e\n\
                 PATH: b/q/q-1-{slot}.gpkg.tar\nSIZE: 1\nSLOT: {slot}\n\n"
            ));
        }
        for link in 1..=links {
            let next = if link < links {
                format!("a/p{:06} ", link + 1)
            } else {
                String::new()
            };
            text.push_str(&format!(
                "BUILD_ID: 1\nCPV: a/p{link:06}-1\nMD5: d41d8cd98f00b204e9800998ecf8427e\n\
                 PATH: a/p{link:06}/p{link:06}-1-1.gpkg.tar\nRDEPEND: {next}{}\nSIZE: 1\n\n",
                depends(link),
            ));
        }
        Index::parse(&text)
    }

    #[test]
    fn an_atom_is_held_against_the_index_once_however_often_it_is_asked() {
        // Every package of the chain asks for a version of `b/q` none of its
        // builds is. Asked afresh, each would cost every build of the name, once
        // to choose and once more to say why nothing was chosen; an atom's offer
        // depends only on the index and the preferences, so it is worked out
        // once and the refusals repeat it.
        const BUILDS: usize = 1_000;
        const LINKS: usize = 64;
        let index = crowded(BUILDS, LINKS, |_| ">=b/q-2".to_string());
        let wanted = [atom::parse("a/p000001").expect("a fixture atom")];
        let empty = Installed::default();
        let run = settle(&index, &empty, &wanted, &[]);
        assert_eq!(run.refusals.exceeded, None);
        assert_eq!(run.refusals.unsatisfied.len(), LINKS);
        assert!(
            run.refusals.unsatisfied[0]
                .reason
                .contains("has a version the atom admits"),
            "{}",
            run.refusals.describe(),
        );
        // The name's builds once, and each link's one build twice: held to the
        // link's atom, and ranked as the only build of its version.
        assert_eq!(run.compared.made, BUILDS + 2 * LINKS);
    }

    #[test]
    fn a_resolution_past_its_comparisons_is_refused_where_it_stands() {
        // Distinct atoms on one name, each in a slot none of the name's builds
        // is in. Nothing is chosen for any of them, so the closure bounds none
        // of it, and every one costs every build of the name: 8,388,608
        // comparisons, were the resolution allowed to finish.
        const BUILDS: usize = 4_096;
        const LINKS: usize = 64;
        let index = crowded(BUILDS, LINKS, |link| {
            (0..32)
                .map(|at| format!("b/q:x{link}-{at}"))
                .collect::<Vec<_>>()
                .join(" ")
        });
        let wanted = [atom::parse("a/p000001").expect("a fixture atom")];
        let empty = Installed::default();
        let before = thread_ticks();
        let run = settle(&index, &empty, &wanted, &[]);
        let spent = thread_ticks() - before;
        assert!(spent < MATCHING_TICKS, "{spent} ticks");
        assert_eq!(run.refusals.exceeded, Some(Bound::Comparisons));
        assert!(
            run.refusals
                .describe()
                .contains(&format!("more than {MAX_COMPARISONS} candidate builds")),
            "{}",
            run.refusals.describe(),
        );
        // It stops at the comparison past the bound, which is charged and not
        // made, having refused only the atoms it finished.
        assert_eq!(run.compared.made, MAX_COMPARISONS + 1);
        assert!(run.refusals.unsatisfied.len() <= MAX_COMPARISONS / BUILDS);
    }

    #[test]
    fn a_resolution_past_its_refusals_stops_where_it_stands() {
        // Two shapes an index can give a refusal count. Unmet atoms grow with
        // what the chosen builds state. Conflicts grow with the product of the
        // blockers stated and the builds chosen under the name they block: one
        // build stating `!b/q` a hundred times, over 256 slots of `b/q`, is
        // 25,600 of them from 1.3 KB of `RDEPEND`.
        const SLOTS: usize = 256;
        let unmet_per_class = (index::MAX_CLASS_BYTES - 16) / "b/u00000 ".len();
        let unmet_links = MAX_REFUSALS / unmet_per_class + 2;
        let shapes = [
            (
                "unmet",
                crowded(0, unmet_links, |link| {
                    (0..unmet_per_class)
                        .map(|at| format!("b/u{:05}", link * unmet_per_class + at))
                        .collect::<Vec<_>>()
                        .join(" ")
                }),
            ),
            (
                "conflicting",
                crowded(SLOTS, 2, |link| match link {
                    1 => (0..SLOTS)
                        .map(|slot| format!("b/q:{slot}"))
                        .collect::<Vec<_>>()
                        .join(" "),
                    _ => "!b/q ".repeat(100).trim_end().to_string(),
                }),
            ),
        ];
        let wanted = [atom::parse("a/p000001").expect("a fixture atom")];
        let empty = Installed::default();
        for (shape, index) in shapes {
            let run = settle(&index, &empty, &wanted, &[]);
            let refusals = &run.refusals;
            assert_eq!(refusals.exceeded, Some(Bound::Refusals), "{shape}");
            let recorded =
                refusals.unsatisfied.len() + refusals.conflicts.len() + refusals.occupied.len();
            assert_eq!(recorded, MAX_REFUSALS, "{shape}");
            assert!(
                refusals
                    .describe()
                    .contains(&format!("stopped after {MAX_REFUSALS} refusals")),
                "{shape}",
            );
            // Who asked is shared by every refusal of what one build states,
            // rather than copied into each.
            let askers: Vec<&Rc<str>> = refusals
                .unsatisfied
                .iter()
                .map(|unmet| &unmet.wanted_by)
                .chain(
                    refusals
                        .conflicts
                        .iter()
                        .map(|conflict| &conflict.stated_by),
                )
                .collect();
            let first = askers.first().expect("a refusal");
            let shared = askers
                .iter()
                .filter(|asker| Rc::ptr_eq(asker, first))
                .count();
            assert!(shared > 1, "{shape}");
            assert!(
                askers
                    .iter()
                    .all(|asker| Rc::ptr_eq(asker, first) || **asker != **first),
                "{shape}: one asker copied",
            );
        }
    }

    /// The thread's own processor time, in clock ticks.
    fn thread_ticks() -> u64 {
        ferroday_cage_testkit::process::thread_ticks(
            rustix::thread::gettid().as_raw_nonzero().get(),
        )
    }

    #[test]
    fn a_comparison_an_index_makes_expensive_is_charged_what_it_reads() {
        // Two shapes that make each comparison read as much as a record and an
        // atom may state. In the first, every build of `b/q` carries flag lists
        // at their bound, and every link of the chain holds it to an atom of 64
        // USE dependencies none of the builds knows, each answered by its `(+)`
        // default: every one scans both lists whole, 2 MiB a comparison, and
        // the chain asks 4,096 times. In the second, 800 distinct atoms with
        // versions as long as a `CPV` allows are each held to 4,096 builds with
        // versions as long, every comparison parsing both again. Unbounded,
        // the first reads 8 GiB and the second 3 GiB.
        let flags = |prefix: &str| {
            let one = format!("{prefix}0000 ");
            (0..index::MAX_FLAGS_BYTES / one.len())
                .map(|at| format!("{prefix}{at:04}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let (enabled, known) = (flags("u"), flags("i"));
        let mut flagged = String::from("TIMESTAMP: 1\n\n");
        for slot in 0..4 {
            flagged.push_str(&format!(
                "BUILD_ID: {slot}\nCPV: b/q-1\nIUSE: {known}\n\
                 MD5: d41d8cd98f00b204e9800998ecf8427e\nPATH: b/q/q-1-{slot}.gpkg.tar\n\
                 SIZE: 1\nSLOT: {slot}\nUSE: {enabled}\n\n"
            ));
        }
        chain_text(&mut flagged, 4_096, |link| {
            let deps = (0..64)
                .map(|at| format!("x{link}d{at}(+)"))
                .collect::<Vec<_>>()
                .join(",");
            format!("b/q[{deps}]")
        });
        let long = format!("1{}", ".1".repeat(250));
        let mut versioned = String::from("TIMESTAMP: 1\n\n");
        for build in 0..4_096 {
            versioned.push_str(&format!(
                "BUILD_ID: {build}\nCPV: b/v-{long}\nMD5: d41d8cd98f00b204e9800998ecf8427e\n\
                 PATH: b/v/v-{build}.gpkg.tar\nSIZE: 1\n\n"
            ));
        }
        chain_text(&mut versioned, 8, |link| {
            (0..100)
                .map(|at| format!(">=b/v-{}.{}", &long[..long.len() - 2], link * 100 + at))
                .collect::<Vec<_>>()
                .join(" ")
        });

        let wanted = [atom::parse("a/p000001").expect("a fixture atom")];
        let empty = Installed::default();
        for (shape, text) in [("flagged", flagged), ("versioned", versioned)] {
            let index = Index::parse(&text);
            drop(text);
            assert_eq!(
                index.skipped(),
                0,
                "{shape}: every stanza is within its bounds"
            );
            let before = thread_ticks();
            let run = settle(&index, &empty, &wanted, &[]);
            let spent = thread_ticks() - before;
            assert_eq!(run.refusals.exceeded, Some(Bound::ComparedBytes), "{shape}");
            assert!(
                run.refusals
                    .describe()
                    .contains(&format!("more than {MAX_COMPARED_BYTES} bytes")),
                "{shape}",
            );
            // Charged before it is made, so what was read is within the bound
            // but for the one comparison refused, which is not made.
            let refused = run.compared.read - MAX_COMPARED_BYTES.min(run.compared.read);
            assert!(
                refused <= 2 * 1024 * 1024,
                "{shape}: {refused} past the bound"
            );
            assert!(spent < MATCHING_TICKS, "{shape}: {spent} ticks");
        }
    }

    /// The most processor time, in clock ticks, a test of a comparison bound
    /// lets one resolution spend.
    ///
    /// A tick is a hundredth of a second wherever this runs, so this is thirty
    /// seconds. An unoptimized build reaches a bound in well under that, and
    /// reading what the hostile shapes publish without one takes minutes.
    const MATCHING_TICKS: u64 = 3_000;

    /// Appends a chain of `links` packages from `a/p000001` to `text`, each
    /// depending on the next and on whatever `depends(link)` names.
    fn chain_text(text: &mut String, links: usize, depends: impl Fn(usize) -> String) {
        for link in 1..=links {
            let next = if link < links {
                format!("a/p{:06} ", link + 1)
            } else {
                String::new()
            };
            text.push_str(&format!(
                "BUILD_ID: 1\nCPV: a/p{link:06}-1\nMD5: d41d8cd98f00b204e9800998ecf8427e\n\
                 PATH: a/p{link:06}/p{link:06}-1-1.gpkg.tar\nRDEPEND: {next}{}\nSIZE: 1\n\n",
                depends(link),
            ));
        }
    }

    #[test]
    fn a_closure_stating_more_atoms_than_the_bound_is_refused_where_it_stands() {
        // Each package of the chain states as many atoms as a class may hold,
        // every one answered by the root, so nothing is refused and nothing
        // else is chosen: only the count of what the builds state grows.
        let per_class = (index::MAX_CLASS_BYTES - 16) / "b/z ".len();
        let links = MAX_DEPENDENCIES / per_class + 2;
        let index = crowded(0, links, |_| {
            "b/z ".repeat(per_class).trim_end().to_string()
        });
        let installed = root(&["b/z-1"]);
        let wanted = [atom::parse("a/p000001").expect("a fixture atom")];
        let run = settle(&index, &installed, &wanted, &[]);
        assert_eq!(run.refusals.exceeded, Some(Bound::Dependencies));
        assert!(run.refusals.unsatisfied.is_empty());
        assert!(run.chosen.all.len() < links);
        assert!(run.stated > MAX_DEPENDENCIES);
        assert!(
            run.refusals
                .describe()
                .contains(&format!("more than {MAX_DEPENDENCIES} dependency atoms")),
            "{}",
            run.refusals.describe(),
        );
    }

    /// The archive `virtual/zlib` resolves against: zlib built without the
    /// flag the virtual asks for, and the zlib-ng pair that answers together.
    const ZLIB_VIRTUAL: &str = "\
TIMESTAMP: 1

BUILD_ID: 1
CPV: virtual/zlib-1.3.1
MD5: 1fea75aab3015c66c56ca3efe50f0b9b
PATH: virtual/zlib/zlib-1.3.1-1.gpkg.tar
RDEPEND: || ( >=sys-libs/zlib-1.3.1[minizip] ( sys-libs/zlib-ng[compat] sys-libs/minizip-ng[compat] ) )
SIZE: 10
USE: amd64

BUILD_ID: 1
CPV: sys-libs/zlib-1.3.1
IUSE: minizip
MD5: 2fea75aab3015c66c56ca3efe50f0b9b
PATH: sys-libs/zlib/zlib-1.3.1-1.gpkg.tar
SIZE: 10
USE: amd64

BUILD_ID: 1
CPV: sys-libs/zlib-ng-2.2.5
IUSE: compat
MD5: 3fea75aab3015c66c56ca3efe50f0b9b
PATH: sys-libs/zlib-ng/zlib-ng-2.2.5-1.gpkg.tar
SIZE: 10
USE: amd64 compat

BUILD_ID: 1
CPV: sys-libs/minizip-ng-4.0.10
IUSE: compat
MD5: 4fea75aab3015c66c56ca3efe50f0b9b
PATH: sys-libs/minizip-ng/minizip-ng-4.0.10-1.gpkg.tar
SIZE: 10
USE: amd64 compat
";

    #[test]
    fn an_alternative_of_several_atoms_is_taken_whole_or_not_at_all() {
        // The shape the live index publishes for `virtual/zlib`. Read as three
        // alternatives, zlib-ng alone would satisfy the group and minizip-ng
        // would never be installed; it is one alternative, both together.
        let index = Index::parse(ZLIB_VIRTUAL);
        let (resolved, refusals) = run_over(&index, &Installed::default(), &["virtual/zlib"]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        let mut installed = installing(&resolved);
        installed.sort();
        assert_eq!(
            installed,
            [
                "sys-libs/minizip-ng-4.0.10",
                "sys-libs/zlib-ng-2.2.5",
                "virtual/zlib-1.3.1",
            ],
        );

        // A root that already has zlib-ng has half of the alternative, which is
        // not the alternative: minizip-ng is still installed.
        let root = Installed::of(vec![(
            "sys-libs/zlib-ng".to_string(),
            "2.2.5".to_string(),
            "0".to_string(),
            "amd64 compat".to_string(),
        )]);
        let (resolved, refusals) = run_over(&index, &root, &["virtual/zlib"]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        assert_eq!(
            installing(&resolved),
            ["sys-libs/minizip-ng-4.0.10", "virtual/zlib-1.3.1"],
        );

        // With nothing to answer it, the refusal names the alternatives as the
        // group states them.
        let bare = Index::parse(
            &ZLIB_VIRTUAL[..ZLIB_VIRTUAL
                .find("\nBUILD_ID: 1\nCPV: sys-libs/zlib-1.3.1")
                .unwrap()],
        );
        let (_, refusals) = run_over(&bare, &Installed::default(), &["virtual/zlib"]);
        assert_eq!(refusals.unsatisfied.len(), 1, "{}", refusals.describe());
        assert_eq!(
            refusals.unsatisfied[0].atom,
            ">=sys-libs/zlib-1.3.1[minizip] or (sys-libs/zlib-ng[compat] and \
             sys-libs/minizip-ng[compat])",
        );
    }

    #[test]
    fn an_alternative_that_would_take_an_occupied_slot_gives_way_to_the_next() {
        // `|| ( >=sys-libs/zlib-1.3.2 app-crypt/gnupg )` over a root holding
        // zlib 1.3.1: the first alternative's build would be a second zlib in
        // slot 0, and the group offers another.
        let index = Index::parse(&format!(
            "{ARCHIVE}\nBUILD_ID: 1\nCPV: app-misc/either-1.0\n\
             MD5: 7a61f698748c7323c87081584f383b3d\nPATH: app-misc/either/either-1.0-1.gpkg.tar\n\
             RDEPEND: || ( >=sys-libs/zlib-1.3.2 app-crypt/gnupg )\nSIZE: 10\nUSE: amd64\n",
        ));
        let root = root(&["sys-libs/zlib-1.3.1"]);
        let (resolved, refusals) = run_over(&index, &root, &["app-misc/either"]);
        assert!(refusals.is_empty(), "{}", refusals.describe());
        assert_eq!(
            installing(&resolved),
            ["app-crypt/gnupg-2.4.9", "app-misc/either-1.0"],
        );

        // Where no alternative is left, the collision is the refusal, naming
        // the whole group.
        let index = Index::parse(&format!(
            "{ARCHIVE}\nBUILD_ID: 1\nCPV: app-misc/either-1.0\n\
             MD5: 7a61f698748c7323c87081584f383b3d\nPATH: app-misc/either/either-1.0-1.gpkg.tar\n\
             RDEPEND: || ( >=sys-libs/zlib-1.3.2 app-misc/jq )\nSIZE: 10\nUSE: amd64\n",
        ));
        let (_, refusals) = run_over(&index, &root, &["app-misc/either"]);
        assert_eq!(refusals.occupied.len(), 1, "{}", refusals.describe());
        assert_eq!(
            refusals.occupied[0].atom,
            ">=sys-libs/zlib-1.3.2 or app-misc/jq"
        );
        assert!(refusals.occupied[0].installed);
        assert!(refusals.unsatisfied.is_empty(), "{}", refusals.describe());
    }

    /// A package a plan names, as its metadata files describe it.
    fn arriving(cpv: &str, build_id: u64, files: &[(&str, &str)]) -> Arriving {
        let (category, package, version) = version::split_cpv(cpv).expect("a fixture CPV");
        let files: HashMap<&str, &[u8]> = files
            .iter()
            .map(|(name, text)| (*name, text.as_bytes()))
            .collect();
        let (package, requires) =
            InstalledPackage::from_metadata(&format!("{category}/{package}"), version, |name| {
                files.get(name).copied()
            })
            .expect("fixture metadata");
        Arriving {
            package,
            build_id,
            requires,
        }
    }

    #[test]
    fn a_replayed_plan_skips_what_the_root_has_at_the_version_it_names() {
        let plan = Plan::project("amd64", "x86-64", None, archive().records());
        let root = root(&["sys-libs/zlib-1.3.2", "dev-vcs/git-2.54.0"]);
        let missing: Vec<String> = missing(&root, &plan.packages)
            .iter()
            .map(|planned| format!("{}-{}", planned.name, planned.version))
            .collect();
        // zlib 1.3.2 is skipped and 1.3.1 is not: one version of a package is
        // not another. Both builds of git 2.54.0 are skipped, since the root
        // records a version and not which build it came from.
        assert!(!missing.contains(&"sys-libs/zlib-1.3.2".to_string()));
        assert!(missing.contains(&"sys-libs/zlib-1.3.1".to_string()));
        assert!(!missing.iter().any(|cpv| cpv.starts_with("dev-vcs/git")));
        assert_eq!(missing.len(), plan.packages.len() - 3);
    }

    #[test]
    fn a_replayed_plan_is_held_to_the_slots_and_blockers_of_the_root_it_lands_in() {
        // A plan resolved against one stage3 and replayed over a newer one: the
        // root holds zlib 1.3.3 in the slot the plan's 1.3.2 would take.
        let root = root(&["sys-libs/zlib-1.3.3", "sys-apps/openrc-0.62"])
            .blocking("sys-apps/openrc", &["!app-editors/vim"]);
        let refusals = admit(
            &root,
            vec![
                arriving("sys-libs/zlib-1.3.2", 1, &[("SLOT", "0/1\n")]),
                arriving(
                    "app-misc/tool-1.0",
                    2,
                    &[
                        ("SLOT", "0\n"),
                        ("RDEPEND", "!sys-apps/openrc >=sys-libs/zlib-1.3\n"),
                    ],
                ),
                arriving("app-editors/vim-9.1", 3, &[("SLOT", "0\n")]),
                arriving("app-misc/tool-1.1", 4, &[("SLOT", "0\n")]),
                // A second slot of a package is a second package.
                arriving("app-misc/tool-2.0", 5, &[("SLOT", "2\n")]),
            ],
        );
        assert_eq!(refusals.occupied.len(), 2, "{}", refusals.describe());
        let zlib = &refusals.occupied[0];
        assert_eq!(zlib.held, "sys-libs/zlib-1.3.3");
        assert!(zlib.installed);
        assert_eq!(zlib.second, "sys-libs/zlib-1.3.2 build 1");
        assert_eq!(zlib.atom, "=sys-libs/zlib-1.3.2");
        assert_eq!(&*zlib.wanted_by, "the plan");
        // An earlier entry of the plan holds a slot as the root does.
        let tool = &refusals.occupied[1];
        assert_eq!(tool.held, "app-misc/tool-1.0 build 2");
        assert!(!tool.installed);

        let mut conflicts: Vec<(String, String, bool)> = refusals
            .conflicts
            .iter()
            .map(|conflict| {
                (
                    conflict.stated_by.to_string(),
                    conflict.blocks.clone(),
                    conflict.stated_in_root,
                )
            })
            .collect();
        conflicts.sort();
        assert_eq!(
            conflicts,
            [
                (
                    "app-misc/tool-1.0".to_string(),
                    "sys-apps/openrc-0.62".to_string(),
                    false,
                ),
                (
                    "sys-apps/openrc-0.62".to_string(),
                    "app-editors/vim-9.1".to_string(),
                    true,
                ),
            ],
        );

        // Over a root that holds none of it, the same plan is admitted.
        let refusals = admit(
            &Installed::default(),
            vec![arriving("sys-libs/zlib-1.3.2", 1, &[("SLOT", "0/1\n")])],
        );
        assert!(refusals.is_empty(), "{}", refusals.describe());
    }

    #[test]
    fn a_replayed_plan_is_held_to_what_its_builds_require_of_the_root() {
        // A plan resolved against a stage3 that shipped `dev-libs/foo`,
        // replayed over one that does not. A resolution would have refused
        // the tool for the missing dependency, so the replay does too, naming
        // it, and only it: zlib is in the newer root, `a/y` answers the group
        // by being in the plan itself, and the post-merge dependency is the
        // plan's own first entry, whatever order the two merge in.
        let root = root(&["sys-libs/zlib-1.3.3"]);
        let plan = || {
            vec![
                arriving("app-misc/later-1.0", 1, &[("SLOT", "0\n")]),
                arriving(
                    "app-misc/tool-1.0",
                    2,
                    &[
                        ("SLOT", "0\n"),
                        (
                            "RDEPEND",
                            ">=sys-libs/zlib-1.3 dev-libs/foo || ( a/x a/y ) !a/z\n",
                        ),
                        ("PDEPEND", "app-misc/later\n"),
                    ],
                ),
                arriving("a/y-1", 3, &[("SLOT", "0\n")]),
            ]
        };
        let refusals = admit(&root, plan());
        assert_eq!(refusals.unsatisfied.len(), 1, "{}", refusals.describe());
        let missing = &refusals.unsatisfied[0];
        assert_eq!(missing.atom, "dev-libs/foo");
        assert_eq!(&*missing.wanted_by, "app-misc/tool-1.0");
        assert!(
            refusals
                .describe()
                .contains("app-misc/tool-1.0 requires dev-libs/foo, and no build in the root or in the plan answers it"),
            "{}",
            refusals.describe(),
        );
        assert!(refusals.conflicts.is_empty() && refusals.occupied.is_empty());

        // The root that still has it admits the same plan, and so does a plan
        // that brings it along.
        let older = Installed::of(
            [("sys-libs/zlib", "1.3.3"), ("dev-libs/foo", "2")]
                .map(|(name, version)| {
                    (
                        name.to_string(),
                        version.to_string(),
                        "0".to_string(),
                        String::new(),
                    )
                })
                .to_vec(),
        );
        let refusals = admit(&older, plan());
        assert!(refusals.is_empty(), "{}", refusals.describe());
        let mut bringing = plan();
        bringing.push(arriving("dev-libs/foo-2", 4, &[("SLOT", "0\n")]));
        let refusals = admit(&root, bringing);
        assert!(refusals.is_empty(), "{}", refusals.describe());

        // A group none of whose alternatives is there is refused as written.
        let mut without = plan();
        without.pop();
        without.push(arriving("dev-libs/foo-2", 4, &[("SLOT", "0\n")]));
        let refusals = admit(&root, without);
        assert_eq!(refusals.unsatisfied.len(), 1, "{}", refusals.describe());
        assert_eq!(refusals.unsatisfied[0].atom, "a/x or a/y");
    }

    #[test]
    fn a_preference_that_does_not_name_a_flag_is_refused() {
        assert!(Preference::parse("keyring").is_ok());
        assert!(Preference::parse("-X").is_ok());
        for text in ["", "-", "a b", "a/b", "a,b"] {
            assert!(Preference::parse(text).is_err(), "{text:?} was accepted");
        }
    }
}

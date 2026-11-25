//! The names the stack's nameserver has resolved, by the addresses their
//! answers gave.
//!
//! Each address an answer gives for a question is pinned to the name the guest
//! asked about ([`dns::answer_addresses`](super::dns::answer_addresses)), and a
//! flow to that address is then a flow to that name as far as the destination
//! rules and the reports go. A pin lasts for the attachment rather than for the
//! record's time to live. A program commonly holds an address well past it, and
//! a content network's records commonly live less than a minute, so a pin that
//! expired with its record would refuse connections the guest made in good
//! faith.
//!
//! The table holds [`MAX_PINS`] pins, a pin being one name at one address, and
//! the pin taken or renewed longest ago goes first. Several names can share an
//! address, as a content network's sites do, and an address keeps each of
//! them, the most recently pinned first.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

/// The most pins the table holds.
///
/// A pin costs its address and a share of its name's text. A full table of
/// ordinary names holds a few hundred kilobytes, and one of names as long as a
/// question can hold a few megabytes. The bound is far above the names one
/// sandbox resolves in practice, and a guest that resolves more evicts its own
/// oldest pins and nothing else.
pub(super) const MAX_PINS: usize = 4096;

/// One name pinned at an address.
#[derive(Debug)]
struct Pin {
    name: Arc<str>,
    /// When it was pinned or last renewed, as the table counts.
    taken: u64,
}

/// The pins of one attachment.
#[derive(Debug, Default)]
pub(super) struct Pins {
    /// The names pinned at each address, the most recently pinned first.
    by_address: BTreeMap<IpAddr, Vec<Pin>>,
    /// Each pin's address, by when it was taken, so the oldest is found first.
    by_age: BTreeMap<u64, IpAddr>,
    /// The count the last pin was taken at.
    taken: u64,
}

impl Pins {
    /// Pins `name` at `address`, or renews the pin where it is already there,
    /// evicting the oldest pin where the table is full.
    pub(super) fn pin(&mut self, address: IpAddr, name: &Arc<str>) {
        let held = self.by_address.get_mut(&address).and_then(|pins| {
            let index = pins.iter().position(|pin| pin.name == *name)?;
            Some(pins.remove(index))
        });
        match held {
            Some(pin) => {
                self.by_age.remove(&pin.taken);
            }
            None if self.by_age.len() >= MAX_PINS => self.evict_oldest(),
            None => {}
        }
        self.taken += 1;
        self.by_address.entry(address).or_default().insert(
            0,
            Pin {
                name: Arc::clone(name),
                taken: self.taken,
            },
        );
        self.by_age.insert(self.taken, address);
    }

    /// The names pinned at `address`, the most recently pinned first.
    pub(super) fn names(&self, address: IpAddr) -> impl Iterator<Item = &Arc<str>> + Clone {
        self.by_address
            .get(&address)
            .into_iter()
            .flatten()
            .map(|pin| &pin.name)
    }

    /// Removes the pin taken or renewed longest ago.
    fn evict_oldest(&mut self) {
        let Some((taken, address)) = self.by_age.pop_first() else {
            return;
        };
        if let Some(pins) = self.by_address.get_mut(&address) {
            pins.retain(|pin| pin.taken != taken);
            if pins.is_empty() {
                self.by_address.remove(&address);
            }
        }
    }

    /// How many pins the table holds.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_age.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(pins: &Pins, address: &str) -> Vec<String> {
        pins.names(address.parse().unwrap())
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn an_address_keeps_each_name_the_latest_first() {
        let mut pins = Pins::default();
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        for name in ["a.example", "b.example", "a.example"] {
            pins.pin(address, &Arc::from(name));
        }
        assert_eq!(named(&pins, "192.0.2.1"), ["a.example", "b.example"]);
        assert_eq!(pins.len(), 2, "a renewed pin is one pin");
        assert!(named(&pins, "192.0.2.2").is_empty());
    }

    #[test]
    fn the_oldest_pin_goes_first_at_the_bound() {
        let mut pins = Pins::default();
        let address = |index: usize| IpAddr::from([10, 0, (index >> 8) as u8, index as u8]);
        let name: Arc<str> = Arc::from("many.example");
        for index in 0..MAX_PINS {
            pins.pin(address(index), &name);
        }
        assert_eq!(pins.len(), MAX_PINS);
        // Renewing the first makes the second the oldest.
        pins.pin(address(0), &name);
        pins.pin(address(MAX_PINS), &name);
        assert_eq!(pins.len(), MAX_PINS);
        assert_eq!(pins.names(address(0)).count(), 1, "renewed, so kept");
        assert_eq!(pins.names(address(1)).count(), 0, "the oldest, so evicted");
        assert_eq!(pins.names(address(MAX_PINS)).count(), 1);
        // An address whose last pin goes is forgotten whole.
        assert!(!pins.by_address.contains_key(&address(1)));
    }

    #[test]
    fn eviction_takes_one_name_of_an_address_that_holds_several() {
        let mut pins = Pins::default();
        let shared: IpAddr = "198.51.100.7".parse().unwrap();
        pins.pin(shared, &Arc::from("first.example"));
        pins.pin(shared, &Arc::from("second.example"));
        for index in 0..MAX_PINS - 1 {
            pins.pin(
                IpAddr::from([10, 1, (index >> 8) as u8, index as u8]),
                &Arc::from("x"),
            );
        }
        assert_eq!(named(&pins, "198.51.100.7"), ["second.example"]);
    }
}

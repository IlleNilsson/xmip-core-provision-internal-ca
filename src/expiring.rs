//! What the ACME server keeps for a while: orders and authorizations by
//! the number their URL carries, each kept until it passes its `expires`
//! (RFC 8555 sections 7.1.3 and 7.1.4) and dropped then, so an account
//! that orders and never finalizes does not grow the server. A number is
//! never given twice: one dropped answers as none.

use std::collections::BTreeMap;

/// Something kept until a moment, seconds since the epoch.
pub(crate) trait Expires {
    /// When it expires.
    fn expires(&self) -> i64;
}

/// The entries kept, by number.
pub(crate) struct Expiring<T> {
    entries: BTreeMap<usize, T>,
    next: usize,
}

impl<T> Default for Expiring<T> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            next: 0,
        }
    }
}

impl<T: Expires> Expiring<T> {
    /// Keep `value`: the number it is reached by.
    pub(crate) fn insert(&mut self, value: T) -> usize {
        let number = self.next;
        self.next += 1;
        self.entries.insert(number, value);
        number
    }

    /// The entry `number`, where it is kept.
    pub(crate) fn get(&self, number: usize) -> Option<&T> {
        self.entries.get(&number)
    }

    /// The entry `number`, to change, where it is kept.
    pub(crate) fn get_mut(&mut self, number: usize) -> Option<&mut T> {
        self.entries.get_mut(&number)
    }

    /// Every entry kept, by number.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (usize, &T)> {
        self.entries.iter().map(|(number, value)| (*number, value))
    }

    /// Every entry kept, to change.
    pub(crate) fn values_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.entries.values_mut()
    }

    /// Drop every entry that expired by `now`.
    pub(crate) fn prune(&mut self, now: i64) {
        self.entries.retain(|_, value| value.expires() > now);
    }

    /// How many are kept.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Until(i64);

    impl Expires for Until {
        fn expires(&self) -> i64 {
            self.0
        }
    }

    #[test]
    fn an_entry_past_its_expiry_is_dropped_and_its_number_never_given_again() {
        let mut kept = Expiring::default();
        let early = kept.insert(Until(100));
        let late = kept.insert(Until(200));
        kept.prune(100);
        assert!(kept.get(early).is_none(), "expired at 100");
        assert!(kept.get(late).is_some());
        assert_eq!(kept.insert(Until(300)), late + 1);
        kept.prune(1_000);
        assert_eq!(kept.len(), 0);
    }
}

//! The nonces the authority's ACME server gives (RFC 8555 section 7.2):
//! one on every answer, taken back by the signed request that uses it.
//! Anyone may ask for one, so what is kept is bounded both ways: a nonce
//! lives [`LIFETIME`], and the oldest give way once [`MOST`] are kept. A
//! nonce gone answers `badNonce`, which an ACME client meets by sending
//! again with the fresh nonce that answer carries (section 6.5).

use std::collections::{HashMap, VecDeque};

/// How long a nonce given stays good, in seconds: ten minutes, far longer
/// than a client takes between asking for one and signing with it.
pub(crate) const LIFETIME: i64 = 600;

/// The most nonces kept at once.
pub(crate) const MOST: usize = 4_096;

/// The nonces given and not yet taken, and the order they were given in.
#[derive(Default)]
pub(crate) struct Nonces {
    given: HashMap<String, i64>,
    order: VecDeque<(i64, String)>,
}

impl Nonces {
    /// Keep `nonce`, given at `now`, the oldest dropped to make room.
    pub(crate) fn give(&mut self, nonce: String, now: i64) {
        self.expire(now);
        while self.order.len() >= MOST {
            self.drop_oldest();
        }
        self.given.insert(nonce.clone(), now);
        self.order.push_back((now, nonce));
    }

    /// Whether `nonce` was given, is still good at `now`, and is taken now.
    pub(crate) fn take(&mut self, nonce: &str, now: i64) -> bool {
        self.expire(now);
        self.given
            .remove(nonce)
            .is_some_and(|at| now - at < LIFETIME)
    }

    /// Drop every nonce given [`LIFETIME`] or longer before `now`.
    fn expire(&mut self, now: i64) {
        while self
            .order
            .front()
            .is_some_and(|(at, _)| now - at >= LIFETIME)
        {
            self.drop_oldest();
        }
    }

    fn drop_oldest(&mut self) {
        if let Some((_, oldest)) = self.order.pop_front() {
            self.given.remove(&oldest);
        }
    }

    /// How many entries are kept: the nonces in order, which the nonces
    /// still good never outnumber.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        debug_assert!(self.given.len() <= self.order.len());
        self.order.len()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use net::http::Request;

    use super::*;
    use crate::Authority;
    use crate::books::{Books, Policy};

    #[test]
    fn a_hundred_thousand_nonces_asked_for_keep_the_store_bounded() {
        let authority =
            Authority::create("Bounded Root", provision::now(), 86_400).expect("an authority");
        let policy = Policy {
            lifetime: 3_600,
            challenge_port: 80,
            dns: None,
        };
        let books = Books::new(
            "https://ca.example".to_string(),
            Arc::new(authority),
            policy,
        );
        let asking = Request::new("GET", "/new-nonce");
        let mut last = String::new();
        for _ in 0..100_000 {
            let answer = books.answer(&asking);
            last = answer
                .headers
                .iter()
                .find(|(name, _)| name == "Replay-Nonce")
                .map(|(_, value)| value.clone())
                .expect("a nonce");
        }
        assert!(books.state().nonces.len() <= MOST, "bounded");
        assert!(
            books.state().nonces.take(&last, provision::now()),
            "the newest kept"
        );
    }

    #[test]
    fn a_nonce_is_taken_once_and_one_past_its_lifetime_not_at_all() {
        let mut nonces = Nonces::default();
        nonces.give("fresh".to_string(), 1_000);
        nonces.give("stale".to_string(), 1_000 - LIFETIME);
        assert!(nonces.take("fresh", 1_000));
        assert!(!nonces.take("fresh", 1_000), "used already");
        assert!(!nonces.take("stale", 1_000), "expired");
        assert!(!nonces.take("never", 1_000));
        nonces.give("late".to_string(), 1_000 + LIFETIME);
        assert_eq!(nonces.len(), 1, "the rest expired");
    }
}

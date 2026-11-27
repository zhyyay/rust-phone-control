//! A single-slot handoff for work that should always converge on the newest input.
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

/// A bounded pending slot shared by a producer and one background worker.
///
/// Submitting while a worker is active replaces the pending value. Submitting
/// while idle atomically claims the worker slot and tells the caller to spawn.
pub(crate) struct LatestPendingSlot<T>(Mutex<Option<T>>);

impl<T> Default for LatestPendingSlot<T> {
    fn default() -> Self {
        Self(Mutex::new(None))
    }
}

impl<T> LatestPendingSlot<T> {
    /// Returns true when the caller must start a worker, false when the value
    /// was coalesced into the slot owned by an existing worker.
    pub(crate) fn submit(&self, value: T, in_flight: &AtomicBool) -> bool {
        let Ok(mut pending) = self.0.lock() else {
            return false;
        };

        if in_flight.swap(true, Ordering::AcqRel) {
            *pending = Some(value);
            false
        } else {
            // A previous worker may have exited during cancellation. The new
            // submission supersedes anything that worker left behind.
            *pending = None;
            true
        }
    }

    /// Takes the newest pending item, or releases worker ownership while
    /// still holding the slot lock when the slot is empty.
    pub(crate) fn take_or_release(
        &self,
        in_flight: &AtomicBool,
    ) -> Result<Option<T>, ()> {
        let mut pending = self.0.lock().map_err(|_| ())?;
        if let Some(value) = pending.take() {
            Ok(Some(value))
        } else {
            in_flight.store(false, Ordering::Release);
            Ok(None)
        }
    }

    /// Discards pending work and releases worker ownership under the same
    /// lock, so a concurrent producer cannot strand a new item.
    pub(crate) fn clear_and_release(&self, in_flight: &AtomicBool) -> Result<(), ()> {
        let mut pending = self.0.lock().map_err(|_| ())?;
        *pending = None;
        in_flight.store(false, Ordering::Release);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::LatestPendingSlot;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn first_submission_claims_worker_and_later_submissions_replace_pending() {
        let slot = LatestPendingSlot::default();
        let in_flight = AtomicBool::new(false);

        assert!(slot.submit(10, &in_flight));
        assert!(in_flight.load(Ordering::Acquire));
        assert!(!slot.submit(20, &in_flight));
        assert!(!slot.submit(30, &in_flight));

        assert_eq!(slot.take_or_release(&in_flight).unwrap(), Some(30));
        assert_eq!(slot.take_or_release(&in_flight).unwrap(), None);
        assert!(!in_flight.load(Ordering::Acquire));
    }

    #[test]
    fn clear_discards_pending_work_and_releases_worker_ownership() {
        let slot = LatestPendingSlot::default();
        let in_flight = AtomicBool::new(false);

        assert!(slot.submit(1, &in_flight));
        assert!(!slot.submit(2, &in_flight));
        slot.clear_and_release(&in_flight).unwrap();

        assert_eq!(slot.take_or_release(&in_flight).unwrap(), None);
        assert!(!in_flight.load(Ordering::Acquire));
        assert!(slot.submit(3, &in_flight));
    }

    #[test]
    fn submission_after_worker_release_claims_a_fresh_worker() {
        let slot = LatestPendingSlot::default();
        let in_flight = AtomicBool::new(false);

        assert!(slot.submit(1, &in_flight));
        assert!(!slot.submit(2, &in_flight));
        assert_eq!(slot.take_or_release(&in_flight).unwrap(), Some(2));
        assert!(in_flight.load(Ordering::Acquire));
        assert_eq!(slot.take_or_release(&in_flight).unwrap(), None);

        assert!(slot.submit(3, &in_flight));
        assert_eq!(slot.take_or_release(&in_flight).unwrap(), None);
        assert!(!in_flight.load(Ordering::Acquire));
    }
}

//! `governance` — the floors under the owner roster, shared by genesis, a resignation and
//! the people decisions in [`crate::approvals`].
//!
//! Pure and wasm-safe like [`crate::users`]: no I/O, no clock, no randomness.

use crate::error::DomainError;

/// Owners that must REMAIN after a removal.
///
/// Two, not three. An earlier draft of the policy used three, so that the money plane
/// could always still reach its `floor(N/2)+1` payout threshold — but at exactly three
/// owners that made a bad actor UNREMOVABLE: removal was blocked by the floor, and
/// admitting an ally to get past it needs the bad actor's own agreement. Dropping to two
/// suspends payouts, which is recoverable — two owners can admit a third and resume. A
/// permanent deadlock is not.
pub const MIN_OWNERS: usize = 2;

/// Owners below which the money plane can no longer authorize a payout at all: its
/// threshold is `floor(N/2)+1` over ALL owners while the initiator cannot vote, so two
/// owners can never reach it. Deliberately NOT [`MIN_OWNERS`] — this one is a WARNING
/// the roster surfaces, never a rule that blocks a removal.
pub const PAYOUT_MIN_OWNERS: usize = 3;
/// Longest reason an operator may write. Backed by a SQL CHECK.
pub const MAX_REASON_CHARS: usize = 500;

/// The floor, as one function so every path that takes a seat away decides it alike.
/// `owners` is the roster BEFORE the seat goes. Admission has no floor — growing the
/// roster can never breach one.
pub fn check_floor(owners: usize) -> Result<(), DomainError> {
	if owners.saturating_sub(1) < MIN_OWNERS {
		return Err(DomainError::Conflict(format!(
			"a fund must keep at least {MIN_OWNERS} owners, and this would leave {}",
			owners.saturating_sub(1)
		)));
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn floor_refuses_a_removal_that_would_leave_too_few() {
		for owners in 0..=MIN_OWNERS {
			assert!(check_floor(owners).is_err(), "{owners} owners cannot spare one");
		}
		assert!(check_floor(MIN_OWNERS + 1).is_ok(), "one to spare is exactly enough");
	}
}

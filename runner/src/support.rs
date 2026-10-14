//! Cross-module gRPC plumbing shared by the runner's services.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use domain::error::DomainError;
use subtle::ConstantTimeEq;
use tonic::{Request, Status};

/// Map a domain error to a gRPC status without leaking control-plane internals.
pub fn domain_to_status(err: DomainError) -> Status {
	match err {
		DomainError::NotFound { .. } => Status::not_found(err.to_string()),
		DomainError::Validation(_) => Status::invalid_argument(err.to_string()),
		DomainError::Forbidden(_) => Status::permission_denied(err.to_string()),
		DomainError::Conflict(_) => Status::already_exists(err.to_string()),
		DomainError::Precondition(_) => Status::failed_precondition(err.to_string()),
		DomainError::Repository(_) => Status::unavailable("internal error"),
	}
}

/// Authenticate a SERVICE-to-service caller against a shared bearer token.
///
/// The two seams that cross a plane boundary without a user behind them — the
/// lifecycle bridge the money plane pulls, and the mail relay it pushes to — both
/// authenticate this way rather than through the user `grpc_auth_layer`, and both are
/// mounted outside it. The comparison is constant time, so verifying leaks nothing
/// through timing; an unconfigured token fails CLOSED, because a seam that quietly
/// stops checking is worse than one that stops working.
///
/// WHY a shared token and not mTLS: this is the platform-bring-up transport. Graduate
/// to mTLS/SPIFFE workload identity at platform scale.
pub fn authenticate_service<T>(expected: Option<&Arc<str>>, request: &Request<T>, seam: &str) -> Result<(), Status> {
	let Some(expected) = expected else {
		return Err(Status::unavailable(format!("{seam} not configured")));
	};
	match bearer_token(request) {
		Some(presented) if bool::from(presented.as_bytes().ct_eq(expected.as_bytes())) => Ok(()),
		_ => Err(Status::unauthenticated(format!("invalid {seam} service token"))),
	}
}

pub(crate) fn bearer_token<T>(request: &Request<T>) -> Option<String> {
	let value = request.metadata().get("authorization")?.to_str().ok()?;
	value.strip_prefix("Bearer ").map(str::to_owned)
}

/// One page of a pull stream a caller reads through a filter
/// (`docs/SCOPES-AND-APPROVALS.md` §4.2). `scanned` is `(position, visible, row)`, oldest
/// first. The cursor is the MAXIMUM POSITION SCANNED: past rows the caller may not see, so
/// a filtered reader never re-scans them, and `after` when nothing was scanned. A page that
/// fills `limit` stops at its last row, so its cursor is exactly that row's position —
/// what lets a consumer re-pull one parked event with `after = position - 1, limit = 1`.
pub fn filtered_page<T>(scanned: impl IntoIterator<Item = (i64, bool, T)>, after: i64, limit: usize) -> (Vec<T>, i64) {
	let mut next = after;
	let mut page = Vec::new();
	for (position, visible, row) in scanned {
		if page.len() == limit {
			break;
		}
		next = position;
		if visible {
			page.push(row);
		}
	}
	(page, next)
}

#[cfg(test)]
mod tests {
	use super::filtered_page;

	#[test]
	fn the_cursor_is_the_maximum_position_scanned() {
		let scanned = || vec![(11, false, 'a'), (12, true, 'b'), (13, false, 'c'), (14, true, 'd'), (15, false, 'e')];
		assert_eq!(filtered_page(scanned(), 10, 10), (vec!['b', 'd'], 15), "an unfilled page reports the last row it scanned");
		assert_eq!(filtered_page(scanned(), 10, 2), (vec!['b', 'd'], 14), "a full page stops at its last event");
		assert_eq!(filtered_page(scanned(), 10, 1), (vec!['b'], 12), "limit 1 answers exactly that event's position");
		assert_eq!(
			filtered_page(Vec::<(i64, bool, char)>::new(), 10, 5),
			(vec![], 10),
			"nothing scanned leaves the cursor where it was"
		);
		assert_eq!(filtered_page(vec![(11, false, 'a')], 10, 5), (vec![], 11), "a page of invisible rows still moves the cursor");
	}
}

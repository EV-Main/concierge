//! FB-27 / CON-ARCHCOMM-01..03, CROSS-3, CROSS-4: the cross-plane
//! `UserLifecycleEvent` envelope carries everything the banking consumer needs to
//! dedupe (`event_id`), order (`sequence`), correlate (`auth_subject`), and
//! provision/gate (`email`/`email_verified`/`token_version`).
//!
//! Pure wire test: a prost encode→decode round trip proves the new fields exist at
//! distinct, non-colliding field numbers (a collision would mis-decode and drop a
//! value). No DB, no services.

use evconcierge_contracts::concierge::v1::{PullUserLifecycleRequest, SeatPermissions, UserLifecycleEvent, user_lifecycle_event::Kind};
use prost::Message;

#[test]
fn lifecycle_event_round_trips_with_full_envelope() {
	let event = UserLifecycleEvent {
		user_id: "concierge-canonical-uuid".to_string(),
		kind: Kind::Created as i32,
		kyc_level: 2,
		occurred_at: 1_700_000_000,
		event_id: "outbox-row-uuid".to_string(),
		sequence: 7,
		auth_subject: "google-sub-1234567890".to_string(),
		email: "user@example.com".to_string(),
		email_verified: true,
		token_version: 3,
		role: "admin".to_string(),
		seat_permissions: Some(SeatPermissions {
			bank: vec!["bank:treasury:read".to_string()],
		}),
	};

	let decoded = UserLifecycleEvent::decode(event.encode_to_vec().as_slice()).expect("round trips");

	assert_eq!(decoded, event);
	assert_eq!(decoded.event_id, "outbox-row-uuid");
	assert_eq!(decoded.sequence, 7);
	assert_eq!(decoded.auth_subject, "google-sub-1234567890");
	assert_eq!(decoded.email, "user@example.com");
	assert!(decoded.email_verified);
	assert_eq!(decoded.token_version, 3);
	assert_eq!(decoded.role, "admin");
}

#[test]
fn role_changed_kind_is_distinct() {
	// The new ROLE_CHANGED variant must round-trip as its own discriminant, and the
	// role string rides alongside it.
	let event = UserLifecycleEvent {
		kind: Kind::RoleChanged as i32,
		role: "operator".to_string(),
		..Default::default()
	};
	let decoded = UserLifecycleEvent::decode(event.encode_to_vec().as_slice()).expect("round trips");
	assert_eq!(decoded.kind(), Kind::RoleChanged);
	assert_eq!(decoded.role, "operator");
}

#[test]
fn an_empty_seat_set_is_told_apart_from_an_unstated_one() {
	let stated = UserLifecycleEvent {
		seat_permissions: Some(SeatPermissions { bank: vec![] }),
		..Default::default()
	};
	let unstated = UserLifecycleEvent::default();
	assert_eq!(
		UserLifecycleEvent::decode(stated.encode_to_vec().as_slice()).unwrap().seat_permissions,
		Some(SeatPermissions { bank: vec![] })
	);
	assert_eq!(UserLifecycleEvent::decode(unstated.encode_to_vec().as_slice()).unwrap().seat_permissions, None);
}

#[test]
fn the_lifecycle_vocabulary_is_the_money_planes_and_nothing_more() {
	// banking halts its single cursor on a kind it cannot name, so a scope or grant kind
	// here would stop every freeze and KYC change behind it until banking redeployed. Those
	// travel on ScopeEvents. Growing this list is a two-repo decision, never a side effect.
	let names: Vec<&str> = (0..=16).filter_map(|n| Kind::try_from(n).ok()).map(|k| k.as_str_name()).collect();
	assert_eq!(
		names,
		[
			"KIND_UNSPECIFIED",
			"CREATED",
			"SUSPENDED",
			"REINSTATED",
			"KYC_CHANGED",
			"SESSIONS_REVOKED",
			"ROLE_CHANGED",
			"PERMISSIONS_CHANGED"
		]
	);
	for scope_kind in ["SCOPE_CHANGED", "GRANTS_CHANGED", "MEMBER_JOINED"] {
		assert_eq!(Kind::from_str_name(scope_kind), None, "{scope_kind} belongs on ScopeEvents");
	}
}

#[test]
fn the_pull_request_banking_builds_still_has_exactly_its_two_fields() {
	// banking builds this with a struct literal and no `..Default::default()`; a field
	// added here breaks its build at the next pin bump. A relying party's filter comes from
	// its credential, not from the request. This literal fails to compile first.
	let request = PullUserLifecycleRequest { after_position: 7, limit: 256 };
	let decoded = PullUserLifecycleRequest::decode(request.encode_to_vec().as_slice()).expect("round trips");
	assert_eq!(decoded, request);
}

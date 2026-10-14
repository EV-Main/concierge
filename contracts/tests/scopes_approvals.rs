//! Wire tests for the scope and approval contracts (scopes.proto, approvals.proto): the
//! distinctions consumers act on survive an encode→decode round trip. No DB, no services.

use evconcierge_contracts::concierge::v1::{
	Approval, ApprovalAmount, ApprovalEscalation, ApprovalFieldSpec, ApprovalFieldType, ApprovalFieldValue, ApprovalKindSpec, ApprovalLevel, ApprovalState, EscalationTest,
	PublishScopeCatalogRequest, Scope, ScopeClient, ScopeEvent, ScopeGrants, approval_field_value::Value, scope_event::Kind,
};
use prost::Message;

fn round_trip<M: Message + Default>(message: &M) -> M {
	M::decode(message.encode_to_vec().as_slice()).expect("round trips")
}

fn field(key: &str, value: Value) -> ApprovalFieldValue {
	ApprovalFieldValue {
		key: key.to_string(),
		value: Some(value),
	}
}

#[test]
fn a_grant_set_emptied_is_told_apart_from_one_not_carried() {
	// A projection must apply "holds nothing here" — it is how a revocation lands.
	let emptied = ScopeEvent {
		kind: Kind::GrantsChanged as i32,
		grants: Some(ScopeGrants { permissions: vec![] }),
		..Default::default()
	};
	assert_eq!(round_trip(&emptied).grants, Some(ScopeGrants { permissions: vec![] }));
	assert_eq!(round_trip(&ScopeEvent::default()).grants, None);
}

#[test]
fn a_scope_snapshot_round_trips_with_its_clients_and_observers() {
	let scope = Scope {
		id: "sa".to_string(),
		namespace: "sa".to_string(),
		parent: "main".to_string(),
		display_name: "Service-Arb".to_string(),
		origins: vec!["https://sa.evinvest.ltd".to_string()],
		clients: vec![ScopeClient {
			client_id: "sa".to_string(),
			audience: "sa".to_string(),
			disabled: false,
		}],
		observers: vec!["invest".to_string()],
		created_at: 1_700_000_000,
		version: 3,
	};
	let event = ScopeEvent {
		kind: Kind::ScopeChanged as i32,
		scope: "sa".to_string(),
		sequence: 3,
		scope_snapshot: Some(scope.clone()),
		..Default::default()
	};
	let decoded = round_trip(&event);
	assert_eq!(decoded.kind(), Kind::ScopeChanged);
	assert_eq!(decoded.scope_snapshot, Some(scope));
}

#[test]
fn every_typed_field_value_keeps_its_type() {
	// The mail is rendered from these types; a value that decoded as another type would be
	// rendered as the wrong thing in front of someone approving money.
	let fields = vec![
		field(
			"amount",
			Value::Amount(ApprovalAmount {
				value: "1200.5".to_string(),
				currency: "USDT".to_string(),
			}),
		),
		field("deviation", Value::Bps(-1_250)),
		field("raises_ceiling", Value::Flag(false)),
		field("holder", Value::UserId("user-uuid".to_string())),
		field("effective_at", Value::Timestamp(1_700_000_000)),
		field("holders", Value::Count(0)),
		field("memo", Value::Text(String::new())),
	];
	let approval = Approval {
		kind: "bank:scope_transfer".to_string(),
		scope: "sa".to_string(),
		level: ApprovalLevel::Platform as i32,
		escalated_by: vec!["per_operation".to_string()],
		state: ApprovalState::Passed as i32,
		fields: fields.clone(),
		..Default::default()
	};
	let decoded = round_trip(&approval);
	assert_eq!(decoded.fields, fields);
	assert_eq!(decoded.level(), ApprovalLevel::Platform);
	assert_eq!(decoded.state(), ApprovalState::Passed);
	// A default-valued oneof arm is still SET: `false`, `0` and "" must not read as absent.
	for value in &decoded.fields {
		assert!(value.value.is_some(), "{} lost its value", value.key);
	}
}

#[test]
fn a_published_kind_keeps_its_escalation_parameters() {
	let kind = ApprovalKindSpec {
		name: "invest:valuation_override".to_string(),
		label: "Valuation override".to_string(),
		description: String::new(),
		level: ApprovalLevel::Scope as i32,
		fields: vec![ApprovalFieldSpec {
			key: "deviation".to_string(),
			label: "Deviation from last mark".to_string(),
			r#type: ApprovalFieldType::Bps as i32,
			required: true,
		}],
		escalations: vec![ApprovalEscalation {
			parameter: "max_deviation".to_string(),
			field_key: "deviation".to_string(),
			test: EscalationTest::AbsBpsAbove as i32,
			default_threshold: "1000".to_string(),
			currency: String::new(),
		}],
	};
	let request = PublishScopeCatalogRequest {
		version: 1_700_000_000,
		approval_kinds: vec![kind.clone()],
		notification_topics: vec![],
	};
	assert_eq!(round_trip(&request).approval_kinds, vec![kind]);
}

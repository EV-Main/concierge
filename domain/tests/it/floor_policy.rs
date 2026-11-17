//! A scope's tightening of a floor must outlive its publisher's next catalog.

use domain::{
	approvals::{Amount, Field, FieldValue, ScopePolicy, Threshold, fired_escalations},
	floors::floored,
	scope_catalog::{ApprovalKind, ApprovalLevel, Escalation, EscalationTest, FieldSpec, FieldType},
};

fn transfer(escalations: Vec<Escalation>) -> ApprovalKind {
	ApprovalKind {
		name: "bank:account_transfer".into(),
		label: "Transfer".into(),
		description: String::new(),
		level: ApprovalLevel::Scope,
		fields: vec![FieldSpec {
			key: "amount".into(),
			label: "Amount".into(),
			field_type: FieldType::Amount,
			required: true,
			repeated: false,
		}],
		escalations,
	}
}

#[test]
fn should_escalate_above_a_scope_tightened_floor_after_the_catalog_covers_that_floor() {
	// Given: the scope tightened the floor's per-operation cap to 700 USDT while the catalog
	// had no escalation, so the floor named it `floor_per_operation`.
	let policy = ScopePolicy {
		thresholds: vec![Threshold {
			kind: "bank:account_transfer".into(),
			parameter: "floor_per_operation".into(),
			value: "700".into(),
		}],
		..ScopePolicy::default()
	};
	let fields = vec![Field {
		key: "amount".into(),
		value: FieldValue::Amount(Amount {
			value: "750".into(),
			currency: "USDT".into(),
		}),
	}];
	assert_eq!(
		fired_escalations(&floored(&transfer(vec![])), &fields, &policy, &[]),
		vec!["floor_per_operation".to_owned()],
		"precondition: 750 USDT is above the scope's 700"
	);

	// When: the publisher republishes the kind with its own per-operation escalation at the cap.
	let covered = floored(&transfer(vec![Escalation {
		parameter: "per_operation".into(),
		field_key: "amount".into(),
		test: EscalationTest::AmountAbove,
		default_threshold: "1000".into(),
		currency: "USDT".into(),
	}]));

	// Then: 750 USDT still escalates — the scope's 700 has not been dropped by the publisher.
	let fired = fired_escalations(&covered, &fields, &policy, &[]);
	assert!(!fired.is_empty(), "expected 750 USDT above the scope's 700 to escalate, got {fired:?}");
}

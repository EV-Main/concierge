//! Installed caps replace the plan's defaults wherever the floor binds. A test binary of
//! its own: `floors::configure` is once per process.

use domain::{
	floors::{MoneyCaps, check, configure, floored},
	scope_catalog::{ApprovalKind, ApprovalLevel, Escalation, EscalationTest, FieldSpec, FieldType},
};

fn transfer(per_operation: &str) -> ApprovalKind {
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
		escalations: vec![Escalation {
			parameter: "per_operation".into(),
			field_key: "amount".into(),
			test: EscalationTest::AmountAbove,
			default_threshold: per_operation.into(),
			currency: "USDT".into(),
		}],
	}
}

#[test]
fn should_hold_scope_kinds_to_the_configured_caps() {
	// Given: the owners raised the caps to 2000 per operation and 8000 a day.
	configure(MoneyCaps::new("2000", "8000").expect("valid caps")).expect("first install");

	// Then: a catalog at 1500 — looser than the default 1000 — is now within the floor,
	assert_eq!(check(&transfer("1500")), Ok(()));
	// one at 2500 is still refused,
	assert!(check(&transfer("2500")).is_err());
	// and the floor's own escalations carry the configured caps.
	let kind = floored(&transfer("1500"));
	let threshold = |parameter: &str| kind.escalations.iter().find(|e| e.parameter == parameter).map(|e| e.default_threshold.clone());
	assert_eq!(threshold("floor_per_operation").as_deref(), Some("2000"));
	assert_eq!(threshold("floor_daily").as_deref(), Some("8000"));
	assert_eq!(threshold("per_operation").as_deref(), Some("1500"), "a stricter catalog stands");

	// And: a second install is refused rather than silently switching floors mid-process.
	assert!(configure(MoneyCaps::new("1", "1").expect("valid caps")).is_err());
}

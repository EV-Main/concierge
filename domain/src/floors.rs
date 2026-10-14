//! The floor this plane keeps on the known money kinds, whatever their publisher's catalog
//! says (D24, decided by the session; `docs/SCOPES-AND-APPROVALS.md` §5.3).
//!
//! A catalog is the publisher's word, and the publisher is the service that moves the
//! money: a compromised or careless release could publish `bank:payment` at scope level, or
//! a transfer threshold of a million, and every decision from then on would bypass the
//! owners. So the levels and thresholds the organisation plan fixes (§4.4) live HERE, in one
//! table, and bind twice: a publication that is looser is refused, and a proposal is
//! measured against the stricter of the table and the catalog in force — which also covers
//! a catalog stored before this table existed.

use crate::{
	approvals::amount_above,
	scope_catalog::{ApprovalKind, ApprovalLevel, Escalation, EscalationTest},
};

/// One escalation the table holds a kind to. `parameter` is what `escalated_by` names
/// when the table, not the catalog, sent the proposal to the owners.
#[derive(Clone, Copy, Debug)]
pub struct Floor {
	pub parameter: &'static str,
	pub field_key: &'static str,
	pub test: EscalationTest,
	/// The highest threshold allowed; empty for FLAG_SET.
	pub cap: &'static str,
	pub currency: &'static str,
}

#[derive(Clone, Copy, Debug)]
pub enum KindFloor {
	/// Always decided by the owners.
	Platform,
	/// Decided in the scope up to these limits.
	Scope(&'static [Floor]),
}

const fn floor(parameter: &'static str, field_key: &'static str, test: EscalationTest, cap: &'static str, currency: &'static str) -> Floor {
	Floor {
		parameter,
		field_key,
		test,
		cap,
		currency,
	}
}

/// §4.4 of the organisation plan: what leaves the platform, crosses scopes, seeds or
/// sweeps capital, sets a compartment's limits or grants holdings is always the owners';
/// inside a scope, 1000 USDT per operation and 5000 USDT a day, a payout to one recipient,
/// a valuation within 10 % and a fee change within its ceiling.
const TABLE: &[(&str, KindFloor)] = &[
	("bank:payment", KindFloor::Platform),
	("bank:scope_transfer", KindFloor::Platform),
	("bank:seed_capital", KindFloor::Platform),
	("bank:treasury_surplus", KindFloor::Platform),
	("bank:compartment_policy", KindFloor::Platform),
	("invest:holder_grant", KindFloor::Platform),
	(
		"bank:account_transfer",
		KindFloor::Scope(&[
			floor("floor_per_operation", "amount", EscalationTest::AmountAbove, "1000", "USDT"),
			floor("floor_daily", "amount", EscalationTest::Rolling24hAmountAbove, "5000", "USDT"),
		]),
	),
	(
		"bank:scope_payout",
		KindFloor::Scope(&[
			floor("floor_per_operation", "total", EscalationTest::AmountAbove, "1000", "USDT"),
			floor("floor_daily", "total", EscalationTest::Rolling24hAmountAbove, "5000", "USDT"),
			// A distribution to more than one holder is a dividend: the owners' (D24).
			floor("floor_recipients", "recipients", EscalationTest::CountAbove, "1", ""),
		]),
	),
	(
		"invest:valuation_override",
		KindFloor::Scope(&[floor("floor_deviation", "deviation", EscalationTest::AbsBpsAbove, "1000", "")]),
	),
	(
		"invest:fee_policy",
		KindFloor::Scope(&[floor("floor_ceiling", "raises_ceiling", EscalationTest::FlagSet, "", "")]),
	),
];

pub fn floor_of(kind: &str) -> Option<KindFloor> {
	TABLE.iter().find(|(name, _)| *name == kind).map(|(_, floor)| *floor)
}

/// The stricter of two thresholds of one test: `None` when either does not parse, which a
/// caller reads as "cannot measure" and escalates.
pub fn stricter(test: EscalationTest, a: &str, b: &str) -> Option<String> {
	match test {
		EscalationTest::AmountAbove | EscalationTest::Rolling24hAmountAbove => Some(if amount_above(a, b) { b } else { a }.to_owned()),
		EscalationTest::AbsBpsAbove | EscalationTest::CountAbove => Some(a.parse::<u64>().ok()?.min(b.parse::<u64>().ok()?).to_string()),
		EscalationTest::FlagSet => Some(String::new()),
	}
}

/// Whether `threshold` is looser than the floor's cap.
fn looser(floor: &Floor, threshold: &str) -> bool {
	match floor.test {
		EscalationTest::AmountAbove | EscalationTest::Rolling24hAmountAbove => amount_above(threshold, floor.cap),
		EscalationTest::AbsBpsAbove | EscalationTest::CountAbove => match (threshold.parse::<u64>(), floor.cap.parse::<u64>()) {
			(Ok(value), Ok(cap)) => value > cap,
			_ => true,
		},
		EscalationTest::FlagSet => false,
	}
}

/// A publication of a known kind is refused if it is looser than the table: a platform
/// kind at scope level, a floor's field missing or of another type, or an escalation of the
/// floor's test and field above its cap or in another currency.
pub fn check(kind: &ApprovalKind) -> Result<(), String> {
	let name = &kind.name;
	match floor_of(name) {
		None => Ok(()),
		Some(KindFloor::Platform) if kind.level != ApprovalLevel::Platform => Err(format!("approval kind `{name}` is always decided by the platform owners")),
		Some(KindFloor::Platform) => Ok(()),
		Some(KindFloor::Scope(floors)) => {
			for floor in floors {
				let field = kind.fields.iter().find(|f| f.key == floor.field_key);
				if !field.is_some_and(|f| f.field_type == floor.test.tests() && f.required) {
					return Err(format!("approval kind `{name}` declares no required `{}` field of the type its floor tests", floor.field_key));
				}
				for e in kind.escalations.iter().filter(|e| e.test == floor.test && e.field_key == floor.field_key) {
					if looser(floor, &e.default_threshold) || e.currency != floor.currency {
						return Err(format!(
							"approval kind `{name}` escalation `{}` is looser than this plane's floor: at most {} {}",
							e.parameter, floor.cap, floor.currency
						));
					}
				}
			}
			Ok(())
		}
	}
}

/// `kind` as a proposal is measured against: at the platform if the table says so, its
/// own escalations capped at the floor, and every floor it does not cover added beside
/// them.
pub fn floored(kind: &ApprovalKind) -> ApprovalKind {
	let mut floored = kind.clone();
	match floor_of(&kind.name) {
		None => {}
		Some(KindFloor::Platform) => {
			floored.level = ApprovalLevel::Platform;
			floored.escalations.clear();
		}
		Some(KindFloor::Scope(floors)) => {
			for floor in floors {
				// An escalation in another currency than the cap's cannot be capped: it does
				// not cover the floor, whose own escalation is added and escalates what it
				// cannot measure.
				let mut covered = false;
				for e in floored
					.escalations
					.iter_mut()
					.filter(|e| e.test == floor.test && e.field_key == floor.field_key && e.currency == floor.currency)
				{
					covered = true;
					if let Some(stricter) = stricter(floor.test, &e.default_threshold, floor.cap) {
						e.default_threshold = stricter;
					}
				}
				if !covered && floored.level == ApprovalLevel::Scope {
					floored.escalations.push(Escalation {
						parameter: floor.parameter.to_owned(),
						field_key: floor.field_key.to_owned(),
						test: floor.test,
						default_threshold: floor.cap.to_owned(),
						currency: floor.currency.to_owned(),
					});
				}
			}
		}
	}
	floored
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::scope_catalog::{FieldSpec, FieldType};

	fn field(key: &str, field_type: FieldType) -> FieldSpec {
		FieldSpec {
			key: key.into(),
			label: key.into(),
			field_type,
			required: true,
			repeated: false,
		}
	}

	fn kind(name: &str, level: ApprovalLevel, fields: Vec<FieldSpec>, escalations: Vec<Escalation>) -> ApprovalKind {
		ApprovalKind {
			name: name.into(),
			label: "Money".into(),
			description: String::new(),
			level,
			fields,
			escalations,
		}
	}

	fn amount_escalation(parameter: &str, test: EscalationTest, threshold: &str) -> Escalation {
		Escalation {
			parameter: parameter.into(),
			field_key: "amount".into(),
			test,
			default_threshold: threshold.into(),
			currency: "USDT".into(),
		}
	}

	#[test]
	fn the_table_is_consistent() {
		for (name, floor) in TABLE {
			assert!(name.contains(':'), "{name}");
			if let KindFloor::Scope(floors) = floor {
				for f in *floors {
					assert!(f.parameter.starts_with("floor_"), "{name}: a floor names itself apart from the catalog's own");
				}
			}
		}
	}

	#[test]
	fn a_platform_kind_stays_the_platforms() {
		let payment = kind("bank:payment", ApprovalLevel::Scope, vec![field("amount", FieldType::Amount)], vec![]);
		assert!(check(&payment).is_err());
		assert_eq!(floored(&payment).level, ApprovalLevel::Platform);
	}

	#[test]
	fn a_scope_kind_is_held_to_its_caps() {
		let fields = vec![field("amount", FieldType::Amount)];
		let loose = kind(
			"bank:account_transfer",
			ApprovalLevel::Scope,
			fields.clone(),
			vec![amount_escalation("per_operation", EscalationTest::AmountAbove, "2000")],
		);
		assert!(check(&loose).is_err());
		let floored = floored(&loose);
		let per_operation = floored.escalations.iter().find(|e| e.parameter == "per_operation").unwrap();
		assert_eq!(per_operation.default_threshold, "1000", "a stored looser catalog is capped at the floor");
		assert!(floored.escalations.iter().any(|e| e.parameter == "floor_daily"), "an uncovered floor is added");
		assert!(!floored.escalations.iter().any(|e| e.parameter == "floor_per_operation"), "a covered one is not doubled");

		let tight = kind(
			"bank:account_transfer",
			ApprovalLevel::Scope,
			fields,
			vec![amount_escalation("per_operation", EscalationTest::AmountAbove, "500")],
		);
		assert_eq!(check(&tight), Ok(()));
		assert_eq!(super::floored(&tight).escalations[0].default_threshold, "500", "a stricter catalog stands");
		assert!(check(&kind("bank:account_transfer", ApprovalLevel::Scope, vec![field("value", FieldType::Amount)], vec![])).is_err());
	}

	#[test]
	fn stricter_takes_the_lower_threshold() {
		assert_eq!(stricter(EscalationTest::AmountAbove, "1000.5", "1000").as_deref(), Some("1000"));
		assert_eq!(stricter(EscalationTest::CountAbove, "3", "1").as_deref(), Some("1"));
		assert_eq!(stricter(EscalationTest::AbsBpsAbove, "x", "1"), None);
	}
}

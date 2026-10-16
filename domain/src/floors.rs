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
//!
//! The two money caps of the scope kinds — per operation and per trailing day — are read
//! from the runner's environment (`APPROVAL_FLOOR_PER_OPERATION_USDT`,
//! `APPROVAL_FLOOR_DAILY_USDT`) and installed once at boot with [`configure`]; unset, they
//! are [`MoneyCaps::DEFAULT`]. Environment and not the database, because the floor exists
//! to hold against a compromised publisher, and anything a running service can write is
//! within that publisher's reach: the environment is set in the devops repo by a reviewed
//! PR, so moving a cap stays a decision of the platform owners and still needs no release
//! of this code. Every other cap is a constant on purpose.

use std::sync::OnceLock;

use crate::{
	approvals::amount_above,
	scope_catalog::{ApprovalKind, ApprovalLevel, Escalation, EscalationTest, is_canonical_amount},
};

/// The money caps of the scope kinds, in USDT, as canonical amounts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoneyCaps {
	per_operation: String,
	daily: String,
}

impl MoneyCaps {
	/// §4.4 of the organisation plan.
	pub const DEFAULT: (&'static str, &'static str) = ("1000", "5000");

	/// Both caps must be positive canonical amounts — the spelling a threshold is compared
	/// in, so `1000.0` or `1e3` is refused rather than compared wrongly.
	pub fn new(per_operation: &str, daily: &str) -> Result<Self, String> {
		let valid = |name: &str, raw: &str| {
			if is_canonical_amount(raw) && raw != "0" {
				Ok(raw.to_owned())
			} else {
				Err(format!(
					"{name} must be a positive decimal amount without leading or trailing zeros (e.g. `1000` or `2500.5`), got `{raw}`"
				))
			}
		};
		Ok(Self {
			per_operation: valid("APPROVAL_FLOOR_PER_OPERATION_USDT", per_operation)?,
			daily: valid("APPROVAL_FLOOR_DAILY_USDT", daily)?,
		})
	}

	pub fn per_operation(&self) -> &str {
		&self.per_operation
	}

	pub fn daily(&self) -> &str {
		&self.daily
	}
}

static MONEY_CAPS: OnceLock<MoneyCaps> = OnceLock::new();

/// Installs the caps for the life of the process. Refused once caps are installed: two
/// values in one process would measure proposals against two different floors.
pub fn configure(caps: MoneyCaps) -> Result<(), String> {
	MONEY_CAPS.set(caps).map_err(|_| "the money floor caps are already configured".to_owned())
}

/// A floor's highest threshold allowed.
#[derive(Clone, Copy, Debug)]
pub enum Cap {
	Fixed(&'static str),
	/// [`MoneyCaps::per_operation`].
	PerOperation,
	/// [`MoneyCaps::daily`].
	Daily,
}

impl Cap {
	pub fn value(self) -> &'static str {
		match self {
			Cap::Fixed(cap) => cap,
			Cap::PerOperation => MONEY_CAPS.get().map_or(MoneyCaps::DEFAULT.0, |c| c.per_operation.as_str()),
			Cap::Daily => MONEY_CAPS.get().map_or(MoneyCaps::DEFAULT.1, |c| c.daily.as_str()),
		}
	}
}

/// One escalation the table holds a kind to. `parameter` is what `escalated_by` names
/// when the table, not the catalog, sent the proposal to the owners.
#[derive(Clone, Copy, Debug)]
pub struct Floor {
	pub parameter: &'static str,
	pub field_key: &'static str,
	pub test: EscalationTest,
	/// Empty for FLAG_SET.
	pub cap: Cap,
	pub currency: &'static str,
}

#[derive(Clone, Copy, Debug)]
pub enum KindFloor {
	/// Always decided by the owners.
	Platform,
	/// Decided in the scope up to these limits.
	Scope(&'static [Floor]),
	/// A kind of a money namespace that moves no money, named here so that it may be
	/// decided in its scope without limits. A kind of such a namespace the table does not
	/// name is the owners' (see [`floor_of`]).
	Unbounded,
}

const fn floor(parameter: &'static str, field_key: &'static str, test: EscalationTest, cap: Cap, currency: &'static str) -> Floor {
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
/// inside a scope, [`MoneyCaps`] per operation and a day (1000 and 5000 USDT unless
/// configured), a payout to one recipient
/// a day, a valuation within 10 % and a fee change within its ceiling.
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
			floor("floor_per_operation", "amount", EscalationTest::AmountAbove, Cap::PerOperation, "USDT"),
			floor("floor_daily", "amount", EscalationTest::Rolling24hAmountAbove, Cap::Daily, "USDT"),
		]),
	),
	(
		"bank:scope_payout",
		KindFloor::Scope(&[
			floor("floor_per_operation", "total", EscalationTest::AmountAbove, Cap::PerOperation, "USDT"),
			floor("floor_daily", "total", EscalationTest::Rolling24hAmountAbove, Cap::Daily, "USDT"),
			floor("floor_recipients", "recipients", EscalationTest::CountAbove, Cap::Fixed("1"), ""),
			// One recipient a day in a scope: a payout split into single-recipient ones must
			// not pass as many small decisions what is one distribution (decided by the session).
			floor("floor_daily_recipients", "recipients", EscalationTest::Rolling24hCountAbove, Cap::Fixed("1"), ""),
			// A distribution to every holder is a dividend: the owners' (D24).
			floor("floor_distribution", "distribution", EscalationTest::FlagSet, Cap::Fixed(""), ""),
			// The single daily scope budget (D24(4)) is banking's to measure; the escalation it
			// raises must not live only in banking's catalog, or a wrong publication drops it.
			floor("floor_scope_budget", "over_scope_budget", EscalationTest::FlagSet, Cap::Fixed(""), ""),
		]),
	),
	(
		"invest:valuation_override",
		KindFloor::Scope(&[floor("floor_deviation", "deviation", EscalationTest::AbsBpsAbove, Cap::Fixed("1000"), "")]),
	),
	(
		"invest:fee_policy",
		KindFloor::Scope(&[floor("floor_ceiling", "raises_ceiling", EscalationTest::FlagSet, Cap::Fixed(""), "")]),
	),
];

/// What the table holds `kind` to. `None` for a kind of a namespace the table does not
/// govern. A kind of a governed namespace (`bank`, `invest`) the table does not name is
/// [`KindFloor::Platform`]: an allow-list, so a money kind added to a catalog before it is
/// added here goes to the owners rather than slipping past them.
pub fn floor_of(kind: &str) -> Option<KindFloor> {
	if let Some((_, floor)) = TABLE.iter().find(|(name, _)| *name == kind) {
		return Some(*floor);
	}
	let namespace = kind.split(':').next().unwrap_or_default();
	TABLE.iter().any(|(name, _)| name.split(':').next() == Some(namespace)).then_some(KindFloor::Platform)
}

/// Whether `parameter` is one the table reserves for its own escalations.
pub fn is_floor_parameter(parameter: &str) -> bool {
	parameter.starts_with("floor_")
}

/// The stricter of two thresholds of one test: `None` when either does not parse, which a
/// caller reads as "cannot measure" and escalates.
pub fn stricter(test: EscalationTest, a: &str, b: &str) -> Option<String> {
	match test {
		EscalationTest::AmountAbove | EscalationTest::Rolling24hAmountAbove => Some(if amount_above(a, b) { b } else { a }.to_owned()),
		EscalationTest::AbsBpsAbove | EscalationTest::CountAbove | EscalationTest::Rolling24hCountAbove => Some(a.parse::<u64>().ok()?.min(b.parse::<u64>().ok()?).to_string()),
		EscalationTest::FlagSet => Some(String::new()),
	}
}

/// Whether `threshold` is looser than the floor's cap.
fn looser(floor: &Floor, threshold: &str) -> bool {
	match floor.test {
		EscalationTest::AmountAbove | EscalationTest::Rolling24hAmountAbove => amount_above(threshold, floor.cap.value()),
		EscalationTest::AbsBpsAbove | EscalationTest::CountAbove | EscalationTest::Rolling24hCountAbove => match (threshold.parse::<u64>(), floor.cap.value().parse::<u64>()) {
			(Ok(value), Ok(cap)) => value > cap,
			_ => true,
		},
		EscalationTest::FlagSet => false,
	}
}

/// A publication of a governed kind is refused if it is looser than the table: a platform
/// kind — named, or of a governed namespace and not named — at scope level, or a scope kind
/// published at scope level with a floor's field missing or of another type, or with an
/// escalation of the floor's test and field above its cap or in another currency. A scope
/// kind published at the platform is stricter and needs none of that.
pub fn check(kind: &ApprovalKind) -> Result<(), String> {
	let name = &kind.name;
	match floor_of(name) {
		None | Some(KindFloor::Unbounded) => Ok(()),
		Some(KindFloor::Platform) if kind.level != ApprovalLevel::Platform => Err(format!(
			"approval kind `{name}` is decided by the platform owners: this plane's floor names it so, or does not name it at all"
		)),
		Some(KindFloor::Platform) => Ok(()),
		Some(KindFloor::Scope(_)) if kind.level == ApprovalLevel::Platform => Ok(()),
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
							e.parameter,
							floor.cap.value(),
							floor.currency
						));
					}
				}
			}
			Ok(())
		}
	}
}

/// `kind` as a proposal is measured against: at the platform if the table says so, else
/// its own escalations capped at the floor and EVERY floor beside them. The floors are
/// always there, under their own names, so a scope policy that tightened one keeps
/// tightening it whatever the publisher's next catalog declares (review of #142).
pub fn floored(kind: &ApprovalKind) -> ApprovalKind {
	let mut floored = kind.clone();
	match floor_of(&kind.name) {
		None | Some(KindFloor::Unbounded) => {}
		Some(KindFloor::Platform) => {
			floored.level = ApprovalLevel::Platform;
			floored.escalations.clear();
		}
		Some(KindFloor::Scope(floors)) => {
			if floored.level == ApprovalLevel::Platform {
				floored.escalations.clear();
				return floored;
			}
			for floor in floors {
				for e in floored
					.escalations
					.iter_mut()
					.filter(|e| e.test == floor.test && e.field_key == floor.field_key && e.currency == floor.currency)
				{
					if let Some(stricter) = stricter(floor.test, &e.default_threshold, floor.cap.value()) {
						e.default_threshold = stricter;
					}
				}
				floored.escalations.retain(|e| e.parameter != floor.parameter);
				floored.escalations.push(Escalation {
					parameter: floor.parameter.to_owned(),
					field_key: floor.field_key.to_owned(),
					test: floor.test,
					default_threshold: floor.cap.value().to_owned(),
					currency: floor.currency.to_owned(),
				});
			}
		}
	}
	floored
}

/// The table's rules no escalation test can state, fired over a proposal's fields.
pub fn special_fired(kind: &str, fields: &[crate::approvals::Field]) -> Vec<String> {
	use crate::approvals::FieldValue;
	let mut fired = Vec::new();
	// A payout to nobody is not a payout the scope can decide: whatever it moves, it
	// moves to no named holder, and only the owners should be asked about that.
	if kind == "bank:scope_payout" && fields.iter().any(|f| f.key == "recipients" && f.value == FieldValue::Count(0)) {
		fired.push("floor_no_recipients".to_owned());
	}
	fired
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
		assert!(
			floored.escalations.iter().any(|e| e.parameter == "floor_per_operation"),
			"a covered one is kept too, under its own name, for a scope policy to hold onto"
		);

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
	fn a_governed_namespace_is_an_allow_list() {
		let unknown = kind("bank:new_rail", ApprovalLevel::Scope, vec![field("amount", FieldType::Amount)], vec![]);
		assert!(check(&unknown).is_err(), "a bank kind the table does not name is not a scope's");
		assert_eq!(floored(&unknown).level, ApprovalLevel::Platform, "and a stored one goes to the owners");
		let elsewhere = kind("sa:lead_bonus", ApprovalLevel::Scope, vec![], vec![]);
		assert_eq!(check(&elsewhere), Ok(()), "a namespace the table does not govern is its publisher's");
	}

	#[test]
	fn a_scope_kind_published_at_the_platform_needs_no_floor_field() {
		assert_eq!(check(&kind("bank:account_transfer", ApprovalLevel::Platform, vec![], vec![])), Ok(()));
	}

	/// The catalog here escalates nothing, as one published without the budget escalation
	/// would: the flag must still reach the owners.
	#[test]
	fn the_scope_budget_flag_escalates_without_the_catalog() {
		use crate::approvals::{Field, FieldValue, ScopePolicy, fired_escalations, resolve_level};
		let payout = kind("bank:scope_payout", ApprovalLevel::Scope, vec![field("over_scope_budget", FieldType::Flag)], vec![]);
		let floored = floored(&payout);
		let flag = |on| {
			[Field {
				key: "over_scope_budget".into(),
				value: FieldValue::Flag(on),
			}]
		};
		let fired = fired_escalations(&floored, &flag(true), &ScopePolicy::default(), &[]);
		assert!(fired.contains(&"floor_scope_budget".to_owned()), "{fired:?}");
		assert_eq!(resolve_level(floored.level, false, fired, 2).level, ApprovalLevel::Platform);
		let unset = fired_escalations(&floored, &flag(false), &ScopePolicy::default(), &[]);
		assert!(!unset.contains(&"floor_scope_budget".to_owned()), "{unset:?}");
	}

	#[test]
	fn a_payout_to_nobody_goes_to_the_owners() {
		use crate::approvals::{Field, FieldValue};
		let fields = [Field {
			key: "recipients".into(),
			value: FieldValue::Count(0),
		}];
		assert_eq!(special_fired("bank:scope_payout", &fields), vec!["floor_no_recipients".to_owned()]);
		assert!(special_fired("bank:account_transfer", &fields).is_empty());
	}

	#[test]
	fn money_caps_take_positive_canonical_amounts_only() {
		let caps = MoneyCaps::new("2500.5", "10000").expect("valid caps");
		assert_eq!((caps.per_operation(), caps.daily()), ("2500.5", "10000"));
		for bad in ["0", "", "-1", "1000.0", "01000", "1e3", " 1000", "1000 USDT"] {
			let error = MoneyCaps::new(bad, "5000").expect_err(bad);
			assert!(error.contains("APPROVAL_FLOOR_PER_OPERATION_USDT"), "{error}");
		}
		assert!(MoneyCaps::new("1000", "0").unwrap_err().contains("APPROVAL_FLOOR_DAILY_USDT"));
		let (per_operation, daily) = MoneyCaps::DEFAULT;
		assert!(MoneyCaps::new(per_operation, daily).is_ok(), "the defaults pass their own check");
	}

	/// Nothing in this binary installs caps — that would leak into every other test of the
	/// process — so the configured path has a test binary of its own
	/// (`tests/configured_floors.rs`).
	#[test]
	fn unconfigured_money_caps_are_the_plans() {
		assert_eq!(Cap::PerOperation.value(), "1000");
		assert_eq!(Cap::Daily.value(), "5000");
	}

	#[test]
	fn stricter_takes_the_lower_threshold() {
		assert_eq!(stricter(EscalationTest::AmountAbove, "1000.5", "1000").as_deref(), Some("1000"));
		assert_eq!(stricter(EscalationTest::CountAbove, "3", "1").as_deref(), Some("1"));
		assert_eq!(stricter(EscalationTest::AbsBpsAbove, "x", "1"), None);
	}
}

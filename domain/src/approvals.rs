//! `approvals` — the consilium generalised to every scope (`docs/SCOPES-AND-APPROVALS.md`
//! §5, `approvals.proto`).
//!
//! Pure and wasm-safe like [`crate::governance`]: ids, the clock, the roster and the
//! amounts already counted in a scope's trailing window are supplied by the application
//! layer, so every rule here — who decides, when a proposal passes, what a veto may still
//! stop — is testable without a database and identical for every caller.
//!
//! What differs from the owner consilia, and why:
//!
//! * the quorum is MORE THAN HALF of a roster frozen at open and NOBODY is excluded from
//!   it: a service cannot prove which person asked it, so the person it names
//!   (`requested_by`) is information, never a fact a quorum can rest on (§5.2);
//! * a passed proposal is not executed here — it waits out a veto delay and is then
//!   PULLED by the one namespace that proposed it, which reports the outcome (§5.4).
//!   "Executable" is `Passed` with the clock past `executable_at`, not a state, so nothing
//!   has to sweep for a proposal to become pullable — the same reason expiry is lazy.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::{
	error::DomainError,
	scope_catalog::{ApprovalKind, ApprovalLevel, Escalation, EscalationTest, FieldSpec, FieldType, is_canonical_amount, is_currency, plain_text},
	users::UserId,
};

/// The platform roster's bar: more than half of the owners, as the user consilia.
pub const PLATFORM_QUORUM_BPS: u32 = 5001;
/// The owners' veto window, the consilium's.
pub const PLATFORM_DELAY_SECS: u32 = 24 * 60 * 60;
/// How long any proposal may stay open; the platform's lifetime and a scope's ceiling.
pub const MAX_TTL_SECS: u32 = 72 * 60 * 60;
/// Below this a platform proposal is refused at open: one owner would decide alone.
pub const PLATFORM_MIN_ROSTER: usize = 2;
/// Below this a scope proposal escalates to the platform (`sole_admin`), for the same
/// reason.
pub const SCOPE_MIN_ADMINS: usize = 2;
/// What `escalated_by` says when the scope had too few admins to decide.
pub const SOLE_ADMIN: &str = "sole_admin";
/// `ESCALATION_TEST_ROLLING_24H_AMOUNT_ABOVE`'s window.
pub const ROLLING_WINDOW_SECS: i64 = 24 * 60 * 60;
/// How long a passed decision stays executable after its veto delay. Past it the decision
/// lapses to VOID: a stale approval must not be carried out weeks later against a subject
/// that has moved on (decided).
pub const EXECUTION_WINDOW_SECS: i64 = 72 * 60 * 60;
/// At most this many live proposals per proposer namespace and scope: one leaked
/// credential must not be able to bury a scope's deciders.
pub const MAX_LIVE_PER_PROPOSER: i64 = 200;
/// Live decisions about people one owner may have open at once: opening is cheap and each
/// one mails every other owner, so one owner (or one stolen session) must not be able to fill
/// the proposer's whole live cap with them.
pub const MAX_LIVE_PEOPLE_PER_OPENER: i64 = 5;
/// `PullApproved` stops serving a decision this long before it lapses, so whatever a
/// proposer pulled it still has this long to report — a pull at the last second would
/// otherwise hand out work whose report is already too late.
pub const PULL_MARGIN_SECS: i64 = 60 * 60;
/// A scope's veto window is never shorter: an hour is the least an owner gets to see a
/// scope decision and stop it (decided).
pub const MIN_SCOPE_DELAY_SECS: u32 = 60 * 60;
/// Threshold overrides one policy may carry, each a field of its proposal.
pub const MAX_THRESHOLDS: usize = 64;
/// The shortest lifetime a scope policy may give an open proposal.
pub const MIN_SCOPE_TTL_SECS: u32 = 60 * 60;

/// This plane's own namespace: the proposer and executor of the built-in kinds.
pub const OWN_NAMESPACE: &str = "concierge";
pub const SCOPE_ADMIN_GRANT: &str = "concierge:scope_admin_grant";
pub const SCOPE_POLICY_CHANGE: &str = "concierge:scope_policy_change";
pub const PLATFORM_POLICY: &str = "concierge:platform_policy";
/// The decisions about people, moved here from the legacy governance consilia. Each is the
/// platform's, in scope `main`.
pub const OWNER_ADMISSION: &str = "concierge:owner_admission";
pub const OWNER_REMOVAL: &str = "concierge:owner_removal";
pub const USER_SUSPENSION: &str = "concierge:user_suspension";
pub const USER_REINSTATEMENT: &str = "concierge:user_reinstatement";
pub const ADMIN_ADMISSION: &str = "concierge:admin_admission";
/// Remove every second factor of an account whose person lost them and their recovery
/// codes: it re-arms the money plane on the sign-in alone, so it is a judgement about who
/// the person is, and the owners make it.
pub const SECOND_FACTOR_RESET: &str = "concierge:second_factor_reset";
/// The unanimity the owner consilia demand: every owner on the roster, which is what the
/// roster's quorum comes to at 100 %.
pub const UNANIMOUS_QUORUM_BPS: u32 = 10_000;

/// The bar a platform proposal of `kind` is measured by: every owner on the roster for a
/// change of the seats — nobody may grow or shrink the roster that decides everything else
/// by a majority (the reason the legacy consilia were unanimous) — and more than half for
/// the rest, as the user consilia were.
pub fn platform_quorum_bps(kind: &str) -> u32 {
	match kind {
		OWNER_ADMISSION | OWNER_REMOVAL => UNANIMOUS_QUORUM_BPS,
		_ => PLATFORM_QUORUM_BPS,
	}
}

/// How long platform decisions pause after the owner roster changes, until the owners set
/// another (D24(2)): long enough for the owners who were there before to notice a seat
/// that should not have moved, and to act on it before anyone decides with the new roster.
pub const DEFAULT_COOLDOWN_SECS: u32 = 48 * 60 * 60;
/// The longest pause the owners may set: two weeks. Longer would let one decision of theirs
/// freeze every platform decision — payments included — for a quarter.
pub const MAX_COOLDOWN_SECS: u32 = 14 * 24 * 60 * 60;
/// The version of a platform policy nobody has changed yet.
pub const DEFAULT_PLATFORM_POLICY_VERSION: u64 = 1;

/// The platform's approval policy: its roster, quorum and delay are the owners'
/// consilium's; what it sets is the pause after the owners change.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PlatformPolicy {
	pub version: u64,
	pub cooldown_secs: u32,
}

impl Default for PlatformPolicy {
	fn default() -> Self {
		Self {
			version: DEFAULT_PLATFORM_POLICY_VERSION,
			cooldown_secs: DEFAULT_COOLDOWN_SECS,
		}
	}
}

impl PlatformPolicy {
	pub fn check(&self) -> Result<(), String> {
		if self.cooldown_secs > MAX_COOLDOWN_SECS {
			return Err(format!("cooldown_secs is 0..={MAX_COOLDOWN_SECS} (fourteen days)"));
		}
		Ok(())
	}

	/// Whether a platform decision may open at `now`, the owners having last changed at
	/// `roster_changed_at`; `Err` names when they may again.
	pub fn admits(&self, roster_changed_at: i64, now: i64) -> Result<(), i64> {
		let reopens = roster_changed_at.saturating_add(i64::from(self.cooldown_secs));
		if now < reopens { Err(reopens) } else { Ok(()) }
	}
}
/// What `void_reason` says of a decision nobody executed in time.
pub const LAPSED: &str = "not executed within 72 hours of becoming executable";

pub const DEFAULT_SCOPE_QUORUM_BPS: u32 = 5001;
pub const DEFAULT_SCOPE_DELAY_SECS: u32 = 60 * 60;
/// The version of a scope policy nobody has changed yet. Not 0: 0 is what a proposal in
/// scope `main`, which has no policy, records.
pub const DEFAULT_POLICY_VERSION: u64 = 1;

pub const TEXT_FIELD_BYTES: usize = 200;
pub const REASON_BYTES: usize = 500;
pub const SUBJECT_REF_BYTES: usize = 128;
pub const DEDUPE_KEY_BYTES: usize = 128;
const AUTH_SUBJECT_BYTES: usize = 255;
/// Fractional digits an amount may carry; the scale sums are taken at.
const AMOUNT_SCALE: usize = 18;

/// A scope's approval policy. Scope `main` has none: its roster, quorum and delay are the
/// owners' consilium's.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScopePolicy {
	pub version: u64,
	pub quorum_bps: u32,
	pub delay_secs: u32,
	pub ttl_secs: u32,
	pub thresholds: Vec<Threshold>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Threshold {
	pub kind: String,
	pub parameter: String,
	pub value: String,
}

impl Default for ScopePolicy {
	fn default() -> Self {
		Self {
			version: DEFAULT_POLICY_VERSION,
			quorum_bps: DEFAULT_SCOPE_QUORUM_BPS,
			delay_secs: DEFAULT_SCOPE_DELAY_SECS,
			ttl_secs: MAX_TTL_SECS,
			thresholds: Vec::new(),
		}
	}
}

impl ScopePolicy {
	/// A policy a scope may be measured against, given the kinds in force (every
	/// namespace's): a quorum of more than half, a delay of at least an hour, a lifetime
	/// within the ceiling, and each override naming a scope-level kind's escalation once,
	/// spelled as that escalation's threshold is. Checked when it is proposed AND when it is
	/// installed, because the catalogs move in between.
	pub fn check(&self, kinds: &[ApprovalKind]) -> Result<(), String> {
		if !(5001..=10_000).contains(&self.quorum_bps) {
			return Err("quorum_bps is more than half of the roster: 5001..=10000".into());
		}
		if !(MIN_SCOPE_DELAY_SECS..=MAX_TTL_SECS).contains(&self.delay_secs) {
			return Err(format!(
				"delay_secs is {MIN_SCOPE_DELAY_SECS}..={MAX_TTL_SECS}: an owner gets at least an hour to stop a scope's decision"
			));
		}
		if !(MIN_SCOPE_TTL_SECS..=MAX_TTL_SECS).contains(&self.ttl_secs) {
			return Err(format!("ttl_secs is {MIN_SCOPE_TTL_SECS}..={MAX_TTL_SECS}"));
		}
		if self.thresholds.len() > MAX_THRESHOLDS {
			return Err(format!("a policy overrides at most {MAX_THRESHOLDS} thresholds"));
		}
		for (i, t) in self.thresholds.iter().enumerate() {
			if self.thresholds[..i].iter().any(|o| o.kind == t.kind && o.parameter == t.parameter) {
				return Err(format!("threshold `{}`/`{}` is given twice", t.kind, t.parameter));
			}
			// Measured against the kind as a proposal is: floored, so "only tightens" counts
			// from the table's cap where it is stricter than the catalog.
			let escalation = kinds
				.iter()
				.filter(|k| k.name == t.kind)
				.map(crate::floors::floored)
				.filter(|k| k.level == ApprovalLevel::Scope)
				.flat_map(|k| k.escalations)
				.find(|e| e.parameter == t.parameter)
				.ok_or_else(|| format!("threshold `{}`/`{}` names no escalation of a scope-level kind in force", t.kind, t.parameter))?;
			let shaped = match escalation.test {
				EscalationTest::AmountAbove | EscalationTest::Rolling24hAmountAbove => is_canonical_amount(&t.value),
				EscalationTest::AbsBpsAbove | EscalationTest::CountAbove | EscalationTest::Rolling24hCountAbove => t.value.parse::<u64>().is_ok_and(|v| v.to_string() == t.value),
				EscalationTest::FlagSet => false,
			};
			if !shaped {
				return Err(format!("threshold `{}`/`{}` is not a value its test takes", t.kind, t.parameter));
			}
			// A scope may only make a kind's escalation stricter than the kind is measured by
			// (decided): a looser one would let the scope keep for itself what its publisher,
			// or this plane's floor, sends to the owners.
			let looser = match escalation.test {
				EscalationTest::AmountAbove | EscalationTest::Rolling24hAmountAbove => amount_above(&t.value, &escalation.default_threshold),
				EscalationTest::AbsBpsAbove | EscalationTest::CountAbove | EscalationTest::Rolling24hCountAbove =>
					match (t.value.parse::<u64>(), escalation.default_threshold.parse::<u64>()) {
						(Ok(value), Ok(default)) => value > default,
						_ => true,
					},
				EscalationTest::FlagSet => true,
			};
			if looser {
				return Err(format!(
					"threshold `{}`/`{}` is above the kind's own `{}`: a scope may only tighten it",
					t.kind, t.parameter, escalation.default_threshold
				));
			}
		}
		Ok(())
	}

	/// The policy as installed: a threshold on a catalog escalation the floor also covers
	/// (same test, field and currency) is moved onto the floor's parameter, which this plane
	/// keeps whatever the publisher's next catalog says — so the next catalog cannot drop the
	/// scope's tightening by renaming or removing its own escalation (review of #142). Two
	/// thresholds landing on one parameter keep the stricter.
	pub fn anchored(&self, kinds: &[ApprovalKind]) -> ScopePolicy {
		let mut anchored = ScopePolicy {
			thresholds: Vec::new(),
			..self.clone()
		};
		for t in &self.thresholds {
			let kind = kinds.iter().find(|k| k.name == t.kind).map(crate::floors::floored);
			let escalation = kind.as_ref().and_then(|k| k.escalations.iter().find(|e| e.parameter == t.parameter));
			let floor = kind.as_ref().zip(escalation).and_then(|(k, e)| {
				k.escalations
					.iter()
					.find(|f| crate::floors::is_floor_parameter(&f.parameter) && f.test == e.test && f.field_key == e.field_key && f.currency == e.currency)
			});
			let parameter = floor.map_or_else(|| t.parameter.clone(), |f| f.parameter.clone());
			let test = escalation.map(|e| e.test);
			match anchored.thresholds.iter_mut().find(|o| o.kind == t.kind && o.parameter == parameter) {
				Some(existing) =>
					if let Some(stricter) = test.and_then(|test| crate::floors::stricter(test, &existing.value, &t.value)) {
						existing.value = stricter;
					},
				None => anchored.thresholds.push(Threshold {
					kind: t.kind.clone(),
					parameter,
					value: t.value.clone(),
				}),
			}
		}
		anchored
	}
}

/// The kinds this plane proposes and executes itself, at catalog version 0 (§5.3). Both
/// are the platform's: who administers a scope, and what a scope's decisions are measured
/// against, must not be decided by the scope.
pub fn builtin_kinds() -> Vec<ApprovalKind> {
	let field = |key: &str, label: &str, field_type: FieldType| FieldSpec {
		key: key.into(),
		label: label.into(),
		field_type,
		required: true,
		repeated: false,
	};
	vec![
		ApprovalKind {
			name: SCOPE_ADMIN_GRANT.into(),
			label: "Appoint a scope admin".into(),
			description: "Grant the scope's admin alias, which seats its holder on the scope's approval roster.".into(),
			level: ApprovalLevel::Platform,
			fields: vec![field("account", "Account", FieldType::User)],
			escalations: Vec::new(),
		},
		ApprovalKind {
			name: SCOPE_POLICY_CHANGE.into(),
			label: "Change a scope's approval policy".into(),
			description: "Replace the quorum, veto delay, lifetime and escalation thresholds a scope's proposals are measured against.".into(),
			level: ApprovalLevel::Platform,
			fields: vec![
				field("quorum_bps", "Quorum, basis points of the roster", FieldType::Count),
				field("delay_secs", "Veto delay, seconds", FieldType::Count),
				field("ttl_secs", "Lifetime, seconds", FieldType::Count),
				field("thresholds", "Threshold overrides", FieldType::Count),
				// One per override, `<kind>/<parameter>=<value>`: the values the owners
				// approve are fields, so `payload_hash` is taken over them.
				FieldSpec {
					key: "threshold".into(),
					label: "Threshold override".into(),
					field_type: FieldType::Text,
					required: false,
					repeated: true,
				},
			],
			escalations: Vec::new(),
		},
		person_kind(OWNER_ADMISSION, "Admit an owner", "Seat an account as a platform owner. Every other owner must agree.", &field),
		person_kind(
			OWNER_REMOVAL,
			"Remove an owner",
			"Take an owner's seat away. Every other owner besides the target must agree.",
			&field,
		),
		person_kind(USER_SUSPENSION, "Suspend an account", "Freeze an account until the owners lift it.", &field),
		person_kind(USER_REINSTATEMENT, "Reinstate an account", "Lift a suspension the owners imposed.", &field),
		person_kind(ADMIN_ADMISSION, "Appoint an admin", "Grant the admin role to an account.", &field),
		person_kind(
			SECOND_FACTOR_RESET,
			"Reset an account's second factors",
			"Remove every second factor and recovery code of an account whose person lost them, and sign it out everywhere.",
			&field,
		),
		ApprovalKind {
			name: PLATFORM_POLICY.into(),
			label: "Change the platform's approval policy".into(),
			description: "Set how long platform decisions pause after the owner roster changes.".into(),
			level: ApprovalLevel::Platform,
			fields: vec![field("cooldown_secs", "Pause after the owners change, seconds", FieldType::Count)],
			escalations: Vec::new(),
		},
	]
}

fn person_kind(name: &str, label: &str, description: &str, field: &dyn Fn(&str, &str, FieldType) -> FieldSpec) -> ApprovalKind {
	ApprovalKind {
		name: name.into(),
		label: label.into(),
		description: description.into(),
		level: ApprovalLevel::Platform,
		fields: vec![field("account", "Account", FieldType::User), field("reason", "Reason", FieldType::Text)],
		escalations: Vec::new(),
	}
}

/// What a passed `concierge:*` proposal does when this plane's executor carries it out.
/// Stored with the proposal at open, because the executor acts on what was approved and on
/// nothing read later.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
	/// Grant `scope`'s `<namespace>:admin` to `user`, recorded as granted by `granted_by`,
	/// the person who opened the proposal.
	GrantAdmin { user: uuid::Uuid, scope: String, granted_by: uuid::Uuid },
	/// Install `policy` as `scope`'s next version.
	InstallPolicy { scope: String, policy: ScopePolicy },
	/// Install `policy` as the platform's next version.
	InstallPlatformPolicy { policy: PlatformPolicy },
	/// A decision about one person's standing, opened by the owner `opened_by`.
	People { effect: PersonEffect, user: uuid::Uuid, opened_by: uuid::Uuid },
}

impl Action {
	/// The account whose own standing this decision is about, if it is that kind of
	/// decision: it neither votes nor vetoes (nobody judges their own seat).
	pub fn about(&self) -> Option<uuid::Uuid> {
		match self {
			Self::People { user, .. } => Some(*user),
			Self::GrantAdmin { .. } | Self::InstallPolicy { .. } | Self::InstallPlatformPolicy { .. } => None,
		}
	}

	/// The people kept off the roster: whoever opened it over a session, and whoever it
	/// seats or is about.
	pub fn off_roster(&self, opener: uuid::Uuid) -> Vec<uuid::Uuid> {
		match self {
			Self::GrantAdmin { user, .. } | Self::People { user, .. } => vec![opener, *user],
			Self::InstallPolicy { .. } | Self::InstallPlatformPolicy { .. } => vec![opener],
		}
	}
}

/// What an executed decision about a person writes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonEffect {
	/// `Role::Owner`. Written by nothing else but genesis.
	AdmitOwner,
	/// Back to `investor`, as an expulsion always was.
	RemoveOwner,
	/// `suspended_by = governance`: the owners' verdict, no expiry.
	Suspend,
	/// Lift such a verdict.
	Reinstate,
	AdmitAdmin,
	/// Every second factor and recovery code gone, every session ended.
	ResetSecondFactor,
}

impl PersonEffect {
	pub fn kind(self) -> &'static str {
		match self {
			Self::AdmitOwner => OWNER_ADMISSION,
			Self::RemoveOwner => OWNER_REMOVAL,
			Self::Suspend => USER_SUSPENSION,
			Self::Reinstate => USER_REINSTATEMENT,
			Self::AdmitAdmin => ADMIN_ADMISSION,
			Self::ResetSecondFactor => SECOND_FACTOR_RESET,
		}
	}

	/// The `admin_action` verb its execution records.
	pub fn audit_verb(self) -> &'static str {
		match self {
			Self::AdmitOwner => "owner_admitted_by_approval",
			Self::RemoveOwner => "owner_removed_by_approval",
			Self::Suspend => "suspended_by_approval",
			Self::Reinstate => "reinstated_by_approval",
			Self::AdmitAdmin => "admin_granted_by_approval",
			Self::ResetSecondFactor => "second_factor_reset_by_approval",
		}
	}

	/// The RPC a refusal names.
	pub fn rpc(self) -> &'static str {
		match self {
			Self::AdmitOwner => "ApprovalService.ProposeOwnerAdmission",
			Self::RemoveOwner => "ApprovalService.ProposeOwnerRemoval",
			Self::Suspend => "ApprovalService.ProposeUserSuspension",
			Self::Reinstate => "ApprovalService.ProposeUserReinstatement",
			Self::AdmitAdmin => "ApprovalService.ProposeAdminAdmission",
			Self::ResetSecondFactor => "ApprovalService.ProposeSecondFactorReset",
		}
	}

	/// Whether the decision changes who the platform owners are, and so how many must
	/// remain: it is held to the floor.
	pub fn is_removal(self) -> bool {
		self == Self::RemoveOwner
	}
}

/// What a decision about a person is measured against, read under the lock that makes it
/// current: at open to refuse what cannot be done, at execution to void what no longer can.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersonStanding {
	pub role: crate::authz::Role,
	pub active: bool,
	pub verified: bool,
	/// Suspended by the owners' verdict (not by one admin's hold).
	pub governance_suspended: bool,
	/// Holds a confirmed second factor.
	pub second_factor: bool,
}

/// Why `effect` cannot be carried out against `subject` as they stand, if it cannot.
/// `owners` is the number of STANDING owner seats, `subject`'s included if it stands: the
/// floor is over seats that can still decide. An owner suspended by the owners' verdict has
/// no say and is not counted, or two suspensions and a resignation would leave one voice; a
/// temporary hold (`admin_hold`) is counted, because it lapses and is one operator's brake.
pub fn person_inapplicable(effect: PersonEffect, subject: PersonStanding, owners: usize) -> Option<&'static str> {
	use crate::authz::Role;
	match effect {
		PersonEffect::AdmitOwner =>
			if subject.role == Role::Owner {
				Some("the account already holds an owner seat")
			} else if !subject.active {
				Some("the account is no longer active")
			} else if !subject.verified {
				Some("the account's address is not verified")
			} else {
				None
			},
		PersonEffect::RemoveOwner =>
			if subject.role != Role::Owner {
				Some("the account no longer holds an owner seat")
			} else if crate::governance::check_floor(owners).is_err() {
				Some("the platform would be left below the owner floor")
			} else {
				None
			},
		PersonEffect::Suspend =>
			if subject.governance_suspended {
				Some("the account is already suspended by the owners")
			} else {
				None
			},
		PersonEffect::Reinstate =>
			if subject.governance_suspended {
				None
			} else {
				// Nothing left to lift, or a hold one admin could lift anyway: either way the
				// owners' verdict would not be what freed this account.
				Some("the account is no longer suspended by the owners")
			},
		PersonEffect::ResetSecondFactor =>
			if subject.second_factor {
				None
			} else {
				Some("the account holds no second factor")
			},
		PersonEffect::AdmitAdmin => match subject.role {
			// Writing `admin` over `owner` would be an expulsion with no removal decision,
			// no floor check and no audit of the seat.
			Role::Owner => Some("the account holds an owner seat, which outranks admin"),
			Role::Admin => Some("the account already holds the admin role"),
			// Parity with an owner admission: an admin is reached by mail and acts with a
			// session, so the account must be live and its address proven.
			Role::Investor | Role::Operator =>
				if !subject.active {
					Some("the account is no longer active")
				} else if !subject.verified {
					Some("the account's address is not verified")
				} else {
					None
				},
		},
	}
}

/// The fields a policy change shows its voters, every override with its value among them.
pub fn policy_fields(policy: &ScopePolicy) -> Vec<Field> {
	let count = |key: &str, value: u64| Field {
		key: key.into(),
		value: FieldValue::Count(value),
	};
	let mut fields = vec![
		count("quorum_bps", u64::from(policy.quorum_bps)),
		count("delay_secs", u64::from(policy.delay_secs)),
		count("ttl_secs", u64::from(policy.ttl_secs)),
		count("thresholds", u64::try_from(policy.thresholds.len()).unwrap_or(u64::MAX)),
	];
	fields.extend(policy.thresholds.iter().map(|t| Field {
		key: "threshold".into(),
		value: FieldValue::Text(format!("{}/{}={}", t.kind, t.parameter, t.value)),
	}));
	fields
}

/// Money as the proposer spells it. The spelling is canonical (checked at open), because
/// `payload_hash` is taken over it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Amount {
	pub value: String,
	pub currency: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum FieldValue {
	Text(String),
	Amount(Amount),
	Bps(i64),
	Flag(bool),
	/// An `auth_subject`.
	User(String),
	Timestamp(i64),
	Count(u64),
}

impl FieldValue {
	pub fn field_type(&self) -> FieldType {
		match self {
			Self::Text(_) => FieldType::Text,
			Self::Amount(_) => FieldType::Amount,
			Self::Bps(_) => FieldType::Bps,
			Self::Flag(_) => FieldType::Flag,
			Self::User(_) => FieldType::User,
			Self::Timestamp(_) => FieldType::Timestamp,
			Self::Count(_) => FieldType::Count,
		}
	}
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Field {
	pub key: String,
	pub value: FieldValue,
}

/// `<type>:<uuid>` — `type` `[a-z][a-z0-9_]{0,31}`, a lowercase hyphenated UUID, at most
/// 128 bytes: the rule banking's scope/v1 enforces, so both planes refuse the same refs.
pub fn check_subject_ref(raw: &str) -> Result<(), String> {
	let shaped = raw.len() <= SUBJECT_REF_BYTES
		&& raw.split_once(':').is_some_and(|(kind, id)| {
			let mut bytes = kind.bytes();
			kind.len() <= 32 && bytes.next().is_some_and(|b| b.is_ascii_lowercase()) && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') && is_lower_uuid(id)
		});
	if shaped {
		Ok(())
	} else {
		Err(format!("subject_ref is not `<type>:<uuid>` of at most {SUBJECT_REF_BYTES} bytes"))
	}
}

fn is_lower_uuid(raw: &str) -> bool {
	let groups: Vec<&str> = raw.split('-').collect();
	groups.len() == 5
		&& groups
			.iter()
			.zip([8, 4, 4, 4, 12])
			.all(|(g, len)| g.len() == len && g.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// A reason, a veto reason, an outcome detail or a TEXT field: rendered as somebody
/// else's words, so one line, bounded, no control character and no link.
pub fn check_text(what: &str, text: &str, max_bytes: usize) -> Result<(), String> {
	plain_text(text, max_bytes, false).map_err(|why| format!("{what} {why} (at most {max_bytes} bytes, one line, no link)"))
}

/// An account's `auth_subject` as another plane names it: opaque, so only bounded here;
/// whether it names an account is the adapter's question.
pub fn check_auth_subject(what: &str, raw: &str) -> Result<(), String> {
	if raw.is_empty() || raw.len() > AUTH_SUBJECT_BYTES || raw.chars().any(char::is_control) {
		return Err(format!("{what} is not an auth_subject"));
	}
	Ok(())
}

pub fn check_dedupe_key(raw: &str) -> Result<(), String> {
	if raw.is_empty() || raw.len() > DEDUPE_KEY_BYTES || raw.chars().any(char::is_control) {
		return Err(format!("dedupe_key is required: 1 to {DEDUPE_KEY_BYTES} bytes, no control character"));
	}
	Ok(())
}

/// The fields exactly as `kind` declares them, returned in the kind's display order: every
/// key declared, at most once, of its declared type, every required one present, every
/// value one this plane can render as it stands.
pub fn check_fields(kind: &ApprovalKind, fields: Vec<Field>) -> Result<Vec<Field>, String> {
	for (i, field) in fields.iter().enumerate() {
		let Some(spec) = kind.fields.iter().find(|s| s.key == field.key) else {
			return Err(format!("field `{}` is not declared by `{}`", field.key, kind.name));
		};
		if !spec.repeated && fields[..i].iter().any(|f| f.key == field.key) {
			return Err(format!("field `{}` is given twice", field.key));
		}
		if spec.field_type != field.value.field_type() {
			return Err(format!("field `{}` is not of its declared type", field.key));
		}
		match &field.value {
			FieldValue::Text(text) => check_text(&format!("field `{}`", field.key), text, TEXT_FIELD_BYTES)?,
			FieldValue::Amount(amount) =>
				if !is_canonical_amount(&amount.value) || !is_currency(&amount.currency) {
					return Err(format!("field `{}` is not a canonical amount and currency", field.key));
				},
			FieldValue::User(subject) => check_auth_subject(&format!("field `{}`", field.key), subject)?,
			FieldValue::Bps(_) | FieldValue::Flag(_) | FieldValue::Timestamp(_) | FieldValue::Count(_) => {}
		}
	}
	if let Some(missing) = kind.fields.iter().find(|s| s.required && !fields.iter().any(|f| f.key == s.key)) {
		return Err(format!("required field `{}` is missing", missing.key));
	}
	let mut ordered = fields;
	ordered.sort_by_key(|f| kind.fields.iter().position(|s| s.key == f.key));
	Ok(ordered)
}

/// The bytes `payload_hash` is SHA-256 over (§5.4). The hash itself is taken by the host:
/// this crate carries no digest dependency.
pub fn payload_preimage(kind: &str, scope: &str, subject_ref: &str, fields: &[Field]) -> String {
	let mut lines: Vec<String> = fields
		.iter()
		.map(|f| {
			let (tag, value) = match &f.value {
				FieldValue::Text(text) => ("TEXT", text.clone()),
				FieldValue::Amount(a) => ("AMOUNT", format!("{} {}", a.value, a.currency)),
				FieldValue::Bps(v) => ("BPS", v.to_string()),
				FieldValue::Flag(v) => ("FLAG", v.to_string()),
				FieldValue::User(subject) => ("USER", subject.clone()),
				FieldValue::Timestamp(v) => ("TIMESTAMP", v.to_string()),
				FieldValue::Count(v) => ("COUNT", v.to_string()),
			};
			format!("{}\t{tag}\t{value}\n", f.key)
		})
		.collect();
	lines.sort();
	format!("ev-approval-v1\n{kind}\n{scope}\n{subject_ref}\n{}", lines.concat())
}

/// A canonical amount as base-10 digits at [`AMOUNT_SCALE`], most significant first,
/// without leading zeros. Amounts are unbounded decimal strings on the wire, so they are
/// summed and compared as digits rather than squeezed into a machine integer.
fn scaled_digits(raw: &str) -> Vec<u8> {
	let (whole, fraction) = raw.split_once('.').unwrap_or((raw, ""));
	let mut digits: Vec<u8> = whole.bytes().chain(fraction.bytes()).map(|b| b - b'0').collect();
	digits.extend(std::iter::repeat_n(0, AMOUNT_SCALE - fraction.len()));
	let first = digits.iter().position(|&d| d != 0).unwrap_or(digits.len());
	digits.split_off(first)
}

fn compare_digits(a: &[u8], b: &[u8]) -> Ordering {
	a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn add_digits(a: &[u8], b: &[u8]) -> Vec<u8> {
	let mut sum = Vec::with_capacity(a.len().max(b.len()) + 1);
	let (mut i, mut j, mut carry) = (a.len(), b.len(), 0u8);
	while i > 0 || j > 0 || carry > 0 {
		let mut digit = carry;
		if i > 0 {
			i -= 1;
			digit += a[i];
		}
		if j > 0 {
			j -= 1;
			digit += b[j];
		}
		sum.push(digit % 10);
		carry = digit / 10;
	}
	sum.reverse();
	sum
}

/// `a > b` for two canonical amounts.
pub fn amount_above(a: &str, b: &str) -> bool {
	compare_digits(&scaled_digits(a), &scaled_digits(b)) == Ordering::Greater
}

/// The canonical spelling of `a + b`.
pub fn amount_sum(a: &str, b: &str) -> String {
	let digits = add_digits(&scaled_digits(a), &scaled_digits(b));
	let split = digits.len().saturating_sub(AMOUNT_SCALE);
	let whole: String = digits[..split].iter().map(|d| char::from(b'0' + d)).collect();
	let mut fraction: String = std::iter::repeat_n('0', AMOUNT_SCALE - (digits.len() - split))
		.chain(digits[split..].iter().map(|d| char::from(b'0' + d)))
		.collect();
	while fraction.ends_with('0') {
		fraction.pop();
	}
	let whole = if whole.is_empty() { "0".to_owned() } else { whole };
	if fraction.is_empty() { whole } else { format!("{whole}.{fraction}") }
}

/// The escalation parameters of `kind` that fire for these fields under `policy`.
/// `window` holds the fields of every scope-level proposal of the same kind and scope that
/// is LIVE (open, or passed and not lapsed) whenever it was opened, or was EXECUTED in the
/// trailing [`ROLLING_WINDOW_SECS`] (§5.2, decided). Counting only executed ones would let a
/// batch opened together each pass under the limit and then execute together above it;
/// counting by the opening instant would drop a live proposal from the window a day after
/// it was opened, and an execution a day after its proposal rather than after the money moved.
pub fn fired_escalations(kind: &ApprovalKind, fields: &[Field], policy: &ScopePolicy, window: &[Vec<Field>]) -> Vec<String> {
	let value_of = |fields: &[Field], key: &str| fields.iter().find(|f| f.key == key).map(|f| f.value.clone());
	// A policy threshold binds by WHAT it tests, not by name: every escalation of the same
	// test, field and currency as the one it names is held to it. Never looser than the
	// default the kind is measured by — a policy installed before the floor may hold an
	// override above it.
	let held_to = |e: &Escalation| -> Option<String> {
		policy
			.thresholds
			.iter()
			.filter(|t| t.kind == kind.name)
			.filter(|t| {
				kind.escalations
					.iter()
					.any(|named| named.parameter == t.parameter && named.test == e.test && named.field_key == e.field_key && named.currency == e.currency)
			})
			.try_fold(e.default_threshold.clone(), |held, t| crate::floors::stricter(e.test, &held, &t.value))
	};
	let mut fired: Vec<String> = kind
		.escalations
		.iter()
		.filter(|e| {
			let Some(threshold) = held_to(e) else {
				return true;
			};
			let threshold = threshold.as_str();
			let value = value_of(fields, &e.field_key);
			// A field that cannot be compared — absent, of another type, in another currency —
			// escalates: what this plane cannot measure goes to the owners (fail safe). Only
			// an unset FLAG stays down, because absent is what "not set" looks like. Matched
			// per test so a new test is a compile error rather than an escalation that
			// silently never fires.
			match e.test {
				EscalationTest::AmountAbove => !matches!(value, Some(FieldValue::Amount(a)) if a.currency == e.currency && !amount_above(&a.value, threshold)),
				EscalationTest::Rolling24hAmountAbove => {
					let Some(FieldValue::Amount(a)) = value else { return true };
					if a.currency != e.currency {
						return true;
					}
					let total = window
						.iter()
						.filter_map(|prior| match value_of(prior, &e.field_key) {
							Some(FieldValue::Amount(p)) if p.currency == e.currency => Some(p.value),
							_ => None,
						})
						.fold(a.value, |sum, v| amount_sum(&sum, &v));
					amount_above(&total, threshold)
				}
				EscalationTest::AbsBpsAbove => !matches!(value, Some(FieldValue::Bps(bps)) if threshold.parse::<u64>().is_ok_and(|limit| bps.unsigned_abs() <= limit)),
				EscalationTest::FlagSet => matches!(value, Some(FieldValue::Flag(true))),
				EscalationTest::CountAbove => !matches!(value, Some(FieldValue::Count(n)) if threshold.parse::<u64>().is_ok_and(|limit| n <= limit)),
				EscalationTest::Rolling24hCountAbove => {
					let Some(FieldValue::Count(n)) = value else { return true };
					let total = window
						.iter()
						.filter_map(|prior| match value_of(prior, &e.field_key) {
							Some(FieldValue::Count(p)) => Some(p),
							_ => None,
						})
						.fold(n, u64::saturating_add);
					threshold.parse::<u64>().map_or(true, |limit| total > limit)
				}
			}
		})
		.map(|e| e.parameter.clone())
		.collect();
	fired.extend(crate::floors::special_fired(&kind.name, fields));
	fired
}

/// Who decides a proposal, frozen at open.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resolution {
	pub level: ApprovalLevel,
	pub escalated_by: Vec<String>,
}

/// `in_root` — the proposal is in scope `main`, which has no admins and is always the
/// platform's. `fired` from [`fired_escalations`]; `scope_admins` the size of the scope's
/// roster.
pub fn resolve_level(kind_level: ApprovalLevel, in_root: bool, fired: Vec<String>, scope_admins: usize) -> Resolution {
	match kind_level {
		ApprovalLevel::Platform => Resolution {
			level: ApprovalLevel::Platform,
			escalated_by: Vec::new(),
		},
		ApprovalLevel::Scope if in_root => Resolution {
			level: ApprovalLevel::Platform,
			escalated_by: Vec::new(),
		},
		ApprovalLevel::Scope => {
			let mut escalated_by = fired;
			if scope_admins < SCOPE_MIN_ADMINS {
				escalated_by.push(SOLE_ADMIN.to_owned());
			}
			Resolution {
				level: if escalated_by.is_empty() { ApprovalLevel::Scope } else { ApprovalLevel::Platform },
				escalated_by,
			}
		}
	}
}

/// `max(1, ceil(roster × quorum_bps / 10000))`.
pub fn threshold(roster: usize, quorum_bps: u32) -> u32 {
	let roster = u64::try_from(roster).unwrap_or(u64::MAX);
	let needed = (roster * u64::from(quorum_bps)).div_ceil(10_000).max(1);
	u32::try_from(needed).unwrap_or(u32::MAX)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalState {
	Open,
	Passed,
	Executed,
	ExecutionFailed,
	Rejected,
	Vetoed,
	Expired,
	Cancelled,
	Void,
}

impl ApprovalState {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Open => "open",
			Self::Passed => "passed",
			Self::Executed => "executed",
			Self::ExecutionFailed => "execution_failed",
			Self::Rejected => "rejected",
			Self::Vetoed => "vetoed",
			Self::Expired => "expired",
			Self::Cancelled => "cancelled",
			Self::Void => "void",
		}
	}

	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		Ok(match raw {
			"open" => Self::Open,
			"passed" => Self::Passed,
			"executed" => Self::Executed,
			"execution_failed" => Self::ExecutionFailed,
			"rejected" => Self::Rejected,
			"vetoed" => Self::Vetoed,
			"expired" => Self::Expired,
			"cancelled" => Self::Cancelled,
			"void" => Self::Void,
			other => return Err(DomainError::Repository(format!("unknown approval state `{other}`"))),
		})
	}

	/// Holds its subject: at most one live proposal per kind, scope and subject.
	pub fn is_live(self) -> bool {
		match self {
			Self::Open | Self::Passed => true,
			Self::Executed | Self::ExecutionFailed | Self::Rejected | Self::Vetoed | Self::Expired | Self::Cancelled | Self::Void => false,
		}
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Vote {
	Pending,
	For,
	Against,
}

impl Vote {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Pending => "pending",
			Self::For => "for",
			Self::Against => "against",
		}
	}

	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		Ok(match raw {
			"pending" => Self::Pending,
			"for" => Self::For,
			"against" => Self::Against,
			other => return Err(DomainError::Repository(format!("unknown approval vote `{other}`"))),
		})
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
	Executed,
	Failed,
	Void,
}

impl Outcome {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Executed => "executed",
			Self::Failed => "failed",
			Self::Void => "void",
		}
	}

	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		Ok(match raw {
			"executed" => Self::Executed,
			"failed" => Self::Failed,
			"void" => Self::Void,
			other => return Err(DomainError::Repository(format!("unknown approval outcome `{other}`"))),
		})
	}

	fn state(self) -> ApprovalState {
		match self {
			Self::Executed => ApprovalState::Executed,
			Self::Failed => ApprovalState::ExecutionFailed,
			Self::Void => ApprovalState::Void,
		}
	}
}

/// What the audit log records about a proposal, one row per transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalEvent {
	Opened,
	Voted,
	Passed,
	Rejected,
	Vetoed,
	Expired,
	Withdrawn,
	Executed,
	ExecutionFailed,
	Voided,
	/// Passed and never executed within its execution window.
	Lapsed,
}

impl ApprovalEvent {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Opened => "opened",
			Self::Voted => "voted",
			Self::Passed => "passed",
			Self::Rejected => "rejected",
			Self::Vetoed => "vetoed",
			Self::Expired => "expired",
			Self::Withdrawn => "withdrawn",
			Self::Executed => "executed",
			Self::ExecutionFailed => "execution_failed",
			Self::Voided => "voided",
			Self::Lapsed => "lapsed",
		}
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Voter {
	pub user_id: UserId,
	pub vote: Vote,
	pub voted_at: i64,
}

/// The decision part of a proposal — everything a transition moves. What the proposal is
/// ABOUT (kind, scope, subject, fields) never changes after open and is not carried here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decision {
	pub state: ApprovalState,
	pub threshold: u32,
	pub voters: Vec<Voter>,
	pub delay_secs: i64,
	pub expires_at: i64,
	pub passed_at: Option<i64>,
	pub executable_at: Option<i64>,
	pub decided_at: Option<i64>,
	pub vetoed_by: Option<UserId>,
	pub veto_reason: String,
	pub void_reason: String,
	pub outcome: Option<Outcome>,
	pub outcome_detail: String,
	pub version: u64,
	/// Transitions not yet written to the audit log.
	pub pending: Vec<ApprovalEvent>,
}

/// What a repeated report did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reported {
	Applied,
	/// The same outcome was reported before: nothing moved.
	Repeated,
}

impl Decision {
	pub fn open(roster: &[UserId], threshold: u32, delay_secs: i64, expires_at: i64) -> Self {
		Self {
			state: ApprovalState::Open,
			threshold,
			voters: roster
				.iter()
				.map(|&user_id| Voter {
					user_id,
					vote: Vote::Pending,
					voted_at: 0,
				})
				.collect(),
			delay_secs,
			expires_at,
			passed_at: None,
			executable_at: None,
			decided_at: None,
			vetoed_by: None,
			veto_reason: String::new(),
			void_reason: String::new(),
			outcome: None,
			outcome_detail: String::new(),
			version: 0,
			pending: vec![ApprovalEvent::Opened],
		}
	}

	/// When a passed decision lapses unexecuted.
	pub fn execute_by(&self) -> Option<i64> {
		self.executable_at.map(|at| at.saturating_add(EXECUTION_WINDOW_SECS))
	}

	/// The state a reader sees: an open proposal past its deadline reads as expired, and a
	/// passed one past its execution window as void, before anything has written so.
	pub fn effective_state(&self, now: i64) -> ApprovalState {
		match self.state {
			ApprovalState::Open if now >= self.expires_at => ApprovalState::Expired,
			ApprovalState::Passed if self.execute_by().is_some_and(|by| now >= by) => ApprovalState::Void,
			state => state,
		}
	}

	/// When the effective state was reached: the stored instant, else the deadline a lazy
	/// transition is projected from.
	pub fn effective_decided_at(&self, now: i64) -> Option<i64> {
		match (self.effective_state(now), self.decided_at) {
			(_, Some(at)) => Some(at),
			(ApprovalState::Expired, None) => Some(self.expires_at),
			(ApprovalState::Void, None) => self.execute_by(),
			(_, None) => None,
		}
	}

	/// Passed, its veto window behind the clock and its execution window not, no outcome
	/// yet: what `ReportOutcome` accepts.
	pub fn is_executable(&self, now: i64) -> bool {
		self.effective_state(now) == ApprovalState::Passed && self.executable_at.is_some_and(|at| now >= at)
	}

	/// Executable with at least [`PULL_MARGIN_SECS`] left to report: what `PullApproved`
	/// serves and what this plane's own executor starts.
	pub fn is_pullable(&self, now: i64) -> bool {
		self.is_executable(now) && self.execute_by().is_some_and(|by| now < by - PULL_MARGIN_SECS)
	}

	/// Inside the window where a veto or a withdrawal still stops it.
	fn stoppable(&self, now: i64) -> bool {
		match self.state {
			ApprovalState::Open => true,
			ApprovalState::Passed => self.executable_at.is_some_and(|at| now < at),
			ApprovalState::Executed
			| ApprovalState::ExecutionFailed
			| ApprovalState::Rejected
			| ApprovalState::Vetoed
			| ApprovalState::Expired
			| ApprovalState::Cancelled
			| ApprovalState::Void => false,
		}
	}

	fn transition(&mut self, event: ApprovalEvent) {
		self.version += 1;
		self.pending.push(event);
	}

	fn close(&mut self, state: ApprovalState, event: ApprovalEvent, now: i64) {
		self.state = state;
		self.decided_at = Some(now);
		self.transition(event);
	}

	/// Writes the lazy expiry or lapse, dated at the deadline it passed. True when it moved.
	pub fn expire_if_due(&mut self, now: i64) -> bool {
		let Some(at) = self.effective_decided_at(now) else { return false };
		match (self.state, self.effective_state(now)) {
			(ApprovalState::Open, ApprovalState::Expired) => self.close(ApprovalState::Expired, ApprovalEvent::Expired, at),
			(ApprovalState::Passed, ApprovalState::Void) => {
				self.void_reason = LAPSED.to_owned();
				self.close(ApprovalState::Void, ApprovalEvent::Lapsed, at);
			}
			_ => return false,
		}
		true
	}

	pub fn is_voter(&self, user: UserId) -> bool {
		self.voters.iter().any(|v| v.user_id == user)
	}

	/// A roster member's vote. Final: the same vote again is a no-op, the other one is
	/// refused. Call [`Self::expire_if_due`] first. `unseated` are roster members who no
	/// longer hold the seat the roster was drawn from: their FOR is not counted (decided) —
	/// a vote is the seat's, so removing an admin takes back what they carried, and the
	/// threshold stays where it was frozen.
	pub fn vote(&mut self, voter: UserId, vote: Vote, now: i64, unseated: &[UserId]) -> Result<(), DomainError> {
		if vote == Vote::Pending {
			return Err(DomainError::Validation("a vote is FOR or AGAINST".into()));
		}
		let Some(index) = self.voters.iter().position(|v| v.user_id == voter) else {
			return Err(DomainError::Forbidden("you are not on this proposal's roster".into()));
		};
		let cast = self.voters[index].vote;
		if cast == vote {
			return Ok(());
		}
		if self.state != ApprovalState::Open {
			return Err(DomainError::Precondition(format!("the proposal is {}, not open", self.state.as_str())));
		}
		if cast != Vote::Pending {
			return Err(DomainError::Precondition("a vote is final".into()));
		}
		self.voters[index].vote = vote;
		self.voters[index].voted_at = now;
		self.transition(ApprovalEvent::Voted);
		let seated = || self.voters.iter().filter(|x| !unseated.contains(&x.user_id));
		let fors = seated().filter(|x| x.vote == Vote::For).count();
		// Rejected only by seated AGAINSTs, more than the roster could spare (review of
		// #140): a seat lost is not a vote against, so what can no longer be carried for
		// want of seats waits out its lifetime rather than being decided by a removal.
		let againsts = seated().filter(|x| x.vote == Vote::Against).count();
		let threshold = usize::try_from(self.threshold).unwrap_or(usize::MAX);
		if fors >= threshold {
			self.state = ApprovalState::Passed;
			self.passed_at = Some(now);
			self.executable_at = Some(now.saturating_add(self.delay_secs));
			self.transition(ApprovalEvent::Passed);
		} else if againsts > self.voters.len().saturating_sub(threshold) {
			self.close(ApprovalState::Rejected, ApprovalEvent::Rejected, now);
		}
		Ok(())
	}

	/// One roster member stops it outright, while open or inside the delay — and so does
	/// any platform owner, on any proposal: containment is never slower than the grant
	/// (decided).
	pub fn veto(&mut self, by: UserId, owner: bool, reason: &str, now: i64) -> Result<(), DomainError> {
		if !owner && !self.is_voter(by) {
			return Err(DomainError::Forbidden("you are not on this proposal's roster".into()));
		}
		if !self.stoppable(now) {
			return Err(DomainError::Precondition(format!(
				"the proposal is {} and can no longer be vetoed",
				self.effective_state(now).as_str()
			)));
		}
		self.vetoed_by = Some(by);
		self.veto_reason = reason.to_owned();
		self.close(ApprovalState::Vetoed, ApprovalEvent::Vetoed, now);
		Ok(())
	}

	/// The proposer takes it back, in the same window as a veto.
	pub fn withdraw(&mut self, now: i64) -> Result<(), DomainError> {
		if !self.stoppable(now) {
			return Err(DomainError::Precondition(format!(
				"the proposal is {} and can no longer be withdrawn",
				self.effective_state(now).as_str()
			)));
		}
		self.close(ApprovalState::Cancelled, ApprovalEvent::Withdrawn, now);
		Ok(())
	}

	/// The proposer's report. The same outcome again is [`Reported::Repeated`], whatever
	/// its detail: the proposer retries a report it did not see acknowledged, and must be
	/// told it landed rather than refused.
	pub fn report(&mut self, outcome: Outcome, detail: &str, now: i64) -> Result<Reported, DomainError> {
		if let Some(reported) = self.outcome {
			return if reported == outcome {
				Ok(Reported::Repeated)
			} else {
				Err(DomainError::Precondition(format!("the outcome was already reported as {}", reported.as_str())))
			};
		}
		if !self.is_executable(now) {
			return Err(DomainError::Precondition(format!("the proposal is {} and not executable", self.effective_state(now).as_str())));
		}
		self.outcome = Some(outcome);
		self.outcome_detail = detail.to_owned();
		let event = match outcome {
			Outcome::Executed => ApprovalEvent::Executed,
			Outcome::Failed => ApprovalEvent::ExecutionFailed,
			Outcome::Void => {
				self.void_reason = detail.to_owned();
				ApprovalEvent::Voided
			}
		};
		self.close(outcome.state(), event, now);
		Ok(Reported::Applied)
	}
}

#[cfg(test)]
mod tests {
	use uuid::Uuid;

	use super::*;

	fn uid() -> UserId {
		UserId::from_raw(Uuid::new_v4())
	}

	fn transfer_kind() -> ApprovalKind {
		ApprovalKind {
			name: "bank:account_transfer".into(),
			label: "Transfer".into(),
			description: String::new(),
			level: ApprovalLevel::Scope,
			fields: vec![
				FieldSpec {
					key: "to_account".into(),
					label: "To".into(),
					field_type: FieldType::Text,
					required: true,
					repeated: false,
				},
				FieldSpec {
					key: "amount".into(),
					label: "Amount".into(),
					field_type: FieldType::Amount,
					required: true,
					repeated: false,
				},
				FieldSpec {
					key: "distribution".into(),
					label: "To every holder".into(),
					field_type: FieldType::Flag,
					required: false,
					repeated: false,
				},
			],
			escalations: vec![
				Escalation {
					parameter: "per_operation".into(),
					field_key: "amount".into(),
					test: EscalationTest::AmountAbove,
					default_threshold: "1000".into(),
					currency: "USDT".into(),
				},
				Escalation {
					parameter: "daily".into(),
					field_key: "amount".into(),
					test: EscalationTest::Rolling24hAmountAbove,
					default_threshold: "5000".into(),
					currency: "USDT".into(),
				},
				Escalation {
					parameter: "distribution".into(),
					field_key: "distribution".into(),
					test: EscalationTest::FlagSet,
					default_threshold: String::new(),
					currency: String::new(),
				},
			],
		}
	}

	fn amount(value: &str, currency: &str) -> Field {
		Field {
			key: "amount".into(),
			value: FieldValue::Amount(Amount {
				value: value.into(),
				currency: currency.into(),
			}),
		}
	}

	fn text(key: &str, value: &str) -> Field {
		Field {
			key: key.into(),
			value: FieldValue::Text(value.into()),
		}
	}

	#[test]
	fn decimals_sum_and_compare_as_digits() {
		assert_eq!(amount_sum("0.1", "0.2"), "0.3");
		assert_eq!(amount_sum("999.999999999999999999", "0.000000000000000001"), "1000");
		assert_eq!(amount_sum("0", "0"), "0");
		assert_eq!(amount_sum("123456789012345678901234567890", "1"), "123456789012345678901234567891");
		assert!(amount_above("1000.5", "1000"));
		assert!(!amount_above("1000", "1000"));
		assert!(!amount_above("999.99", "1000"));
		assert!(amount_above("10000", "9999.999"));
	}

	#[test]
	fn subject_refs_are_type_colon_lowercase_uuid() {
		assert!(check_subject_ref("payment:4f0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b").is_ok());
		for bad in [
			"payment:4F0C1A2B-3C4D-4E5F-8A9B-0C1D2E3F4A5B",
			"Payment:4f0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b",
			"payment-4f0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b",
			"payment:4f0c1a2b3c4d4e5f8a9b0c1d2e3f4a5b",
			":4f0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b",
			"",
		] {
			assert!(check_subject_ref(bad).is_err(), "{bad}");
		}
	}

	#[test]
	fn fields_are_checked_against_the_kind_and_ordered_by_it() {
		let kind = transfer_kind();
		let ordered = check_fields(&kind, vec![amount("10", "USDT"), text("to_account", "ops")]).unwrap();
		assert_eq!(ordered[0].key, "to_account");
		assert!(check_fields(&kind, vec![amount("10", "USDT")]).is_err(), "a required field is missing");
		assert!(check_fields(&kind, vec![text("to_account", "ops"), amount("10.50", "USDT")]).is_err(), "not canonical");
		assert!(check_fields(&kind, vec![text("to_account", "see www.evil.example"), amount("1", "USDT")]).is_err(), "a link");
		assert!(check_fields(&kind, vec![text("to_account", "a\tb"), amount("1", "USDT")]).is_err(), "a tab");
		assert!(
			check_fields(&kind, vec![text("to_account", "ops"), amount("1", "USDT"), text("nope", "x")]).is_err(),
			"undeclared"
		);
		assert!(check_fields(&kind, vec![text("to_account", "ops"), text("amount", "1")]).is_err(), "wrong type");
		assert!(
			check_fields(&kind, vec![text("to_account", "ops"), text("to_account", "x"), amount("1", "USDT")]).is_err(),
			"twice"
		);
	}

	#[test]
	fn the_preimage_sorts_fields_by_key() {
		let fields = vec![text("to_account", "ops"), amount("1200.5", "USDT")];
		assert_eq!(
			payload_preimage("bank:account_transfer", "sa", "payment:4f0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b", &fields),
			"ev-approval-v1\nbank:account_transfer\nsa\npayment:4f0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b\namount\tAMOUNT\t1200.5 USDT\nto_account\tTEXT\tops\n"
		);
	}

	#[test]
	fn escalation_by_amount_currency_window_and_flag() {
		let kind = transfer_kind();
		let policy = ScopePolicy::default();
		let fire = |fields: Vec<Field>, window: &[Vec<Field>]| fired_escalations(&kind, &fields, &policy, window);
		assert!(fire(vec![amount("1000", "USDT")], &[]).is_empty(), "at the threshold is not above it");
		assert_eq!(fire(vec![], &[]), vec!["per_operation", "daily"], "an amount it cannot measure goes to the owners");
		assert_eq!(fire(vec![amount("1000.1", "USDT")], &[]), vec!["per_operation"]);
		assert_eq!(fire(vec![amount("1", "USDC")], &[]), vec!["per_operation", "daily"], "another currency escalates");
		let window = vec![vec![amount("1000", "USDT")]; 4];
		assert!(fire(vec![amount("1000", "USDT")], &window).is_empty(), "5000 in the day is not above 5000");
		assert_eq!(fire(vec![amount("0.5", "USDT")], &[window.clone(), vec![vec![amount("1000", "USDT")]]].concat()), vec!["daily"]);
		assert!(
			fire(vec![amount("10", "USDT")], &[vec![amount("9999", "USDC")]]).is_empty(),
			"another currency in the window was the owners' to count"
		);
		let flagged = vec![
			amount("1", "USDT"),
			Field {
				key: "distribution".into(),
				value: FieldValue::Flag(true),
			},
		];
		assert_eq!(fire(flagged, &[]), vec!["distribution"]);
		let tighter = ScopePolicy {
			thresholds: vec![Threshold {
				kind: kind.name.clone(),
				parameter: "per_operation".into(),
				value: "10".into(),
			}],
			..ScopePolicy::default()
		};
		assert_eq!(fired_escalations(&kind, &[amount("11", "USDT")], &tighter, &[]), vec!["per_operation"]);
	}

	#[test]
	fn who_decides() {
		let platform = resolve_level(ApprovalLevel::Platform, false, vec![], 5);
		assert_eq!((platform.level, platform.escalated_by.len()), (ApprovalLevel::Platform, 0));
		assert_eq!(resolve_level(ApprovalLevel::Scope, true, vec![], 5).level, ApprovalLevel::Platform, "main is the owners'");
		assert_eq!(resolve_level(ApprovalLevel::Scope, false, vec![], 2).level, ApprovalLevel::Scope);
		let sole = resolve_level(ApprovalLevel::Scope, false, vec![], 1);
		assert_eq!((sole.level, sole.escalated_by), (ApprovalLevel::Platform, vec![SOLE_ADMIN.to_owned()]));
		let both = resolve_level(ApprovalLevel::Scope, false, vec!["daily".into()], 0);
		assert_eq!(both.escalated_by, vec!["daily".to_owned(), SOLE_ADMIN.to_owned()]);
	}

	#[test]
	fn more_than_half_of_the_whole_roster() {
		assert_eq!(threshold(1, 5001), 1);
		assert_eq!(threshold(2, 5001), 2);
		assert_eq!(threshold(3, 5001), 2);
		assert_eq!(threshold(4, 5001), 3);
		assert_eq!(threshold(5, 10_000), 5);
		assert_eq!(threshold(0, 5001), 1);
	}

	#[test]
	fn passes_on_threshold_then_waits_out_the_delay() {
		let roster = [uid(), uid(), uid()];
		let mut d = Decision::open(&roster, 2, 3600, 1000);
		d.vote(roster[0], Vote::For, 10, &[]).unwrap();
		assert_eq!(d.state, ApprovalState::Open);
		d.vote(roster[0], Vote::For, 11, &[]).unwrap();
		assert!(d.vote(roster[0], Vote::Against, 12, &[]).is_err(), "a vote is final");
		d.vote(roster[1], Vote::For, 20, &[]).unwrap();
		assert_eq!((d.state, d.executable_at), (ApprovalState::Passed, Some(3620)));
		assert!(!d.is_executable(3619));
		assert!(d.is_executable(3620));
		assert!(matches!(d.vote(roster[2], Vote::Against, 30, &[]), Err(DomainError::Precondition(_))));
		assert!(d.report(Outcome::Executed, "", 3619).is_err(), "inside the delay");
		assert_eq!(d.report(Outcome::Executed, "", 3620).unwrap(), Reported::Applied);
		assert_eq!(d.report(Outcome::Executed, "again", 4000).unwrap(), Reported::Repeated);
		assert!(d.report(Outcome::Failed, "x", 4000).is_err());
		assert_eq!(d.state, ApprovalState::Executed);
	}

	#[test]
	fn rejected_once_the_threshold_is_out_of_reach() {
		let roster = [uid(), uid(), uid()];
		let mut d = Decision::open(&roster, 2, 0, 1000);
		d.vote(roster[0], Vote::Against, 1, &[]).unwrap();
		assert_eq!(d.state, ApprovalState::Open);
		d.vote(roster[1], Vote::Against, 2, &[]).unwrap();
		assert_eq!(d.state, ApprovalState::Rejected);
	}

	#[test]
	fn veto_and_withdrawal_stop_it_only_inside_the_delay() {
		let roster = [uid(), uid()];
		let outsider = uid();
		let mut d = Decision::open(&roster, 2, 100, 1000);
		assert!(matches!(d.veto(outsider, false, "no", 1), Err(DomainError::Forbidden(_))));
		d.vote(roster[0], Vote::For, 1, &[]).unwrap();
		d.vote(roster[1], Vote::For, 2, &[]).unwrap();
		let mut late = d.clone();
		d.veto(roster[0], false, "changed my mind", 101).unwrap();
		assert_eq!((d.state, d.vetoed_by), (ApprovalState::Vetoed, Some(roster[0])));
		assert!(late.veto(roster[0], false, "too late", 102).is_err());
		assert!(late.withdraw(102).is_err());
		let mut early = Decision::open(&roster, 2, 100, 1000);
		early.withdraw(5).unwrap();
		assert_eq!(early.state, ApprovalState::Cancelled);
		let mut owned = Decision::open(&roster, 2, 100, 1000);
		owned.veto(outsider, true, "an owner off the roster", 5).unwrap();
		assert_eq!(owned.state, ApprovalState::Vetoed);
	}

	#[test]
	fn a_passed_decision_lapses_after_its_execution_window() {
		let roster = [uid(), uid()];
		let mut d = Decision::open(&roster, 2, 100, 1000);
		d.vote(roster[0], Vote::For, 0, &[]).unwrap();
		d.vote(roster[1], Vote::For, 0, &[]).unwrap();
		let by = 100 + EXECUTION_WINDOW_SECS;
		assert!(d.is_executable(by - 1));
		assert!(!d.is_executable(by));
		assert_eq!((d.effective_state(by), d.effective_decided_at(by)), (ApprovalState::Void, Some(by)));
		assert!(d.expire_if_due(by + 50));
		assert_eq!((d.state, d.decided_at, d.void_reason.as_str()), (ApprovalState::Void, Some(by), LAPSED));
		assert_eq!(d.pending.last(), Some(&ApprovalEvent::Lapsed));
		assert!(d.report(Outcome::Executed, "", by + 60).is_err(), "a lapsed decision takes no report");
	}

	#[test]
	fn a_for_vote_without_the_seat_does_not_count() {
		let roster = [uid(), uid(), uid()];
		let mut d = Decision::open(&roster, 2, 0, 1000);
		d.vote(roster[0], Vote::For, 1, &[]).unwrap();
		d.vote(roster[1], Vote::For, 2, &[roster[0]]).unwrap();
		assert_eq!(d.state, ApprovalState::Open);
		d.vote(roster[2], Vote::For, 3, &[roster[0]]).unwrap();
		assert_eq!(d.state, ApprovalState::Passed);
	}

	#[test]
	fn only_seated_againsts_reject() {
		let roster = [uid(), uid(), uid()];
		let mut d = Decision::open(&roster, 2, 0, 1000);
		d.vote(roster[0], Vote::For, 1, &[]).unwrap();
		d.vote(roster[1], Vote::Against, 2, &[roster[0]]).unwrap();
		assert_eq!(d.state, ApprovalState::Open, "a lost seat is no vote against");
		d.vote(roster[2], Vote::Against, 3, &[roster[0]]).unwrap();
		assert_eq!(d.state, ApprovalState::Rejected, "two seated AGAINSTs of three");
		let mut d = Decision::open(&roster, 2, 0, 1000);
		d.vote(roster[0], Vote::Against, 1, &[]).unwrap();
		d.vote(roster[1], Vote::Against, 2, &[roster[0]]).unwrap();
		assert_eq!(d.state, ApprovalState::Open, "an unseated AGAINST counts no more than a FOR would");
	}

	#[test]
	fn a_policy_change_carries_its_values_into_the_hash() {
		let with = |value: &str| {
			let policy = ScopePolicy {
				thresholds: vec![Threshold {
					kind: "bank:account_transfer".into(),
					parameter: "per_operation".into(),
					value: value.into(),
				}],
				..ScopePolicy::default()
			};
			let kind = builtin_kinds().into_iter().find(|k| k.name == SCOPE_POLICY_CHANGE).unwrap();
			let fields = check_fields(&kind, policy_fields(&policy)).unwrap();
			payload_preimage(&kind.name, "sa", "scope_policy:4f0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b", &fields)
		};
		assert_ne!(with("500"), with("900"));
		assert!(with("500").contains("threshold\tTEXT\tbank:account_transfer/per_operation=500\n"));
	}

	fn transfer_with(escalations: Vec<Escalation>) -> ApprovalKind {
		ApprovalKind { escalations, ..transfer_kind() }
	}

	fn policy_with(parameter: &str, value: &str) -> ScopePolicy {
		ScopePolicy {
			thresholds: vec![Threshold {
				kind: "bank:account_transfer".into(),
				parameter: parameter.into(),
				value: value.into(),
			}],
			..ScopePolicy::default()
		}
	}

	fn per_operation_at(threshold: &str) -> Escalation {
		Escalation {
			parameter: "per_operation".into(),
			field_key: "amount".into(),
			test: EscalationTest::AmountAbove,
			default_threshold: threshold.into(),
			currency: "USDT".into(),
		}
	}

	/// A scope's tightening of a catalog escalation is anchored on the floor at install, so
	/// a catalog that later drops or renames its own escalation drops nothing.
	#[test]
	fn a_policy_threshold_outlives_the_catalog_escalation_it_named() {
		let before = vec![transfer_with(vec![per_operation_at("1000")])];
		let installed = policy_with("per_operation", "700").anchored(&before);
		assert_eq!(installed.thresholds[0].parameter, "floor_per_operation");
		let dropped = crate::floors::floored(&transfer_with(vec![]));
		assert_eq!(fired_escalations(&dropped, &[amount("750", "USDT")], &installed, &[]), vec!["floor_per_operation"]);
	}

	/// A policy stored above the floor — before the floor existed — binds at the floor.
	#[test]
	fn a_stored_policy_above_the_floor_binds_at_the_floor() {
		let kind = crate::floors::floored(&transfer_with(vec![per_operation_at("1000")]));
		let fired = fired_escalations(&kind, &[amount("1500", "USDT")], &policy_with("per_operation", "5000"), &[]);
		assert!(fired.contains(&"floor_per_operation".to_owned()), "{fired:?}");
	}

	#[test]
	fn recipients_are_counted_over_the_day() {
		let payout = ApprovalKind {
			name: "bank:scope_payout".into(),
			fields: vec![],
			escalations: vec![Escalation {
				parameter: "floor_daily_recipients".into(),
				field_key: "recipients".into(),
				test: EscalationTest::Rolling24hCountAbove,
				default_threshold: "1".into(),
				currency: String::new(),
			}],
			..transfer_kind()
		};
		let recipients = |n: u64| Field {
			key: "recipients".into(),
			value: FieldValue::Count(n),
		};
		let policy = ScopePolicy::default();
		assert!(fired_escalations(&payout, &[recipients(1)], &policy, &[]).is_empty());
		assert_eq!(fired_escalations(&payout, &[recipients(1)], &policy, &[vec![recipients(1)]]), vec!["floor_daily_recipients"]);
	}

	#[test]
	fn the_platform_pauses_after_the_owners_change() {
		let policy = PlatformPolicy::default();
		assert_eq!(policy.admits(1000, 1000 + i64::from(DEFAULT_COOLDOWN_SECS) - 1), Err(1000 + i64::from(DEFAULT_COOLDOWN_SECS)));
		assert_eq!(policy.admits(1000, 1000 + i64::from(DEFAULT_COOLDOWN_SECS)), Ok(()));
		assert_eq!(PlatformPolicy { cooldown_secs: 0, ..policy }.admits(1000, 1000), Ok(()));
		assert!(
			PlatformPolicy {
				cooldown_secs: MAX_COOLDOWN_SECS + 1,
				..policy
			}
			.check()
			.is_err()
		);
	}

	#[test]
	fn pulling_stops_before_the_lapse() {
		let roster = [uid(), uid()];
		let mut d = Decision::open(&roster, 2, 100, 1000);
		d.vote(roster[0], Vote::For, 0, &[]).unwrap();
		d.vote(roster[1], Vote::For, 0, &[]).unwrap();
		let by = 100 + EXECUTION_WINDOW_SECS;
		assert!(d.is_pullable(by - PULL_MARGIN_SECS - 1));
		assert!(!d.is_pullable(by - PULL_MARGIN_SECS));
		assert!(d.is_executable(by - 1), "a pulled decision is still reportable");
	}

	#[test]
	fn a_policy_measures_against_the_kinds_in_force() {
		let kinds = vec![transfer_kind()];
		let threshold = |parameter: &str, value: &str| Threshold {
			kind: "bank:account_transfer".into(),
			parameter: parameter.into(),
			value: value.into(),
		};
		let ok = ScopePolicy {
			thresholds: vec![threshold("per_operation", "500")],
			..ScopePolicy::default()
		};
		assert_eq!(ok.check(&kinds), Ok(()));
		for bad in [
			ScopePolicy { delay_secs: 3599, ..ok.clone() },
			ScopePolicy { quorum_bps: 5000, ..ok.clone() },
			ScopePolicy {
				ttl_secs: MAX_TTL_SECS + 1,
				..ok.clone()
			},
			ScopePolicy {
				thresholds: vec![threshold("nothing", "1")],
				..ok.clone()
			},
			ScopePolicy {
				thresholds: vec![threshold("per_operation", "1.50")],
				..ok.clone()
			},
			ScopePolicy {
				thresholds: vec![threshold("distribution", "")],
				..ok.clone()
			},
			ScopePolicy {
				thresholds: vec![threshold("per_operation", "1"), threshold("per_operation", "2")],
				..ok.clone()
			},
		] {
			assert!(bad.check(&kinds).is_err(), "{bad:?}");
		}
		assert!(ok.check(&[]).is_err(), "a kind withdrawn since");
		let looser = ScopePolicy {
			thresholds: vec![threshold("per_operation", "1000.5")],
			..ok.clone()
		};
		assert!(looser.check(&kinds).is_err(), "above the kind's own 1000");
		let equal = ScopePolicy {
			thresholds: vec![threshold("per_operation", "1000")],
			..ok.clone()
		};
		assert_eq!(equal.check(&kinds), Ok(()));
	}

	#[test]
	fn the_built_in_kinds_are_the_platforms() {
		for kind in builtin_kinds() {
			assert_eq!(kind.level, ApprovalLevel::Platform, "{}", kind.name);
			assert!(kind.name.starts_with("concierge:"));
		}
	}

	#[test]
	fn expiry_is_lazy() {
		let roster = [uid(), uid()];
		let mut d = Decision::open(&roster, 2, 0, 1000);
		assert_eq!(d.effective_state(999), ApprovalState::Open);
		assert_eq!(d.effective_state(1000), ApprovalState::Expired);
		assert_eq!(d.state, ApprovalState::Open, "reading wrote nothing");
		assert!(d.expire_if_due(1000));
		assert_eq!((d.state, d.decided_at), (ApprovalState::Expired, Some(1000)));
		assert!(d.vote(roster[0], Vote::For, 1001, &[]).is_err());
	}

	fn standing(role: crate::authz::Role) -> PersonStanding {
		PersonStanding {
			role,
			active: true,
			verified: true,
			governance_suspended: false,
			second_factor: false,
		}
	}

	#[test]
	fn only_the_seat_changes_demand_unanimity() {
		for kind in [OWNER_ADMISSION, OWNER_REMOVAL] {
			assert_eq!(platform_quorum_bps(kind), 10_000, "{kind}");
		}
		for kind in [USER_SUSPENSION, USER_REINSTATEMENT, ADMIN_ADMISSION, SCOPE_ADMIN_GRANT, PLATFORM_POLICY, "bank:payment"] {
			assert_eq!(platform_quorum_bps(kind), PLATFORM_QUORUM_BPS, "{kind}");
		}
		// The bar over a roster of n: unanimity is n, the majority is what the user consilia
		// frozen onto their rows (floor(n/2)+1).
		for n in 1..=9usize {
			assert_eq!(threshold(n, 10_000) as usize, n);
			assert_eq!(threshold(n, PLATFORM_QUORUM_BPS) as usize, n / 2 + 1, "n = {n}");
		}
	}

	#[test]
	fn every_people_kind_is_built_in_at_the_platform_level_with_an_account_and_a_reason() {
		let kinds = builtin_kinds();
		for effect in [
			PersonEffect::AdmitOwner,
			PersonEffect::RemoveOwner,
			PersonEffect::Suspend,
			PersonEffect::Reinstate,
			PersonEffect::AdmitAdmin,
			PersonEffect::ResetSecondFactor,
		] {
			let kind = kinds.iter().find(|k| k.name == effect.kind()).unwrap_or_else(|| panic!("{} is built in", effect.kind()));
			assert_eq!(kind.level, ApprovalLevel::Platform);
			assert!(kind.escalations.is_empty());
			let keys: Vec<_> = kind.fields.iter().map(|f| (f.key.as_str(), f.field_type)).collect();
			assert_eq!(keys, [("account", FieldType::User), ("reason", FieldType::Text)]);
		}
	}

	#[test]
	fn a_people_action_names_the_account_it_is_about_and_keeps_it_off_the_roster() {
		let (opener, user) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
		let action = Action::People {
			effect: PersonEffect::RemoveOwner,
			user,
			opened_by: opener,
		};
		assert_eq!(action.about(), Some(user));
		assert_eq!(action.off_roster(opener), vec![opener, user]);
		let stored: Action = serde_json::from_value(serde_json::to_value(&action).unwrap()).unwrap();
		assert_eq!(stored, action);
		assert_eq!(Action::InstallPlatformPolicy { policy: PlatformPolicy::default() }.about(), None, "a policy is about nobody");
	}

	#[test]
	fn what_no_longer_applies_is_void_not_executed() {
		use crate::authz::Role;
		let at = |effect, subject, owners| person_inapplicable(effect, subject, owners);
		assert!(at(PersonEffect::AdmitOwner, standing(Role::Investor), 2).is_none());
		assert!(at(PersonEffect::AdmitOwner, standing(Role::Owner), 2).is_some(), "already seated");
		assert!(
			at(
				PersonEffect::AdmitOwner,
				PersonStanding {
					active: false,
					..standing(Role::Investor)
				},
				2
			)
			.is_some()
		);
		assert!(
			at(
				PersonEffect::AdmitOwner,
				PersonStanding {
					verified: false,
					..standing(Role::Investor)
				},
				2
			)
			.is_some()
		);
		// The floor: a removal leaves at least MIN_OWNERS behind, here and at execution.
		assert!(at(PersonEffect::RemoveOwner, standing(Role::Owner), 3).is_none());
		assert!(at(PersonEffect::RemoveOwner, standing(Role::Owner), 2).is_some(), "would leave one");
		assert!(at(PersonEffect::RemoveOwner, standing(Role::Admin), 5).is_some(), "not an owner any more");
		// Reinstatement lifts only the owners' own verdict.
		let verdict = PersonStanding {
			governance_suspended: true,
			..standing(Role::Investor)
		};
		assert!(at(PersonEffect::Reinstate, verdict, 2).is_none());
		assert!(at(PersonEffect::Reinstate, standing(Role::Investor), 2).is_some());
		assert!(at(PersonEffect::Suspend, verdict, 2).is_some(), "already suspended");
		assert!(at(PersonEffect::Suspend, standing(Role::Investor), 2).is_none());
		// A reset needs something to reset.
		let holder = PersonStanding {
			second_factor: true,
			..standing(Role::Investor)
		};
		assert!(at(PersonEffect::ResetSecondFactor, holder, 2).is_none());
		assert!(at(PersonEffect::ResetSecondFactor, standing(Role::Investor), 2).is_some(), "no factor to reset");
		// `admin` over `owner` would be an expulsion by another door.
		assert!(at(PersonEffect::AdmitAdmin, standing(Role::Owner), 3).is_some());
		assert!(at(PersonEffect::AdmitAdmin, standing(Role::Admin), 3).is_some());
		assert!(at(PersonEffect::AdmitAdmin, standing(Role::Operator), 3).is_none());
		assert!(
			at(
				PersonEffect::AdmitAdmin,
				PersonStanding {
					active: false,
					..standing(Role::Investor)
				},
				3
			)
			.is_some()
		);
		assert!(
			at(
				PersonEffect::AdmitAdmin,
				PersonStanding {
					verified: false,
					..standing(Role::Investor)
				},
				3
			)
			.is_some()
		);
	}
}

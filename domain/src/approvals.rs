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
	scope_catalog::{ApprovalKind, ApprovalLevel, EscalationTest, FieldType, is_canonical_amount, is_currency, plain_text},
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
/// At most this many live proposals per proposer namespace: one leaked credential must
/// not be able to bury the deciders.
pub const MAX_LIVE_PER_PROPOSER: i64 = 200;
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopePolicy {
	pub version: u64,
	pub quorum_bps: u32,
	pub delay_secs: u32,
	pub ttl_secs: u32,
	pub thresholds: Vec<Threshold>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
	fn threshold_of<'a>(&'a self, kind: &str, parameter: &str, default: &'a str) -> &'a str {
		self.thresholds.iter().find(|t| t.kind == kind && t.parameter == parameter).map_or(default, |t| t.value.as_str())
	}
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
		if fields[..i].iter().any(|f| f.key == field.key) {
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
	kind.escalations
		.iter()
		.filter(|e| {
			let threshold = policy.threshold_of(&kind.name, &e.parameter, &e.default_threshold);
			let value = value_of(fields, &e.field_key);
			// An absent optional field adds nothing to test; a field of another type cannot
			// reach here past `check_fields`. Matched per test so a new test is a compile
			// error rather than an escalation that silently never fires.
			match e.test {
				// A different currency than the parameter's cannot be compared, so it goes to
				// the owners: fail safe.
				EscalationTest::AmountAbove => matches!(value, Some(FieldValue::Amount(a)) if a.currency != e.currency || amount_above(&a.value, threshold)),
				EscalationTest::Rolling24hAmountAbove => {
					let Some(FieldValue::Amount(a)) = value else { return false };
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
				EscalationTest::AbsBpsAbove => matches!(value, Some(FieldValue::Bps(bps)) if threshold.parse::<u64>().map_or(true, |limit| bps.unsigned_abs() > limit)),
				EscalationTest::FlagSet => matches!(value, Some(FieldValue::Flag(true))),
			}
		})
		.map(|e| e.parameter.clone())
		.collect()
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
	/// yet: what `PullApproved` serves.
	pub fn is_executable(&self, now: i64) -> bool {
		self.effective_state(now) == ApprovalState::Passed && self.executable_at.is_some_and(|at| now >= at)
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
	/// refused. Call [`Self::expire_if_due`] first.
	pub fn vote(&mut self, voter: UserId, vote: Vote, now: i64) -> Result<(), DomainError> {
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
		let count = |v: Vote| self.voters.iter().filter(|x| x.vote == v).count();
		let (fors, againsts) = (count(Vote::For), count(Vote::Against));
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
	use crate::scope_catalog::{Escalation, FieldSpec};

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
				},
				FieldSpec {
					key: "amount".into(),
					label: "Amount".into(),
					field_type: FieldType::Amount,
					required: true,
				},
				FieldSpec {
					key: "distribution".into(),
					label: "To every holder".into(),
					field_type: FieldType::Flag,
					required: false,
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
		d.vote(roster[0], Vote::For, 10).unwrap();
		assert_eq!(d.state, ApprovalState::Open);
		d.vote(roster[0], Vote::For, 11).unwrap();
		assert!(d.vote(roster[0], Vote::Against, 12).is_err(), "a vote is final");
		d.vote(roster[1], Vote::For, 20).unwrap();
		assert_eq!((d.state, d.executable_at), (ApprovalState::Passed, Some(3620)));
		assert!(!d.is_executable(3619));
		assert!(d.is_executable(3620));
		assert!(matches!(d.vote(roster[2], Vote::Against, 30), Err(DomainError::Precondition(_))));
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
		d.vote(roster[0], Vote::Against, 1).unwrap();
		assert_eq!(d.state, ApprovalState::Open);
		d.vote(roster[1], Vote::Against, 2).unwrap();
		assert_eq!(d.state, ApprovalState::Rejected);
	}

	#[test]
	fn veto_and_withdrawal_stop_it_only_inside_the_delay() {
		let roster = [uid(), uid()];
		let outsider = uid();
		let mut d = Decision::open(&roster, 2, 100, 1000);
		assert!(matches!(d.veto(outsider, false, "no", 1), Err(DomainError::Forbidden(_))));
		d.vote(roster[0], Vote::For, 1).unwrap();
		d.vote(roster[1], Vote::For, 2).unwrap();
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
		d.vote(roster[0], Vote::For, 0).unwrap();
		d.vote(roster[1], Vote::For, 0).unwrap();
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
	fn expiry_is_lazy() {
		let roster = [uid(), uid()];
		let mut d = Decision::open(&roster, 2, 0, 1000);
		assert_eq!(d.effective_state(999), ApprovalState::Open);
		assert_eq!(d.effective_state(1000), ApprovalState::Expired);
		assert_eq!(d.state, ApprovalState::Open, "reading wrote nothing");
		assert!(d.expire_if_due(1000));
		assert_eq!((d.state, d.decided_at), (ApprovalState::Expired, Some(1000)));
		assert!(d.vote(roster[0], Vote::For, 1001).is_err());
	}
}

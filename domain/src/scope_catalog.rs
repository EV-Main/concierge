//! A scope catalog — what a namespace's services define beyond permissions: the approval
//! kinds it alone proposes and executes, and the notification topics it emits on
//! (`docs/SCOPES-AND-APPROVALS.md` §5.1, §6; `ScopeCatalogService`).
//!
//! Stored whole, one row per published version, as `concierge_iam::Catalog` is: which
//! kinds and topics were in force when is a query, and a withdrawn kind is still readable
//! for the proposals opened under it. The shape rules live here so the RPC and anything
//! else that ever writes a catalog refuse the same things.

use serde::{Deserialize, Serialize};

pub const MAX_KINDS: usize = 64;
pub const MAX_TOPICS: usize = 64;
pub const MAX_FIELDS: usize = 16;

const KIND_LABEL_BYTES: usize = 80;
const KIND_DESCRIPTION_BYTES: usize = 500;
const FIELD_LABEL_BYTES: usize = 60;
const TOPIC_BYTES: usize = 64;
const TOPIC_LABEL_BYTES: usize = 60;
const TOPIC_DESCRIPTION_BYTES: usize = 200;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalLevel {
	Platform,
	Scope,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
	Text,
	Amount,
	Bps,
	Flag,
	User,
	Timestamp,
	Count,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationTest {
	AmountAbove,
	Rolling24hAmountAbove,
	AbsBpsAbove,
	FlagSet,
	CountAbove,
	Rolling24hCountAbove,
}

impl EscalationTest {
	/// The one field type each test reads.
	pub(crate) fn tests(self) -> FieldType {
		match self {
			Self::AmountAbove | Self::Rolling24hAmountAbove => FieldType::Amount,
			Self::AbsBpsAbove => FieldType::Bps,
			Self::FlagSet => FieldType::Flag,
			Self::CountAbove | Self::Rolling24hCountAbove => FieldType::Count,
		}
	}
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FieldSpec {
	pub key: String,
	pub label: String,
	pub field_type: FieldType,
	pub required: bool,
	/// May be given more than once. Only this plane's own kinds declare one (a policy's
	/// threshold overrides, one field each): a published kind cannot ask for it, and a
	/// catalog stored before the flag existed reads it as `false`.
	#[serde(default)]
	pub repeated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Escalation {
	pub parameter: String,
	pub field_key: String,
	pub test: EscalationTest,
	pub default_threshold: String,
	pub currency: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApprovalKind {
	pub name: String,
	pub label: String,
	pub description: String,
	pub level: ApprovalLevel,
	pub fields: Vec<FieldSpec>,
	pub escalations: Vec<Escalation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NotificationTopic {
	pub topic: String,
	pub label: String,
	pub description: String,
	pub default_subscribed: bool,
}

/// One publication. Kinds, fields and topics keep the order they were published in: it is
/// the display order, so two publications differing only in order are different content.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScopeCatalog {
	/// The unix seconds of the publisher's build commit.
	pub version: u64,
	pub approval_kinds: Vec<ApprovalKind>,
	pub notification_topics: Vec<NotificationTopic>,
}

impl ScopeCatalog {
	/// Everything is `namespace`'s, within the bounds, and renderable. `reserved` are the
	/// topic keys this plane owns itself: a scope whose namespace happens to share a
	/// built-in topic's prefix must not shadow it.
	pub fn check(&self, namespace: &str, reserved: &[&str]) -> Result<(), String> {
		if self.approval_kinds.len() > MAX_KINDS || self.notification_topics.len() > MAX_TOPICS {
			return Err(format!("a scope catalog holds at most {MAX_KINDS} approval kinds and {MAX_TOPICS} notification topics"));
		}
		for (i, kind) in self.approval_kinds.iter().enumerate() {
			if self.approval_kinds[..i].iter().any(|k| k.name == kind.name) {
				return Err(format!("approval kind `{}` is published twice", kind.name));
			}
			kind.check(namespace)?;
		}
		for (i, topic) in self.notification_topics.iter().enumerate() {
			if self.notification_topics[..i].iter().any(|t| t.topic == topic.topic) {
				return Err(format!("notification topic `{}` is published twice", topic.topic));
			}
			if reserved.contains(&topic.topic.as_str()) {
				return Err(format!("notification topic `{}` is this plane's own", topic.topic));
			}
			topic.check(namespace)?;
		}
		Ok(())
	}
}

impl ApprovalKind {
	fn check(&self, namespace: &str) -> Result<(), String> {
		let name = &self.name;
		match name.split_once(':') {
			Some((ns, rest)) if ns == namespace && is_identifier(rest) => {}
			_ => return Err(format!("approval kind `{name}` is not `{namespace}:<name>`")),
		}
		plain_text(&self.label, KIND_LABEL_BYTES, false).map_err(|why| format!("approval kind `{name}` label {why}"))?;
		plain_text(&self.description, KIND_DESCRIPTION_BYTES, true).map_err(|why| format!("approval kind `{name}` description {why}"))?;
		if self.fields.len() > MAX_FIELDS {
			return Err(format!("approval kind `{name}` has more than {MAX_FIELDS} fields"));
		}
		for (i, field) in self.fields.iter().enumerate() {
			if !is_key(&field.key) || self.fields[..i].iter().any(|f| f.key == field.key) {
				return Err(format!("approval kind `{name}` field `{}` is not a unique `[a-z][a-z0-9_]{{0,31}}` key", field.key));
			}
			plain_text(&field.label, FIELD_LABEL_BYTES, false).map_err(|why| format!("approval kind `{name}` field `{}` label {why}", field.key))?;
		}
		if self.level == ApprovalLevel::Platform && !self.escalations.is_empty() {
			return Err(format!("approval kind `{name}` is decided by the platform and escalates nowhere"));
		}
		for (i, escalation) in self.escalations.iter().enumerate() {
			let parameter = &escalation.parameter;
			if !is_key(parameter) || self.escalations[..i].iter().any(|e| &e.parameter == parameter) {
				return Err(format!("approval kind `{name}` escalation `{parameter}` is not a unique `[a-z][a-z0-9_]{{0,31}}` key"));
			}
			// `floor_*` names this plane's own escalations: a publisher's one under that name
			// would be taken for the floor in `escalated_by` and in a scope's policy.
			if crate::floors::is_floor_parameter(parameter) {
				return Err(format!("approval kind `{name}` escalation `{parameter}`: `floor_*` names this plane's own floor"));
			}
			let Some(field) = self.fields.iter().find(|f| f.key == escalation.field_key) else {
				return Err(format!("approval kind `{name}` escalation `{parameter}` tests no field of the kind"));
			};
			if field.field_type != escalation.test.tests() {
				return Err(format!("approval kind `{name}` escalation `{parameter}` tests a field of the wrong type"));
			}
			// A test over a field the proposer may leave out is a test the proposer may
			// switch off, and an absent field escalates nothing.
			if !field.required {
				return Err(format!("approval kind `{name}` escalation `{parameter}` tests an optional field"));
			}
			let threshold = &escalation.default_threshold;
			let shaped = match escalation.test {
				EscalationTest::AmountAbove | EscalationTest::Rolling24hAmountAbove => is_canonical_amount(threshold) && is_currency(&escalation.currency),
				EscalationTest::AbsBpsAbove => is_unsigned_integer(threshold) && escalation.currency.is_empty(),
				EscalationTest::FlagSet => threshold.is_empty() && escalation.currency.is_empty(),
				EscalationTest::CountAbove | EscalationTest::Rolling24hCountAbove => is_unsigned_integer(threshold) && escalation.currency.is_empty(),
			};
			if !shaped {
				return Err(format!("approval kind `{name}` escalation `{parameter}` has a threshold or currency its test does not take"));
			}
		}
		crate::floors::check(self)
	}
}

impl NotificationTopic {
	fn check(&self, namespace: &str) -> Result<(), String> {
		let topic = &self.topic;
		let mut segments = topic.split(':');
		let ours = segments.next() == Some(namespace);
		let rest: Vec<&str> = segments.collect();
		let shaped = !rest.is_empty()
			&& rest
				.iter()
				.all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'));
		if !ours || !shaped || topic.len() > TOPIC_BYTES {
			return Err(format!("notification topic `{topic}` is not `{namespace}:<segment>…` of at most {TOPIC_BYTES} bytes"));
		}
		plain_text(&self.label, TOPIC_LABEL_BYTES, false).map_err(|why| format!("notification topic `{topic}` label {why}"))?;
		plain_text(&self.description, TOPIC_DESCRIPTION_BYTES, true).map_err(|why| format!("notification topic `{topic}` description {why}"))
	}
}

/// Rendered into mail and screens as the publisher's words, never as markup: one line,
/// no control character, no link a reader could be sent to.
pub(crate) fn plain_text(text: &str, max_bytes: usize, may_be_empty: bool) -> Result<(), &'static str> {
	if text.is_empty() && !may_be_empty {
		return Err("is empty");
	}
	if text.len() > max_bytes {
		return Err("is too long");
	}
	if text.chars().any(char::is_control) {
		return Err("carries a control character");
	}
	let lower = text.to_ascii_lowercase();
	if lower.contains("://") || lower.contains("www.") {
		return Err("carries a link");
	}
	Ok(())
}

fn is_identifier(raw: &str) -> bool {
	let mut bytes = raw.bytes();
	bytes.next().is_some_and(|b| b.is_ascii_lowercase()) && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn is_key(raw: &str) -> bool {
	raw.len() <= 32 && is_identifier(raw)
}

pub(crate) fn is_currency(raw: &str) -> bool {
	let mut bytes = raw.bytes();
	(2..=16).contains(&raw.len()) && bytes.next().is_some_and(|b| b.is_ascii_uppercase()) && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn is_unsigned_integer(raw: &str) -> bool {
	raw == "0" || (!raw.is_empty() && !raw.starts_with('0') && raw.bytes().all(|b| b.is_ascii_digit()))
}

/// Whole digits an amount may carry: beyond any real sum, and a bound on what one field
/// costs to store, hash and add up in the rolling window.
const AMOUNT_WHOLE_DIGITS: usize = 30;

/// `0|[1-9][0-9]{0,29}`, then optionally `.` and at most 18 digits not ending in `0` — the
/// spelling `ApprovalAmount` requires, so a threshold compares with the amounts it tests.
pub(crate) fn is_canonical_amount(raw: &str) -> bool {
	let (whole, fraction) = raw.split_once('.').unwrap_or((raw, ""));
	let fraction_ok = raw
		.contains('.')
		.then(|| (1..=18).contains(&fraction.len()) && fraction.bytes().all(|b| b.is_ascii_digit()) && !fraction.ends_with('0'));
	is_unsigned_integer(whole) && whole.len() <= AMOUNT_WHOLE_DIGITS && fraction_ok.unwrap_or(true)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn amount_kind() -> ApprovalKind {
		ApprovalKind {
			name: "bank:account_transfer".into(),
			label: "Transfer between accounts".into(),
			description: String::new(),
			level: ApprovalLevel::Scope,
			fields: vec![
				FieldSpec {
					key: "from_account".into(),
					label: "From".into(),
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
			],
			escalations: vec![Escalation {
				parameter: "per_operation".into(),
				field_key: "amount".into(),
				test: EscalationTest::AmountAbove,
				default_threshold: "1000".into(),
				currency: "USDT".into(),
			}],
		}
	}

	fn topic(key: &str) -> NotificationTopic {
		NotificationTopic {
			topic: key.into(),
			label: "Money movement".into(),
			description: "Deposits and withdrawals".into(),
			default_subscribed: false,
		}
	}

	fn catalog(kinds: Vec<ApprovalKind>, topics: Vec<NotificationTopic>) -> ScopeCatalog {
		ScopeCatalog {
			version: 1,
			approval_kinds: kinds,
			notification_topics: topics,
		}
	}

	#[test]
	fn a_well_formed_catalog_passes() {
		assert_eq!(catalog(vec![amount_kind()], vec![topic("bank:money-movement")]).check("bank", &[]), Ok(()));
	}

	#[test]
	fn everything_must_be_the_publishers() {
		assert!(catalog(vec![amount_kind()], vec![]).check("invest", &[]).is_err());
		assert!(catalog(vec![], vec![topic("bank:money-movement")]).check("invest", &[]).is_err());
		assert!(catalog(vec![], vec![topic("account:verification")]).check("account", &["account:verification"]).is_err());
	}

	#[test]
	fn a_platform_kind_escalates_nowhere() {
		let mut kind = amount_kind();
		kind.level = ApprovalLevel::Platform;
		assert!(catalog(vec![kind], vec![]).check("bank", &[]).is_err());
	}

	#[test]
	fn an_escalation_tests_a_field_of_its_type_with_a_canonical_threshold() {
		for (field_key, threshold, currency) in [
			("from_account", "1000", "USDT"),
			("amount", "1000.50", "USDT"),
			("amount", "01000", "USDT"),
			("amount", "1000", ""),
			("missing", "1", "USDT"),
		] {
			let mut kind = amount_kind();
			kind.escalations[0].field_key = field_key.into();
			kind.escalations[0].default_threshold = threshold.into();
			kind.escalations[0].currency = currency.into();
			assert!(catalog(vec![kind], vec![]).check("bank", &[]).is_err(), "{field_key} {threshold} {currency}");
		}
		let mut kind = amount_kind();
		kind.escalations[0].default_threshold = "999.5".into();
		assert_eq!(catalog(vec![kind], vec![]).check("bank", &[]), Ok(()));
		let mut kind = amount_kind();
		kind.escalations[0].default_threshold = "1000.5".into();
		assert!(catalog(vec![kind], vec![]).check("bank", &[]).is_err(), "above this plane's floor for a transfer");
	}

	#[test]
	fn a_count_escalation_takes_an_integer_and_no_currency() {
		let mut kind = amount_kind();
		kind.name = "sa:headcount".into();
		kind.fields[0] = FieldSpec {
			key: "seats".into(),
			label: "Seats".into(),
			field_type: FieldType::Count,
			required: true,
			repeated: false,
		};
		kind.escalations[0] = Escalation {
			parameter: "crowd".into(),
			field_key: "seats".into(),
			test: EscalationTest::CountAbove,
			default_threshold: "3".into(),
			currency: String::new(),
		};
		assert_eq!(catalog(vec![kind.clone()], vec![]).check("sa", &[]), Ok(()));
		kind.escalations[0].currency = "USDT".into();
		assert!(catalog(vec![kind.clone()], vec![]).check("sa", &[]).is_err());
		kind.escalations[0].currency = String::new();
		kind.escalations[0].parameter = "floor_crowd".into();
		assert!(catalog(vec![kind], vec![]).check("sa", &[]).is_err(), "`floor_*` is this plane's own name");
	}

	#[test]
	fn an_escalation_tests_a_required_field() {
		let mut kind = amount_kind();
		kind.fields[1].required = false;
		assert!(
			catalog(vec![kind], vec![]).check("bank", &[]).is_err(),
			"an escalation over a field a proposer may leave out is one it may switch off"
		);
	}

	#[test]
	fn an_amount_has_at_most_thirty_whole_digits() {
		assert!(is_canonical_amount(&"9".repeat(30)));
		assert!(is_canonical_amount(&format!("{}.5", "9".repeat(30))));
		assert!(!is_canonical_amount(&"9".repeat(31)));
	}

	#[test]
	fn text_is_one_line_without_links() {
		for label in ["", "see https://evil.example", "visit www.evil.example", "two\nlines"] {
			let mut kind = amount_kind();
			kind.label = label.into();
			assert!(catalog(vec![kind], vec![]).check("bank", &[]).is_err(), "{label:?}");
		}
	}

	#[test]
	fn duplicates_and_bounds_are_refused() {
		assert!(catalog(vec![amount_kind(), amount_kind()], vec![]).check("bank", &[]).is_err());
		assert!(catalog(vec![], vec![topic("bank:a"), topic("bank:a")]).check("bank", &[]).is_err());
		let many = (0..=MAX_TOPICS).map(|i| topic(&format!("bank:t{i}"))).collect();
		assert!(catalog(vec![], many).check("bank", &[]).is_err());
		assert!(catalog(vec![], vec![topic(&format!("bank:{}", "a".repeat(60)))]).check("bank", &[]).is_err());
		assert!(catalog(vec![], vec![topic("bank:")]).check("bank", &[]).is_err());
		assert!(catalog(vec![], vec![topic("bank:Upper")]).check("bank", &[]).is_err());
	}
}

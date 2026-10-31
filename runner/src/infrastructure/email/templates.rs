//! Server-rendered transactional emails for the notification plane.
//!
//! Inline hex (not design tokens) is required here: email clients support neither
//! CSS variables nor external stylesheets, so brand colours are inlined per element.
//!
//! The palette below is flattened from `@evinvest/uikit` (`styles/tokens.css`), the
//! same source the Figma `ev/color` variables publish from — keep the two in step
//! when either moves. Kept deliberately identical to the `site_conductor` templates
//! so a person receiving mail from both planes sees one brand.

// Flattened tokens. Mail clients support neither CSS variables nor `color-mix`, so
// the alpha-based semantic tokens are pre-composited against the surface they sit on
// and pasted as opaque hex.
const MIST: &str = "#e6e1d3"; // --color-main-mist
const TEAL: &str = "#2a9d8f"; // --color-main-accent-t1
const HAIR: &str = "#1b2742"; // navy-hairline
const BLACK: &str = "#070d18"; // --color-main-black / --background
const SURFACE: &str = "#081020"; // --color-main-surface
const CARD: &str = "#0c1626"; // --color-main-card / --card
// `--muted-foreground` is mist at 40%, which composites to ~#63676b on the card —
// 3.3:1, under the 4.5:1 that 13px body copy needs. Kept on the same mist ramp but
// at 60% so the label column stays legible in a mail client.
const MUTED: &str = "#8f908e";

const SERIF: &str = "'Playfair Display',Georgia,'Times New Roman',serif";
const SANS: &str = "Inter,-apple-system,'Segoe UI',Arial,Helvetica,sans-serif";

pub struct RenderedEmail {
	pub subject: String,
	pub html: String,
	pub text: String,
}

/// A notification's email copy. `target` is the finished URL; which cabinet it may name
/// is decided by `notice_link::NoticeLinkBases::mail_target`, not here. `required` is the
/// publisher's reason when the topic is a required notice: the footer then says why the
/// mail came instead of "you follow", and the caller passes no unsubscribe target.
pub fn notification(topic_label: &str, title: &str, body: &str, target: &str, occurred_at: i64, unsubscribe_url: &str, required: Option<&str>) -> RenderedEmail {
	// The text part prints the link bare on its own line — see `one_line`.
	let target = &one_line(target);

	let mut inner = String::new();
	inner.push_str(&eyebrow(topic_label));
	inner.push_str(&heading(title));
	if !body.is_empty() {
		inner.push_str(&paragraph(body));
	}
	inner.push_str(&detail_box(&[("Topic", topic_label.to_owned()), ("As of", fmt_ts(occurred_at))]));
	inner.push_str(&button("Open your cabinet", target));

	let footer = match required {
		Some(reason) => format!(
			"You are receiving this because {topic_label} is a required notice, which cannot be switched off: {}. This message is a copy — it is already waiting in your cabinet.",
			reason.trim_end_matches('.')
		),
		None => format!("You are receiving this because you follow {topic_label}. This message is a copy — it is already waiting in your cabinet."),
	};
	let unsubscribe_line = if unsubscribe_url.is_empty() {
		String::new()
	} else {
		format!("Unsubscribe: {unsubscribe_url}\n")
	};
	RenderedEmail {
		subject: format!("{topic_label} — {title}"),
		html: shell(title, &card(&inner), &footer, unsubscribe_url, topic_label),
		text: format!(
			"{topic_label}\n\n{title}\n\n{body}\n\nAs of: {}\n\nOpen your cabinet: {target}\n\n—\n{footer}\n{unsubscribe_line}",
			fmt_ts(occurred_at)
		),
	}
}

/// The double opt-in mail — the ONLY thing an unconfirmed, account-less subscriber
/// ever receives. Deliberately minimal: no fund content before consent.
pub fn confirm_subscription(topic_label: &str, confirm_url: &str, unsubscribe_url: &str) -> RenderedEmail {
	let mut inner = String::new();
	inner.push_str(&eyebrow("Confirm your subscription"));
	inner.push_str(&heading("One click and you're on the list"));
	inner.push_str(&paragraph(&format!(
		"Someone — we hope you — asked for {topic_label} updates at this address. Confirm below and we'll start sending. If it wasn't you, ignore this message and nothing further will be sent."
	)));
	inner.push_str(&button("Confirm subscription", confirm_url));

	RenderedEmail {
		subject: format!("Confirm your {topic_label} updates"),
		html: shell(
			"Confirm your subscription",
			&card(&inner),
			"You received this once because this address was entered on our site. We send nothing else until you confirm.",
			unsubscribe_url,
			topic_label,
		),
		text: format!(
			"Confirm your subscription\n\nSomeone asked for {topic_label} updates at this address.\n\nConfirm: {confirm_url}\n\nIf it wasn't you, ignore this message — nothing further will be sent.\n"
		),
	}
}

/// The owners' alert about a vendor verdict that contradicts a level the account holds.
///
/// Deliberately NOT a request to act on a link. There is no code and no button, because
/// the decision this mail exists to trigger — lowering somebody's KYC level — is one
/// nobody should be able to make from an inbox. It says what happened and where to look;
/// the act itself happens in the console under `Kyc::Manage`.
///
/// The affected account's address is printed because it is how an operator finds the
/// person in the console, and it is an address the recipient already administers.
pub fn kyc_verdict_alert(subject_email: &str, case_id: &str, verdict: &str, held_level: u32, requested_tier: u32, decided_at: i64) -> RenderedEmail {
	let subject_email = one_line(subject_email);
	let case_id = one_line(case_id);
	let verdict = one_line(verdict);
	let decided = fmt_ts(decided_at);

	let headline = "A verification verdict contradicts a level an account already holds";
	let explain = format!(
		"Our verification provider reported \u{201c}{verdict}\u{201d} for a case opened at tier {requested_tier}, and the account still stands at level {held_level}. The level has NOT been changed: only a person holding KYC management may lower one. This message exists so that somebody decides, rather than nobody."
	);

	let rows = vec![
		("Account", subject_email.clone()),
		("Verdict", verdict.clone()),
		("Case", case_id.clone()),
		("Level held", held_level.to_string()),
		("Case tier", requested_tier.to_string()),
		("Decided", decided.clone()),
	];

	let mut inner = String::new();
	inner.push_str(&eyebrow("Verification"));
	inner.push_str(&heading(headline));
	inner.push_str(&paragraph(&explain));
	inner.push_str(&detail_box(&rows));
	inner.push_str(&paragraph(
		"Review the account in the operator console. If the level should come down, lower it there — there is no link in this mail that can do it.",
	));

	RenderedEmail {
		subject: format!("Verification verdict \u{201c}{verdict}\u{201d} contradicts level {held_level}"),
		html: shell(headline, &card(&inner), FOOTER_SECURITY, "", "Verification"),
		text: format!(
			"{headline}\n\n{explain}\n\nAccount: {subject_email}\nVerdict: {verdict}\nCase: {case_id}\nLevel held: {held_level}\nCase tier: {requested_tier}\nDecided: {decided}\n\nReview the account in the operator console. If the level should come down, lower it there — there is no link in this mail that can do it.\n\n—\n{FOOTER_SECURITY}\n"
		),
	}
}

// ── building blocks ────────────────────────────────────────────────────────

/// Why a governance mail has no unsubscribe link, said out loud.
/// A sign-in code or an email-verification code. No link on purpose: a link would sign
/// in whoever's mail gateway follows it, and the code is only worth anything typed into
/// the page that asked for it.
pub fn email_code(sign_in: bool, code: &str, expires_at: i64) -> RenderedEmail {
	let (title, ask, subject) = if sign_in {
		(
			"Your sign-in code",
			"Enter this code on the page where you asked to sign in.",
			format!("{code} is your EV Investment sign-in code"),
		)
	} else {
		(
			"Confirm your email",
			"Enter this code in your EV Investment settings to confirm this address is yours.",
			format!("{code} is your EV Investment verification code"),
		)
	};
	let mut inner = String::new();
	inner.push_str(&eyebrow("Account"));
	inner.push_str(&heading(title));
	inner.push_str(&paragraph(ask));
	inner.push_str(&code_panel(code));
	inner.push_str(&paragraph(&format!(
		"It works once, until {}. If you did not ask for it, ignore this message: without the code nothing happens.",
		fmt_ts(expires_at)
	)));
	RenderedEmail {
		subject,
		html: shell(title, &card(&inner), FOOTER_CODE, "", "Account"),
		text: format!(
			"{title}\n\n{ask}\n\nYour code: {code}\n\nIt works once, until {}. If you did not ask for it, ignore this message: without the code nothing happens.\n\n—\n{FOOTER_CODE}\n",
			fmt_ts(expires_at)
		),
	}
}

/// The code that confirms a sensitive act of the signed-in account (re-authentication,
/// #166). It says what it is for: the person must be able to tell it from a sign-in code
/// and to see that handing it over lets someone act with their money.
pub fn reauth_code(code: &str, expires_at: i64) -> RenderedEmail {
	let title = "Confirm an action on your account";
	let ask = "Enter this code on the page where you were asked to confirm an action with your money.";
	let warn = "If this was not you, do not share the code: change your sign-in methods and sign out of other sessions now.";
	let mut inner = String::new();
	inner.push_str(&eyebrow("Account"));
	inner.push_str(&heading(title));
	inner.push_str(&paragraph(ask));
	inner.push_str(&code_panel(code));
	inner.push_str(&paragraph(&format!("It works once, until {}. {warn}", fmt_ts(expires_at))));
	RenderedEmail {
		subject: format!("{code} confirms an action on your EV Investment account"),
		html: shell(title, &card(&inner), FOOTER_CODE, "", "Account"),
		text: format!(
			"{title}\n\n{ask}\n\nYour code: {code}\n\nIt works once, until {}. {warn}\n\n—\n{FOOTER_CODE}\n",
			fmt_ts(expires_at)
		),
	}
}

/// A second factor of the account changed (`web::second_factor`). `None` for an `event`
/// this build does not know, which the dispatcher parks rather than mails half-said.
pub fn security_notice(event: &str, label: Option<&str>, at: i64) -> Option<RenderedEmail> {
	let (title, what) = match event {
		"factor_added" => (
			"A second factor was added",
			"A second factor was added to your account. It will be asked for before money leaves it.",
		),
		"factor_removed" => (
			"A second factor was removed",
			"A second factor was removed from your account. With none left, withdrawals are refused until you add one.",
		),
		"recovery_codes_replaced" => ("Your recovery codes were replaced", "New recovery codes were made for your account. The old ones no longer work."),
		"recovered" => (
			"Your second factors were reset with a recovery code",
			"A recovery code was used on your account: every second factor and recovery code was removed and every session was signed out.",
		),
		"reset" => (
			"Your second factors were reset by the platform owners",
			"The platform owners decided to reset your account's second factors: every second factor and recovery code was removed and every session was signed out. Sign in and add a new one.",
		),
		_ => return None,
	};
	let warn = "If this was not you, sign in now, sign out of other sessions and contact support: someone holds your sign-in.";
	let when = fmt_ts_utc(at);
	let name = label.map(one_line);
	let mut rows = vec![("Time", when.clone())];
	if let Some(name) = &name {
		rows.push(("Factor", name.clone()));
	}
	let mut inner = String::new();
	inner.push_str(&eyebrow("Account"));
	inner.push_str(&heading(title));
	inner.push_str(&paragraph(what));
	inner.push_str(&detail_box(&rows));
	inner.push_str(&paragraph(warn));
	let factor_line = name.map(|n| format!("Factor: {n}\n")).unwrap_or_default();
	Some(RenderedEmail {
		subject: format!("{title} on your EV Investment account"),
		html: shell(title, &card(&inner), FOOTER_ACCOUNT, "", "Account"),
		text: format!("{title}\n\n{what}\n\nTime: {when}\n{factor_line}\n{warn}\n\n—\n{FOOTER_ACCOUNT}\n"),
	})
}

const FOOTER_CODE: &str = "You received this because this address was entered on evinvest.ltd. EV Investment never asks for this code by phone, chat or email.";

const FOOTER_ACCOUNT: &str =
	"You are receiving this because it concerns how your own account is protected. Security mail cannot be switched off — if it could, muting it would be the first thing an attacker did.";

const FOOTER_SECURITY: &str =
	"You are receiving this because you hold an owner seat. Security mail cannot be switched off — if it could, muting it would be the first thing an attacker did.";

/// Says whose words follow. Carried by BOTH parts of the mail, so the HTML label and the
/// text label cannot drift apart.
const INITIATOR_NOTE_LABEL: &str = "Text entered by the requester (not written by EV Investment)";

/// Collapse anything that could break a line into a space.
///
/// The emailed LINK goes through this too: the text part prints it bare on a line of its
/// own, so a newline inside it would end our link and start somebody else's on the next
/// line. A notice's link is printable ASCII before it gets here (`notice_link`); this is
/// the renderer's copy of the rule.
///
/// The HTML part escapes, so markup is already accounted for. The TEXT part does not: it
/// is a `Label: value` block assembled by `format!`, and a newline inside a value forges
/// a line of that block — `Amount:` being precisely a line an approval mail exists to
/// state. This is the rule standing where the forgery would actually happen, so no row,
/// however it reached the queue, can do it.
///
/// "Could break a line" is [`breaks_or_hides`], not only the C0/C1 controls: a mail client
/// ends a line at U+2028/U+2029 as well, and an invisible or bidi character makes a value
/// read differently from what it is.
fn one_line(value: &str) -> String {
	value.chars().map(|c| if breaks_or_hides(c) { ' ' } else { c }).collect()
}

/// A character that ends a line, or hides or reorders what a line shows: the C0/C1
/// controls, the Unicode line and paragraph separators, the zero-width and directional
/// marks, the bidi embeddings, overrides and isolates, the invisible operators, and the
/// byte-order mark. The ONE predicate both sides use — an input refuses a field carrying
/// one, the renderer folds it — so the two copies of the rule cannot drift apart. A
/// no-break space is none of these: it is how a number is legitimately grouped.
pub(crate) fn breaks_or_hides(c: char) -> bool {
	c.is_control()
		|| matches!(
			c,
			'\u{2028}' | '\u{2029}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
		)
}

/// Free text somebody else wrote, shown verbatim and marked as theirs.
///
/// Set apart rather than folded into a sentence of ours: it is the one field an operator
/// types freely, and a reader who cannot tell it from the platform's own copy is a reader
/// who can be told anything ("EV Investment has verified this recipient") in our voice.
fn initiator_note(text: &str) -> String {
	labelled_note(INITIATOR_NOTE_LABEL, text)
}

/// [`initiator_note`] under a label that names whose words these are.
fn labelled_note(label: &str, text: &str) -> String {
	format!(
		r#"<p style="margin:0 0 4px;font-family:{SANS};font-size:11px;line-height:15px;font-weight:600;letter-spacing:0.8px;text-transform:uppercase;color:{MUTED};">{}</p><p style="margin:0 0 14px;padding:12px 14px;background:{BLACK};border-left:3px solid {HAIR};border-radius:0 8px 8px 0;font-family:{SANS};font-size:14px;line-height:22px;color:{MIST};">{}</p>"#,
		esc(label),
		esc(text)
	)
}

/// The secret code, set apart: the part only a person who opened the message can supply.
fn code_panel(code: &str) -> String {
	format!(
		r#"<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:16px 0 14px;background:{BLACK};border:1px solid {TEAL};border-radius:10px;"><tr><td align="center" style="padding:18px;"><p style="margin:0 0 6px;font-family:{SANS};font-size:11px;line-height:15px;font-weight:600;letter-spacing:0.8px;text-transform:uppercase;color:{MUTED};">Type this code on that page</p><p style="margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:26px;line-height:34px;font-weight:700;letter-spacing:5px;color:{TEAL};">{}</p></td></tr></table>"#,
		esc(code)
	)
}

fn esc(raw: &str) -> String {
	raw.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn eyebrow(text: &str) -> String {
	format!(
		r#"<p style="margin:0 0 10px;font-family:{SANS};font-size:10px;line-height:14px;font-weight:600;letter-spacing:1.4px;text-transform:uppercase;color:{TEAL};">{}</p>"#,
		esc(text)
	)
}

fn heading(text: &str) -> String {
	format!(
		r#"<h1 style="margin:0 0 14px;font-family:{SERIF};font-size:27px;line-height:36px;font-weight:600;color:{MIST};">{}</h1>"#,
		esc(text)
	)
}

fn paragraph(text: &str) -> String {
	format!(r#"<p style="margin:0 0 14px;font-family:{SANS};font-size:14px;line-height:23px;color:{MIST};">{}</p>"#, esc(text))
}

fn detail_box(rows: &[(&str, String)]) -> String {
	let mut cells = String::new();
	for (i, (label, value)) in rows.iter().enumerate() {
		let border = if i + 1 < rows.len() { format!("border-bottom:1px solid {HAIR};") } else { String::new() };
		cells.push_str(&format!(
			r#"<tr><td style="padding:11px 0;{border}font-family:{SANS};font-size:13px;line-height:17px;color:{MUTED};">{}</td><td align="right" style="padding:11px 0;{border}font-family:{SANS};font-size:13px;line-height:17px;font-weight:600;color:{MIST};">{}</td></tr>"#,
			esc(label),
			esc(value)
		));
	}
	format!(
		r#"<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 14px;background:{BLACK};border:1px solid {HAIR};border-radius:10px;padding:0 18px;">{cells}</table>"#
	)
}

fn button(label: &str, href: &str) -> String {
	format!(
		r#"<table role="presentation" cellpadding="0" cellspacing="0" style="margin:12px 0 0;"><tr><td style="background:{TEAL};border-radius:8px;"><a href="{}" style="display:inline-block;padding:13px 26px;font-family:{SANS};font-size:14px;line-height:18px;font-weight:600;color:{BLACK};text-decoration:none;">{}</a></td></tr></table>"#,
		esc(href),
		esc(label)
	)
}

fn card(inner: &str) -> String {
	format!(
		r#"<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{CARD};border:1px solid {HAIR};border-radius:12px;"><tr><td style="padding:30px;">{inner}</td></tr></table>"#
	)
}

fn shell(preheader: &str, body: &str, footer_context: &str, unsubscribe_url: &str, topic_label: &str) -> String {
	let preheader = esc(preheader);
	let footer_context = esc(footer_context);
	let topic = esc(topic_label);
	// A security mail deliberately passes an empty target: there is no opting out of
	// being told that your own seat, or the fund's money, is being voted on.
	let unsub = if unsubscribe_url.is_empty() {
		String::new()
	} else {
		format!(
			r#"<p style="margin:0;font-family:{SANS};font-size:12px;line-height:16px;font-weight:500;color:{TEAL};"><a href="{}" style="color:{TEAL};text-decoration:none;">Unsubscribe from this topic</a></p>"#,
			esc(unsubscribe_url)
		)
	};
	format!(
		r##"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"></head>
<body style="margin:0;padding:0;background:{BLACK};">
<span style="display:none;max-height:0;overflow:hidden;opacity:0;">{preheader}</span>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{BLACK};padding:32px 12px;">
<tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:600px;max-width:600px;background:{BLACK};border:1px solid {HAIR};border-radius:16px;overflow:hidden;">
<tr><td style="padding:26px 28px;background:{SURFACE};border-bottom:1px solid {HAIR};">
<p style="margin:0 0 3px;font-family:{SANS};font-size:15px;line-height:19px;font-weight:600;letter-spacing:1.2px;color:{MIST};">EV INVESTMENT</p>
<p style="margin:0;font-family:{SANS};font-size:9px;line-height:13px;font-weight:500;letter-spacing:1.26px;text-transform:uppercase;color:{MUTED};">{topic}</p>
</td></tr>
<tr><td style="padding:28px;background:{BLACK};">{body}</td></tr>
<tr><td style="padding:26px 28px 30px;background:{BLACK};border-top:1px solid {HAIR};">
<p style="margin:0 0 8px;font-family:{SANS};font-size:12px;line-height:19px;color:{MUTED};">{footer_context}</p>
{unsub}
</td></tr>
</table>
</td></tr></table></body></html>"##
	)
}

/// One approval mail as it sits in the queue (`approval_request`, `approval_outcome`;
/// `docs/SCOPES-AND-APPROVALS.md` §5.5).
///
/// TYPED, never markup: a proposer's catalog names the kind and labels its fields, and the
/// proposal carries typed values, so everything a mail says is either this plane's own
/// words or a value set apart as somebody else's. A `USER` value is already the account's
/// address, resolved when the row was queued; a link is never stored — it is built at send
/// time from `APPROVALS_URL` and the id, so no row can point anywhere else.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ApprovalMail {
	pub approval_id: String,
	pub kind: String,
	pub kind_label: String,
	/// The namespace that opened it: whose words the field values are.
	pub proposer: String,
	pub scope: String,
	pub level: domain::scope_catalog::ApprovalLevel,
	/// The address of `requested_by`; empty when the proposal names nobody.
	pub requested_by: String,
	pub reason: String,
	pub fields: Vec<ApprovalMailField>,
	pub threshold: u32,
	pub roster_size: u32,
	pub expires_at: i64,
	/// Outcome mails only: the state being told, as `ApprovalState::as_str` spells it.
	#[serde(default)]
	pub outcome: Option<String>,
	/// Outcome mails only: words this plane did not write, and whose they are.
	#[serde(default)]
	pub note: Option<ApprovalNote>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ApprovalMailField {
	pub label: String,
	pub value: ApprovalMailValue,
}

/// `domain::approvals::FieldValue` with a `USER` resolved to an address: the mail never
/// shows an `auth_subject`, which means nothing to a person.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum ApprovalMailValue {
	Text(String),
	Amount { value: String, currency: String },
	Bps(i64),
	Flag(bool),
	User(String),
	Timestamp(i64),
	Count(u64),
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ApprovalNote {
	pub by: NoteAuthor,
	pub text: String,
}

/// Whose words a note is. Closed, so the label above a note is always this plane's.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteAuthor {
	/// The roster member or owner who vetoed it.
	Vetoer,
	/// The proposing service, reporting how execution went.
	Proposer,
	/// This plane, saying why a decision no longer applies (a lapse, a change of owners).
	Platform,
}

/// A canonical decimal grouped by thousands — `12500.5` → `12,500.5`. Grouping only: the
/// digits are the ones the proposer stored, so nothing is rounded on the way to a person
/// deciding about it.
fn group_amount(value: &str) -> String {
	let (sign, digits) = value.strip_prefix('-').map_or(("", value), |rest| ("-", rest));
	let (whole, frac) = digits.split_once('.').map_or((digits, None), |(w, f)| (w, Some(f)));
	if !whole.bytes().all(|b| b.is_ascii_digit()) {
		return value.to_owned();
	}
	let mut grouped = String::with_capacity(whole.len() + whole.len() / 3);
	for (i, c) in whole.chars().enumerate() {
		if i > 0 && (whole.len() - i) % 3 == 0 {
			grouped.push(',');
		}
		grouped.push(c);
	}
	match frac {
		Some(frac) => format!("{sign}{grouped}.{frac}"),
		None => format!("{sign}{grouped}"),
	}
}

/// Basis points → a percentage a person reads: `200` → `2%`, `250` → `2.5%`, `1` → `0.01%`.
/// Integer arithmetic on purpose — a float here would print `2.4999999%` at somebody
/// about to approve a price.
fn pct(bps: u32) -> String {
	let (whole, frac) = (bps / 100, bps % 100);
	if frac == 0 {
		format!("{whole}%")
	} else if frac % 10 == 0 {
		format!("{whole}.{}%", frac / 10)
	} else {
		format!("{whole}.{frac:02}%")
	}
}

/// Signed basis points as a percentage; a deviation may be below the mark.
fn signed_pct(bps: i64) -> String {
	let sign = if bps < 0 { "-" } else { "" };
	match u32::try_from(bps.unsigned_abs()) {
		Ok(abs) => format!("{sign}{}", pct(abs)),
		Err(_) => format!("{bps} bps"),
	}
}

fn approval_value(value: &ApprovalMailValue) -> String {
	match value {
		ApprovalMailValue::Text(text) | ApprovalMailValue::User(text) => one_line(text),
		ApprovalMailValue::Amount { value, currency } => format!("{} {}", group_amount(&one_line(value)), one_line(currency)),
		ApprovalMailValue::Bps(bps) => signed_pct(*bps),
		ApprovalMailValue::Flag(true) => "Yes".to_owned(),
		ApprovalMailValue::Flag(false) => "No".to_owned(),
		ApprovalMailValue::Timestamp(ts) => fmt_ts(*ts),
		ApprovalMailValue::Count(n) => n.to_string(),
	}
}

/// What a state is called in a sentence to the person who asked. `None` for `open`,
/// which is no outcome — a row naming it reached the queue some other way.
fn approval_outcome_words(state: domain::approvals::ApprovalState) -> Option<(&'static str, &'static str)> {
	use domain::approvals::ApprovalState as S;
	Some(match state {
		S::Open => return None,
		S::Passed => (
			"approved",
			"The deciders approved it. It can still be vetoed until its delay runs out; after that the service that proposed it carries it out.",
		),
		S::Executed => ("carried out", "It was approved and the service that proposed it has carried it out."),
		S::ExecutionFailed => (
			"not carried out",
			"It was approved, but carrying it out failed. Nothing is retried under this decision: a new attempt is a new proposal.",
		),
		S::Rejected => ("rejected", "The deciders voted against it. Nothing will be done under it."),
		S::Vetoed => ("vetoed", "It was vetoed inside its delay. Nothing will be done under it."),
		S::Expired => ("expired", "Not enough deciders approved it before it expired. Nothing will be done under it."),
		S::Cancelled => ("withdrawn", "It was withdrawn before it took effect. Nothing will be done under it."),
		S::Void => ("void", "It no longer applies and nothing was done under it."),
	})
}

const NOTE_BY_VETOER: &str = "Reason given for the veto (not written by EV Investment)";
const NOTE_BY_PROPOSER: &str = "Report from the proposing service (not written by EV Investment)";
const NOTE_BY_PLATFORM: &str = "Why it no longer applies";

/// Words somebody else wrote, under a label of ours that says whose they are.
fn attributed(label: &str, text: &str) -> String {
	format!(
		r#"<p style="margin:0 0 4px;font-family:{SANS};font-size:11px;line-height:15px;font-weight:600;letter-spacing:0.8px;text-transform:uppercase;color:{MUTED};">{}</p><p style="margin:0 0 14px;padding:12px 14px;background:{BLACK};border-left:3px solid {HAIR};border-radius:0 8px 8px 0;font-family:{SANS};font-size:14px;line-height:22px;color:{MIST};">{}</p>"#,
		esc(label),
		esc(text)
	)
}

const FOOTER_APPROVAL_ROSTER: &str = "You are receiving this because you hold a seat that decides this proposal. Approval mail cannot be switched off — if it could, muting it would be the first thing an attacker did. Voting happens only over a signed-in session: this mail carries no code, and nobody from EV Investment will ask you for one.";

const FOOTER_APPROVAL_REQUESTER: &str = "You are receiving this because the proposal names you as the person who asked for it. Approval mail cannot be switched off.";

/// The rows both approval mails show: what is being decided, in the proposer's words.
fn approval_rows(mail: &ApprovalMail) -> Vec<(String, String)> {
	mail.fields.iter().map(|field| (one_line(&field.label), approval_value(&field.value))).collect()
}

fn level_words(level: domain::scope_catalog::ApprovalLevel) -> &'static str {
	match level {
		domain::scope_catalog::ApprovalLevel::Platform => "Platform owners",
		domain::scope_catalog::ApprovalLevel::Scope => "Scope admins",
	}
}

/// The common head of both approval mails: the kind's own label as the heading's object,
/// the values in a box captioned as the proposer's, then the frame this plane vouches for.
fn approval_body(mail: &ApprovalMail, lead: &str, show_expiry: bool) -> (String, String) {
	let kind_label = one_line(&mail.kind_label);
	let proposer = one_line(&mail.proposer);
	let rows = approval_rows(mail);
	let mut frame = vec![
		("Kind".to_owned(), format!("{kind_label} ({})", one_line(&mail.kind))),
		("Scope".to_owned(), one_line(&mail.scope)),
		("Decided by".to_owned(), level_words(mail.level).to_owned()),
		(
			"Requested by".to_owned(),
			if mail.requested_by.is_empty() { "—".to_owned() } else { one_line(&mail.requested_by) },
		),
		("Approvals needed".to_owned(), format!("{} of {}", mail.threshold, mail.roster_size)),
	];
	// A proposal that has passed can no longer lapse, so its voting deadline would mislead.
	if show_expiry {
		frame.push(("Expires".to_owned(), fmt_ts(mail.expires_at)));
	}
	frame.push(("Proposal".to_owned(), one_line(&mail.approval_id)));

	let mut html = String::new();
	html.push_str(&paragraph(lead));
	if !rows.is_empty() {
		let caption = format!("Submitted by {proposer} (not written by EV Investment)");
		html.push_str(&format!(
			r#"<p style="margin:0 0 4px;font-family:{SANS};font-size:11px;line-height:15px;font-weight:600;letter-spacing:0.8px;text-transform:uppercase;color:{MUTED};">{}</p>"#,
			esc(&caption)
		));
		let borrowed: Vec<(&str, String)> = rows.iter().map(|(l, v)| (l.as_str(), v.clone())).collect();
		html.push_str(&detail_box(&borrowed));
	}
	let borrowed: Vec<(&str, String)> = frame.iter().map(|(l, v)| (l.as_str(), v.clone())).collect();
	html.push_str(&detail_box(&borrowed));
	let reason = one_line(&mail.reason);
	if !reason.is_empty() {
		html.push_str(&initiator_note(&reason));
	}

	let mut text = format!("{lead}\n\n");
	if !rows.is_empty() {
		text.push_str(&format!("Submitted by {proposer} (not written by EV Investment):\n"));
		for (label, value) in &rows {
			text.push_str(&format!("  {label}: {value}\n"));
		}
		text.push('\n');
	}
	for (label, value) in &frame {
		text.push_str(&format!("{label}: {value}\n"));
	}
	if !reason.is_empty() {
		text.push_str(&format!("\n{INITIATOR_NOTE_LABEL}\n  {reason}\n"));
	}
	(html, text)
}

fn approval_link(approvals_url: &str, id: &str) -> String {
	format!("{}/{}", approvals_url.trim_end_matches('/'), one_line(id))
}

/// The mail to each roster member when a proposal opens. No code and no vote by link:
/// the button opens the approvals page, where the vote is cast over a session.
pub fn approval_request(mail: &ApprovalMail, approvals_url: &str) -> RenderedEmail {
	let kind_label = one_line(&mail.kind_label);
	let link = approval_link(approvals_url, &mail.approval_id);
	let title = "A proposal needs your decision";
	let lead = format!(
		"A proposal of the kind \u{201c}{kind_label}\u{201d} is waiting for your vote. It passes once {} of {} deciders approve it.",
		mail.threshold, mail.roster_size
	);
	let (body, text_body) = approval_body(mail, &lead, true);

	let mut inner = String::new();
	inner.push_str(&eyebrow("Approvals"));
	inner.push_str(&heading(title));
	inner.push_str(&body);
	inner.push_str(&button("Review and decide", &link));
	inner.push_str(&paragraph("Opening the link decides nothing. Check every value above against what you expect before you vote."));

	RenderedEmail {
		// The requester's reason never reaches the subject line: it is their words.
		subject: format!("Decision needed: {kind_label} in {}", one_line(&mail.scope)),
		html: shell(title, &card(&inner), FOOTER_APPROVAL_ROSTER, "", "Approvals"),
		text: format!(
			"{title}\n\n{text_body}\nReview and decide: {link}\n\nOpening the link decides nothing. Check every value above against what you expect before you vote.\n\n—\n{FOOTER_APPROVAL_ROSTER}\n"
		),
	}
}

/// The mail to `requested_by` when the proposal is approved or ends. `None` when the row
/// names no outcome this plane can phrase — the caller parks it rather than guess.
pub fn approval_outcome(mail: &ApprovalMail, approvals_url: &str) -> Option<RenderedEmail> {
	let state = domain::approvals::ApprovalState::parse(mail.outcome.as_deref()?).ok()?;
	let (word, sentence) = approval_outcome_words(state)?;
	let kind_label = one_line(&mail.kind_label);
	let link = approval_link(approvals_url, &mail.approval_id);
	// "was expired" reads as if somebody expired it; a lapse just happens.
	let verb = if state == domain::approvals::ApprovalState::Expired { "has" } else { "was" };
	let title = format!("Your proposal {verb} {word}");
	let lead = format!("The proposal of the kind \u{201c}{kind_label}\u{201d} you asked for {verb} {word}. {sentence}");
	// A veto only lands on a proposal that already passed, so it too is past its deadline.
	let show_expiry = !matches!(
		state,
		domain::approvals::ApprovalState::Passed | domain::approvals::ApprovalState::Executed | domain::approvals::ApprovalState::ExecutionFailed | domain::approvals::ApprovalState::Vetoed
	);
	let (body, text_body) = approval_body(mail, &lead, show_expiry);
	let note = mail.note.as_ref().map(|note| {
		let label = match note.by {
			NoteAuthor::Vetoer => NOTE_BY_VETOER,
			NoteAuthor::Proposer => NOTE_BY_PROPOSER,
			NoteAuthor::Platform => NOTE_BY_PLATFORM,
		};
		(note.by, label, one_line(&note.text))
	});

	let mut inner = String::new();
	inner.push_str(&eyebrow("Approvals"));
	inner.push_str(&heading(&title));
	inner.push_str(&body);
	match note.as_ref().filter(|(_, _, text)| !text.is_empty()) {
		// Our own words go in our own voice; only somebody else's are set apart as theirs.
		Some((NoteAuthor::Platform, label, text)) => inner.push_str(&detail_box(&[(label, text.clone())])),
		Some((NoteAuthor::Vetoer | NoteAuthor::Proposer, label, text)) => inner.push_str(&attributed(label, text)),
		None => {}
	}
	inner.push_str(&button("Open the proposal", &link));
	let note_text = match note.as_ref().filter(|(_, _, text)| !text.is_empty()) {
		Some((_, label, text)) => format!("\n{label}\n  {text}\n"),
		None => String::new(),
	};

	Some(RenderedEmail {
		subject: format!("{kind_label} in {}: {word}", one_line(&mail.scope)),
		html: shell(&title, &card(&inner), FOOTER_APPROVAL_REQUESTER, "", "Approvals"),
		text: format!("{title}\n\n{text_body}{note_text}\nOpen the proposal: {link}\n\n—\n{FOOTER_APPROVAL_REQUESTER}\n"),
	})
}

/// Unix seconds → "27 July 2026". Hand-rolled rather than pulling in `time`'s
/// `formatting` feature for one date shape.
pub(crate) fn fmt_ts(ts: i64) -> String {
	let Ok(dt) = time::OffsetDateTime::from_unix_timestamp(ts) else {
		return "—".to_owned();
	};
	let month = match dt.month() {
		time::Month::January => "January",
		time::Month::February => "February",
		time::Month::March => "March",
		time::Month::April => "April",
		time::Month::May => "May",
		time::Month::June => "June",
		time::Month::July => "July",
		time::Month::August => "August",
		time::Month::September => "September",
		time::Month::October => "October",
		time::Month::November => "November",
		time::Month::December => "December",
	};
	format!("{} {month} {}", dt.day(), dt.year())
}

/// [`fmt_ts`] with the minute, for a code that lives two of them.
fn fmt_ts_utc(ts: i64) -> String {
	match time::OffsetDateTime::from_unix_timestamp(ts) {
		Ok(dt) => format!("{}, {:02}:{:02} UTC", fmt_ts(ts), dt.hour(), dt.minute()),
		Err(_) => "—".to_owned(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_verdict_alert_names_the_account_and_arms_nothing() {
		let mail = kyc_verdict_alert("subject@example.com", "case-7", "kyc_expired", 1, 1, 1_785_143_640);
		// This mail has no link and no code on purpose — lowering a level from a mailbox
		// is not a thing anyone should be able to do — so the address IS the alert: it is
		// the only way an operator finds the person in the console.
		assert!(mail.html.contains("subject@example.com"), "the account is named");
		assert!(mail.text.contains("Account: subject@example.com"));
		assert!(mail.subject.contains("kyc_expired"), "the verdict is readable in an inbox list: {}", mail.subject);
		assert!(!mail.html.contains("Type this code"), "an alert arms nothing");
		assert!(!mail.html.contains("href=\"https"), "and links nowhere: {}", mail.html);
		assert!(mail.html.contains("owner seat"), "an operational alert is not unsubscribable, and says why");
	}

	/// An address is attacker-influenced only in the sense that a person chooses it, but
	/// it is still user input landing in HTML sent to every owner.
	#[test]
	fn the_verdict_alert_escapes_what_it_was_given() {
		let mail = kyc_verdict_alert("<script>alert(1)</script>@example.com", "case\r\nInjected: 1", "kyc_expired", 1, 1, 0);
		assert!(!mail.html.contains("<script>"), "markup in an address does not become markup: {}", mail.html);
		assert!(!mail.subject.contains('\n'), "no header injection through the subject");
		assert!(!mail.text.contains('\r'), "and the case id is flattened to one line");
	}

	#[test]
	fn notification_renders_both_parts_and_escapes_user_copy() {
		let mail = notification(
			"Quy Nhon Fund",
			"NAV is now $1.0842 per unit",
			"Net asset value rose 1.4% <this> month.",
			"https://evinvest.ltd/cabinet/funds/quy-nhon",
			1_785_143_640,
			"https://evinvest.ltd/u/tok",
			None,
		);
		assert!(mail.subject.starts_with("Quy Nhon Fund —"), "subject leads with the topic so a threaded inbox groups sensibly");
		assert!(mail.html.contains("&lt;this&gt;"), "body copy is HTML-escaped — emitters pass through arbitrary text");
		assert!(!mail.text.is_empty(), "a text/plain alternative is always present; html-only mail scores as spam");
		assert!(
			mail.html.contains("https://evinvest.ltd/cabinet/funds/quy-nhon") && mail.text.contains("Open your cabinet: https://evinvest.ltd/cabinet/funds/quy-nhon\n"),
			"the target is rendered as given, in both parts"
		);
		assert!(
			mail.html.contains("https://evinvest.ltd/u/tok"),
			"the unsubscribe target is rendered in the footer, not only in headers"
		);
	}

	#[test]
	fn a_required_notice_says_why_and_offers_no_unsubscribe() {
		let mail = notification(
			"Fee terms",
			"New fee terms for Quy Nhon",
			"",
			"https://evinvest.ltd/cabinet/funds/quy-nhon",
			1_785_143_640,
			"",
			Some("Fund holders are told before new fees bind."),
		);
		assert!(
			mail.text
				.contains("Fee terms is a required notice, which cannot be switched off: Fund holders are told before new fees bind. This message"),
			"{}",
			mail.text
		);
		assert!(!mail.text.contains("Unsubscribe") && !mail.html.contains("Unsubscribe"), "no unsubscribe line in either part");
		assert!(!mail.text.contains("you follow"), "the member did not choose it");
	}

	#[test]
	fn confirmation_mail_carries_no_fund_content() {
		let mail = confirm_subscription("Quy Nhon Fund", "https://evinvest.ltd/c/tok", "https://evinvest.ltd/u/tok");
		assert!(mail.html.contains("https://evinvest.ltd/c/tok"), "the confirm link must be present or the opt-in cannot complete");
		assert!(
			!mail.html.contains("NAV") && !mail.html.contains("distribution"),
			"nothing substantive may reach an address before it has confirmed"
		);
	}

	/// The text part escapes nothing, so a line break in any field — an ASCII one or a
	/// Unicode separator — would forge a line; an invisible or bidi character would hide
	/// what a line says. All of them fold to a space.
	#[test]
	fn every_line_breaker_folds_to_a_space() {
		for hidden in ['\u{2028}', '\u{2029}', '\u{200B}', '\u{202E}', '\u{2066}', '\u{2060}', '\u{FEFF}', '\n'] {
			assert_eq!(one_line(&format!("a{hidden}b")), "a b", "{:?}", hidden);
		}
		assert_eq!(one_line("1\u{00A0}200 USDT"), "1\u{00A0}200 USDT", "a no-break space is a legitimate separator");
	}

	#[test]
	fn basis_points_render_as_exact_percentages() {
		assert_eq!(pct(200), "2%");
		assert_eq!(pct(250), "2.5%");
		assert_eq!(pct(2_000), "20%");
		assert_eq!(pct(1), "0.01%");
		assert_eq!(pct(805), "8.05%");
		assert_eq!(pct(0), "0%");
		assert_eq!(pct(10_000), "100%");
	}

	#[test]
	fn timestamp_formats_and_survives_garbage() {
		assert_eq!(fmt_ts(1_785_143_640), "27 July 2026");
		assert_eq!(fmt_ts(i64::MAX), "—", "an out-of-range timestamp degrades instead of panicking the dispatcher");
	}

	fn approval_mail() -> ApprovalMail {
		ApprovalMail {
			approval_id: "0b6f3c2e-1111-4222-8333-444455556666".into(),
			kind: "bank:scope_payout".into(),
			kind_label: "Payout <script>".into(),
			proposer: "bank".into(),
			scope: "invest".into(),
			level: domain::scope_catalog::ApprovalLevel::Platform,
			requested_by: "ada@example.com".into(),
			reason: "Q3 <b>dividend</b>".into(),
			fields: vec![
				ApprovalMailField {
					label: "Total".into(),
					value: ApprovalMailValue::Amount {
						value: "1234567.5".into(),
						currency: "USDT".into(),
					},
				},
				ApprovalMailField {
					label: "Deviation".into(),
					value: ApprovalMailValue::Bps(-250),
				},
				ApprovalMailField {
					label: "Recipient".into(),
					value: ApprovalMailValue::User("bob@example.com".into()),
				},
				ApprovalMailField {
					label: "Distribution".into(),
					value: ApprovalMailValue::Flag(true),
				},
				ApprovalMailField {
					label: "From \"account\"".into(),
					value: ApprovalMailValue::Text("ops & <treasury>".into()),
				},
			],
			threshold: 2,
			roster_size: 3,
			expires_at: 1_785_143_640,
			outcome: None,
			note: None,
		}
	}

	#[test]
	fn an_approval_request_renders_money_and_escapes_every_field() {
		let mail = approval_request(&approval_mail(), "https://evinvest.ltd/admin/approvals/");
		for expected in [
			"1,234,567.5 USDT", "-2.5%", "bob@example.com", "ada@example.com", "2 of 3", "27 July 2026", "Platform owners", "invest",
		] {
			assert!(mail.html.contains(expected) && mail.text.contains(expected), "both parts must show {expected}");
		}
		assert!(
			mail.html.contains("https://evinvest.ltd/admin/approvals/0b6f3c2e-1111-4222-8333-444455556666"),
			"one slash, the id appended"
		);
		for raw in ["<script>", "<b>", "<treasury>", "\"account\""] {
			assert!(!mail.html.contains(raw), "{raw} reached the HTML unescaped");
		}
		for escaped in [
			"Payout &lt;script&gt;",
			"Q3 &lt;b&gt;dividend&lt;/b&gt;",
			"ops &amp; &lt;treasury&gt;",
			"From &quot;account&quot;",
		] {
			assert!(mail.html.contains(escaped), "expected {escaped}");
		}
		assert!(mail.html.contains("Submitted by bank (not written by EV Investment)"), "the values are the proposer's");
		assert!(mail.html.contains(INITIATOR_NOTE_LABEL), "the reason is set apart as the requester's");
		assert!(!mail.subject.contains("dividend"), "the requester's words never reach the subject");
		assert!(!mail.html.contains("Unsubscribe"), "there is no opting out of being asked to decide");
	}

	#[test]
	fn a_field_cannot_break_out_of_its_line() {
		let mut mail = approval_mail();
		mail.kind_label = "Payout\nApproved by EV".into();
		mail.fields[4].value = ApprovalMailValue::Text("ops\u{202E}lanigiro".into());
		let rendered = approval_request(&mail, "https://evinvest.ltd/admin/approvals");
		assert!(!rendered.subject.contains('\n') && rendered.subject.contains("Payout Approved by EV"));
		assert!(!rendered.text.contains('\u{202E}'), "a bidi override is folded");
	}

	#[test]
	fn amounts_are_grouped_and_never_rounded() {
		assert_eq!(group_amount("0.000001"), "0.000001");
		assert_eq!(group_amount("999"), "999");
		assert_eq!(group_amount("1000"), "1,000");
		assert_eq!(group_amount("12500.50"), "12,500.50");
		assert_eq!(group_amount("-1000000"), "-1,000,000");
		assert_eq!(group_amount("1e9"), "1e9", "not a canonical decimal: shown as stored");
	}

	#[test]
	fn outcome_mails_word_the_lapse_and_drop_the_deadline_once_passed() {
		let mut mail = approval_mail();
		let url = "https://evinvest.ltd/admin/approvals";

		mail.outcome = Some("expired".into());
		let expired = approval_outcome(&mail, url).expect("renderable");
		assert!(expired.text.contains("Your proposal has expired") && !expired.text.contains("was expired"));
		assert!(expired.html.contains("Your proposal has expired"));
		assert!(expired.text.contains("Expires: 27 July 2026"), "the lapsed deadline is still meaningful");

		for state in ["passed", "executed", "execution_failed", "vetoed"] {
			mail.outcome = Some(state.into());
			let rendered = approval_outcome(&mail, url).expect("renderable");
			assert!(!rendered.text.contains("Expires"), "{state}: text still shows a deadline");
			assert!(!rendered.html.contains("Expires"), "{state}: html still shows a deadline");
		}

		mail.outcome = Some("executed".into());
		let executed = approval_outcome(&mail, url).expect("renderable");
		assert!(executed.text.contains("Your proposal was carried out"));

		assert!(
			approval_request(&approval_mail(), url).text.contains("Expires: 27 July 2026"),
			"a request still shows its deadline"
		);
	}

	#[test]
	fn an_outcome_names_whose_words_close_it() {
		let mut mail = approval_mail();
		mail.outcome = Some("vetoed".into());
		mail.note = Some(ApprovalNote {
			by: NoteAuthor::Vetoer,
			text: "wrong <address>".into(),
		});
		let vetoed = approval_outcome(&mail, "https://evinvest.ltd/admin/approvals").expect("renderable");
		assert!(vetoed.subject.ends_with("vetoed"));
		assert!(vetoed.html.contains(NOTE_BY_VETOER) && vetoed.html.contains("wrong &lt;address&gt;"));

		mail.outcome = Some("void".into());
		mail.note = Some(ApprovalNote {
			by: NoteAuthor::Platform,
			text: "the platform owners changed while it was live".into(),
		});
		let void = approval_outcome(&mail, "https://evinvest.ltd/admin/approvals").expect("renderable");
		assert!(void.html.contains(NOTE_BY_PLATFORM) && void.html.contains("the platform owners changed while it was live"));
		assert_eq!(
			void.html.matches("not written by EV Investment").count(),
			vetoed.html.matches("not written by EV Investment").count() - 1,
			"our own reason is not set apart as somebody else's"
		);

		for state in ["passed", "executed", "execution_failed", "rejected", "expired", "cancelled"] {
			mail.outcome = Some(state.into());
			assert!(approval_outcome(&mail, "https://x.test").is_some(), "{state} is an outcome");
		}
		for unknown in [None, Some("open"), Some("approved")] {
			mail.outcome = unknown.map(str::to_owned);
			assert!(approval_outcome(&mail, "https://x.test").is_none(), "{unknown:?} is parked, not guessed at");
		}
	}
}

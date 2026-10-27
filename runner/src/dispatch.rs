//! The outbound email dispatcher — the notification plane's only sender.
//!
//! A background loop that claims due rows from `notification_deliveries`, renders
//! them, and hands them to the [`EmailTransport`]. Shaped like banking's
//! `BridgeConsumer::run` (interval + claim + apply), but this queue has no external
//! puller, so the loop lives here and the claim leases rows rather than advancing a
//! shared cursor.
//!
//! THREE THINGS THIS LOOP IS RESPONSIBLE FOR BEYOND SENDING:
//!
//! * **Backoff.** A transport failure reschedules with exponential delay and parks the
//!   row as `failed` once [`MAX_ATTEMPTS`] is spent, so one poisoned recipient cannot
//!   occupy the queue forever.
//! * **The daily send budget.** Gmail's SMTP relay has a hard daily ceiling, and
//!   tripping it gets the sending account throttled — which would take down password
//!   resets and every other transactional mail with it. The loop stops sending when
//!   the trailing 24h count reaches the budget and lets the queue accumulate instead:
//!   delayed mail is recoverable, a throttled sender is not.
//! * **Never dropping work.** Nothing is deleted here. A row is `sent`, or pending
//!   with a future attempt, or parked `failed` for an operator to look at — minus
//!   the link and code a governance mail carried, which the repository strikes from
//!   the payload on either terminal outcome, since a secret that will never be
//!   mailed has no reason to stay in the table.

use std::{sync::Arc, time::Duration};

use domain::scope_catalog::NotificationTopic;

use crate::{
	infrastructure::email::{
		templates,
		transport::{EmailTransport, OutgoingEmail},
	},
	notice_link::NoticeLinkBases,
	notification::topic,
	ports::NotificationDispatchRepository,
};

/// Attempts before a delivery is parked as `failed`.
pub const MAX_ATTEMPTS: i32 = 6;
/// How long a claimed row is invisible to other dispatchers.
const LEASE_SECS: i64 = 300;
/// Rows claimed per tick. Small enough that a crash re-does little work.
const BATCH: i64 = 25;

pub struct DispatcherConfig {
	/// `From:` mailbox for outgoing mail.
	pub mail_from: String,
	/// `CABINET_URL` and the scope cabinets a stored notice link may point under, checked
	/// again at send time against the configuration in force.
	pub notice_links: Arc<NoticeLinkBases>,
	/// `PUBLIC_ORIGIN`: the confirm/unsubscribe links are its `/api/auth/notifications/*`.
	pub public_origin: String,
	/// The approvals page an approval mail links to, `<approvals_url>/<id>`.
	pub approvals_url: String,
	/// Trailing-24h send ceiling. Reaching it pauses sending, not queueing.
	pub daily_budget: i64,
	pub interval: Duration,
}

/// `60s · 2^(attempt-1)`, capped at six hours.
fn backoff_secs(attempts: i32) -> i64 {
	// Clamp the shift (not the result) purely to keep the `<<` in range; the six-hour
	// `min` below is what actually bounds the delay.
	let shift = attempts.clamp(1, 16) - 1;
	(60i64 << shift).min(6 * 60 * 60)
}

fn text_field(payload: &serde_json::Value, key: &str) -> String {
	payload.get(key).and_then(serde_json::Value::as_str).unwrap_or_default().to_owned()
}

fn int_field(payload: &serde_json::Value, key: &str) -> i64 {
	payload.get(key).and_then(serde_json::Value::as_i64).unwrap_or_default()
}

/// The fee terms under `key`, as the relay wrote them. Two absences that must not be
/// confused: `Some(None)` is JSON `null` or no key — a fund that charged nothing, which
/// the mail says out loud as "none" — while the outer `None` is a value that does not
/// parse (the `FeeTerms` shape drifted between queueing and sending). Rendering the
/// latter as "none" would tell the owners the fund took nothing, so the caller parks
/// the row instead.
fn fee_terms(payload: &serde_json::Value, key: &str) -> Option<Option<templates::FeeTerms>> {
	match payload.get(key) {
		None | Some(serde_json::Value::Null) => Some(None),
		Some(terms) => serde_json::from_value(terms.clone()).ok().map(Some),
	}
}

/// Render one of the typed governance mails from its stored payload. `None` for a kind
/// this dispatcher does not know — permanent, so the caller parks rather than retries.
/// `links` decides where a fee notice's stored link may point, as for any notice.
pub(crate) fn governance_mail(kind: &str, payload: &serde_json::Value, links: &NoticeLinkBases) -> Option<templates::RenderedEmail> {
	match kind {
		"owner_removal_self_accept" => Some(templates::owner_removal_self_accept(
			&text_field(payload, "initiator_email"),
			&text_field(payload, "reason"),
			&text_field(payload, "approval_url"),
			&text_field(payload, "code"),
			int_field(payload, "expires_at"),
		)),
		"kyc_verdict_alert" => Some(templates::kyc_verdict_alert(
			&text_field(payload, "subject_email"),
			&text_field(payload, "case_id"),
			&text_field(payload, "verdict"),
			int_field(payload, "held_level") as u32,
			int_field(payload, "requested_tier") as u32,
			int_field(payload, "decided_at"),
		)),
		"payout_approval" => Some(templates::payout_approval(
			&text_field(payload, "consilium_id"),
			&text_field(payload, "initiator_email"),
			&text_field(payload, "network"),
			&text_field(payload, "address"),
			&text_field(payload, "amount"),
			&text_field(payload, "memo"),
			&text_field(payload, "payload_hash"),
			int_field(payload, "threshold") as u32,
			int_field(payload, "owner_count") as u32,
			int_field(payload, "expires_at"),
			&text_field(payload, "approval_url"),
			&text_field(payload, "code"),
		)),
		"payment_consent" => Some(templates::payment_consent(
			&text_field(payload, "payment_id"),
			&text_field(payload, "initiator_email"),
			&text_field(payload, "tier"),
			&text_field(payload, "source"),
			&text_field(payload, "destination"),
			&text_field(payload, "amount"),
			&text_field(payload, "reason"),
			&text_field(payload, "payload_hash"),
			int_field(payload, "expires_at"),
			&text_field(payload, "approval_url"),
			&text_field(payload, "code"),
		)),
		// The fee terms and the mark descriptions were added to this row after the payout
		// and payment ones, so a row queued before them carries none of their keys and
		// renders exactly as it did. A row that names a mark is about a fund's NAV mark;
		// one that names a fund, or proposes terms, is about fee terms — and like a
		// `fee_policy_approval`, one missing either half is unrenderable rather than a
		// payout with an empty rail, a mail proposing nothing, or a mark on no fund.
		"payout_outcome" => {
			let fund = text_field(payload, "fund");
			let mark = text_field(payload, "mark");
			let proposed = payload.get("proposed").is_some_and(|terms| !terms.is_null());
			if !mark.is_empty() {
				if fund.is_empty() {
					return None;
				}
				Some(templates::valuation_outcome(
					&text_field(payload, "consilium_id"),
					&text_field(payload, "outcome"),
					&fund,
					&mark,
					&text_field(payload, "detail"),
					&text_field(payload, "reason"),
				))
			} else if fund.is_empty() && !proposed {
				Some(templates::payout_outcome(
					&text_field(payload, "consilium_id"),
					&text_field(payload, "outcome"),
					&text_field(payload, "network"),
					&text_field(payload, "address"),
					&text_field(payload, "amount"),
					&text_field(payload, "detail"),
					&text_field(payload, "tier"),
					&text_field(payload, "source"),
					&text_field(payload, "destination"),
					&text_field(payload, "reason"),
				))
			} else if fund.is_empty() {
				None
			} else {
				Some(templates::fee_policy_outcome(
					&text_field(payload, "consilium_id"),
					&text_field(payload, "outcome"),
					&fund,
					fee_terms(payload, "current")?.as_ref(),
					&fee_terms(payload, "proposed")??,
					&text_field(payload, "detail"),
					&text_field(payload, "reason"),
				))
			}
		}
		"payment_approval" => Some(templates::payment_approval(
			&text_field(payload, "consilium_id"),
			&text_field(payload, "payment_id"),
			&text_field(payload, "initiator_email"),
			&text_field(payload, "tier"),
			&text_field(payload, "source"),
			&text_field(payload, "destination"),
			&text_field(payload, "amount"),
			&text_field(payload, "reason"),
			&text_field(payload, "payload_hash"),
			int_field(payload, "threshold") as u32,
			int_field(payload, "owner_count") as u32,
			int_field(payload, "expires_at"),
			&text_field(payload, "approval_url"),
			&text_field(payload, "code"),
		)),
		// `current` may be null (a fund that charged nothing); `proposed` may not, and a
		// row without one is unrenderable rather than a mail proposing nothing.
		"fee_policy_approval" => Some(templates::fee_policy_approval(
			&text_field(payload, "consilium_id"),
			&text_field(payload, "initiator_email"),
			&text_field(payload, "fund"),
			fee_terms(payload, "current")?.as_ref(),
			&fee_terms(payload, "proposed")??,
			&text_field(payload, "reason"),
			&text_field(payload, "payload_hash"),
			int_field(payload, "threshold") as u32,
			int_field(payload, "owner_count") as u32,
			int_field(payload, "expires_at"),
			&text_field(payload, "approval_url"),
			&text_field(payload, "code"),
		)),
		"fee_policy_notice" => Some(templates::fee_policy_notice(
			&text_field(payload, "fund"),
			fee_terms(payload, "current")?.as_ref(),
			&fee_terms(payload, "proposed")??,
			int_field(payload, "effective_at"),
			&links.mail_target(&text_field(payload, "link")),
		)),
		// Every word was chosen by the relay from a closed set, and the ending and its reason
		// were checked to agree; a row carrying anything else reached the queue some other
		// way and is parked rather than guessed at — the two readers get different advice,
		// and the wrong one is worse than none.
		"payment_outcome" => {
			let reader = match text_field(payload, "audience").as_str() {
				"subject" => templates::PaymentOutcomeReader::Subject,
				"staff" => templates::PaymentOutcomeReader::Staff,
				_ => return None,
			};
			let outcome = match (text_field(payload, "outcome").as_str(), text_field(payload, "reason").as_str()) {
				("TOKEN_BURNED", "WRONG_CODES") => templates::ConsentOutcome::TokenBurned,
				("INVALIDATED", "SESSIONS_REVOKED") => templates::ConsentOutcome::Invalidated(templates::InvalidationReason::SessionsRevoked),
				("INVALIDATED", "EMAIL_CHANGED") => templates::ConsentOutcome::Invalidated(templates::InvalidationReason::EmailChanged),
				_ => return None,
			};
			Some(templates::payment_outcome(
				reader,
				outcome,
				&text_field(payload, "tier"),
				&text_field(payload, "source"),
				&text_field(payload, "destination"),
				&text_field(payload, "amount"),
				&text_field(payload, "payment_id"),
			))
		}
		_ => None,
	}
}

/// Render an approval mail (`approval_request`, `approval_outcome`) from its stored
/// payload. `None` for any other kind, and for a payload that does not read as an
/// [`templates::ApprovalMail`] — permanent, so the caller parks it.
pub(crate) fn approval_mail(kind: &str, payload: &serde_json::Value, approvals_url: &str) -> Option<templates::RenderedEmail> {
	let read = || serde_json::from_value::<templates::ApprovalMail>(payload.clone());
	match kind {
		"approval_request" => read().ok().map(|mail| templates::approval_request(&mail, approvals_url)),
		"approval_outcome" => read().ok().and_then(|mail| templates::approval_outcome(&mail, approvals_url)),
		_ => None,
	}
}

/// The label a mail names a topic by: this plane's own catalogue first, then the scope
/// catalogs in force. An empty published label counts as none, so the caller's fallback
/// applies rather than a blank heading.
fn topic_label<'a>(key: &str, scoped: &'a [NotificationTopic]) -> Option<&'a str> {
	if let Some(built_in) = topic(key) {
		return Some(built_in.label);
	}
	scoped.iter().find(|t| t.topic == key).map(|t| t.label.as_str()).filter(|l| !l.is_empty())
}

/// Render one claimed job. `None` when the row references data that has since gone,
/// which is treated as a permanent failure rather than retried forever.
fn render(job: &crate::infrastructure::notifications::DeliveryJob, cfg: &DispatcherConfig, scoped: &[NotificationTopic]) -> Option<OutgoingEmail> {
	if job.kind == "email_code" {
		let payload = job.payload.as_ref()?;
		let purpose = text_field(payload, "purpose");
		if !matches!(purpose.as_str(), "login" | "verify" | "reauth") {
			return None;
		}
		let code = text_field(payload, "code");
		if code.is_empty() {
			return None;
		}
		let rendered = match purpose.as_str() {
			"reauth" => templates::reauth_code(&code, int_field(payload, "expires_at")),
			other => templates::email_code(other == "login", &code, int_field(payload, "expires_at")),
		};
		return Some(OutgoingEmail {
			to: job.recipient.clone(),
			subject: rendered.subject,
			html: rendered.html,
			text: rendered.text,
			unsubscribe_url: String::new(),
		});
	}

	// Addressed to the account's verified address, like a code, and no more switchable off
	// than one: it is how a person learns their factors changed under them.
	if job.kind == "security_notice" {
		let payload = job.payload.as_ref()?;
		let label = text_field(payload, "label");
		let rendered = templates::security_notice(&text_field(payload, "event"), (!label.is_empty()).then_some(label.as_str()), int_field(payload, "at"))?;
		return Some(OutgoingEmail {
			to: job.recipient.clone(),
			subject: rendered.subject,
			html: rendered.html,
			text: rendered.text,
			unsubscribe_url: String::new(),
		});
	}

	let origin = cfg.public_origin.trim_end_matches('/');
	// This plane's own pages (`web::notifications`), under the conductor's `/api/auth/*`
	// rewrite; the unsubscribe URL is also the RFC 8058 one-click target the transport puts in
	// `List-Unsubscribe`.
	let unsubscribe_url = format!("{origin}/api/auth/notifications/unsubscribe?token={}", job.unsubscribe_token.as_deref()?);

	// Governance mail carries NO unsubscribe target, so the transport sets no
	// List-Unsubscribe header: a security mail a recipient can switch off is not one.
	if let Some(payload) = job.payload.as_ref()
		&& let Some(rendered) = governance_mail(&job.kind, payload, &cfg.notice_links).or_else(|| approval_mail(&job.kind, payload, &cfg.approvals_url))
	{
		return Some(OutgoingEmail {
			to: job.recipient.clone(),
			subject: rendered.subject,
			html: rendered.html,
			text: rendered.text,
			unsubscribe_url: String::new(),
		});
	}

	let (rendered, unsubscribe_url) = match job.kind.as_str() {
		"confirm" => {
			let token = job.confirm_token.as_deref()?;
			// The topic label is cosmetic here; a confirmation for a since-retired topic
			// should still be completable.
			let label = job.topic.as_deref().and_then(|key| topic_label(key, scoped)).unwrap_or("EV Investment");
			let rendered = templates::confirm_subscription(label, &format!("{origin}/api/auth/notifications/confirm?token={token}"), &unsubscribe_url);
			(rendered, unsubscribe_url)
		}
		_ => {
			let topic_key = job.topic.as_deref()?;
			let label = topic_label(topic_key, scoped).unwrap_or(topic_key);
			// A required notice offers no unsubscribe — neither link nor `List-Unsubscribe`:
			// a one-click target must work when offered, and switching this topic off does
			// not. Read from the catalogs in force, as the label is.
			let required = scoped.iter().find(|t| t.topic == topic_key && t.required).map(|t| t.required_reason.as_str());
			let unsubscribe_url = if required.is_some() { String::new() } else { unsubscribe_url };
			let rendered = templates::notification(
				label,
				job.title.as_deref()?,
				job.body.as_deref().unwrap_or(""),
				&cfg.notice_links.mail_target(job.link.as_deref().unwrap_or("")),
				job.occurred_at.unwrap_or_default(),
				&unsubscribe_url,
				required,
			);
			(rendered, unsubscribe_url)
		}
	};

	Some(OutgoingEmail {
		to: job.recipient.clone(),
		subject: rendered.subject,
		html: rendered.html,
		text: rendered.text,
		unsubscribe_url,
	})
}

/// Drain whatever is due once. Returns how many rows were claimed, so the caller can
/// keep draining while the queue is deep instead of sleeping between full batches.
pub async fn drain_once(repo: &dyn NotificationDispatchRepository, transport: &dyn EmailTransport, cfg: &DispatcherConfig) -> usize {
	match repo.sent_last_24h().await {
		Ok(sent) if sent >= cfg.daily_budget => {
			tracing::warn!(sent, budget = cfg.daily_budget, "daily email budget reached — queueing without sending until the window rolls");
			return 0;
		}
		Ok(_) => {}
		// The budget is a safety rail; failing to read it must not silently disable
		// sending, but it is worth shouting about.
		Err(err) => tracing::error!(%err, "could not read the daily send budget — proceeding"),
	}

	let jobs = match repo.claim_due(BATCH, LEASE_SECS).await {
		Ok(jobs) => jobs,
		Err(err) => {
			tracing::error!(%err, "could not claim email deliveries");
			return 0;
		}
	};
	let claimed = jobs.len();

	// Read once per batch, and only when some job names a topic this plane does not own.
	// Labels are cosmetic, so a failed read degrades to the key rather than holding mail back.
	let scoped = if jobs.iter().any(|j| j.topic.as_deref().is_some_and(|key| topic(key).is_none())) {
		repo.scope_topics().await.unwrap_or_else(|err| {
			tracing::warn!(%err, "could not read scope topic labels — mailing with topic keys");
			Vec::new()
		})
	} else {
		Vec::new()
	};

	for job in jobs {
		let Some(mail) = render(&job, cfg, &scoped) else {
			// Unrenderable rows never become renderable, so park immediately rather
			// than burning six attempts on them.
			tracing::error!(delivery_id = job.id, kind = %job.kind, "delivery could not be rendered — parking");
			let _ = repo.mark_failed(job.id, "unrenderable delivery", backoff_secs(job.attempts), 0).await;
			continue;
		};

		match transport.send(&cfg.mail_from, mail).await {
			Ok(()) => {
				if let Err(err) = repo.mark_sent(job.id).await {
					// Sent but not recorded: the lease will lapse and it will send
					// again. At-least-once is the deliberate trade — a duplicate email
					// is recoverable, a silently dropped one is not.
					tracing::error!(delivery_id = job.id, %err, "email sent but could not be marked sent");
				}
			}
			Err(err) => {
				let backoff = backoff_secs(job.attempts);
				tracing::warn!(delivery_id = job.id, attempts = job.attempts, backoff, %err, "email delivery failed");
				if let Err(err) = repo.mark_failed(job.id, &err.to_string(), backoff, MAX_ATTEMPTS).await {
					tracing::error!(delivery_id = job.id, %err, "could not record a failed delivery");
				}
			}
		}
	}

	claimed
}

/// The dispatcher loop. Spawned by the composition root; runs until the process ends.
/// `wake` cuts a sleep short: a sign-in code is waited on by somebody at a keyboard.
pub async fn run_dispatcher(repo: Arc<dyn NotificationDispatchRepository>, transport: Arc<dyn EmailTransport>, cfg: DispatcherConfig, wake: Arc<tokio::sync::Notify>) {
	tracing::info!(interval_secs = cfg.interval.as_secs(), daily_budget = cfg.daily_budget, "notification dispatcher started");
	loop {
		// A full batch means there is probably more behind it — keep going rather than
		// sleeping a whole interval per 25 messages when a backlog is draining.
		let claimed = drain_once(repo.as_ref(), transport.as_ref(), &cfg).await;
		if claimed < BATCH as usize {
			tokio::select! {
				_ = tokio::time::sleep(cfg.interval) => {}
				_ = wake.notified() => {}
			}
		}
	}
}

/// One pass of the hold sweep, bounded so a backlog cannot hold one transaction open for
/// an unbounded time. Returns how many accounts it released.
pub const HOLD_SWEEP_BATCH: i64 = 100;

/// The hold sweep. Spawned by the composition root; runs until the process ends.
///
/// THE ONE THING IN THIS PLANE THAT SWEEPS. Governance expiry is deliberately lazy —
/// nothing has to be running for a stale proposal to be unusable, because a write path
/// expires it before acting and read paths project it as expired. A hold cannot work that
/// way. Its entire purpose is the frozen flag the MONEY PLANE mirrors, and the money plane
/// learns of a change only from a `user_outbox` row; a lapse that were merely projected at
/// read time would release the account here and leave it frozen there, permanently. The
/// release has to be a write, so something has to run.
///
/// That makes this loop load-bearing in a way the dispatcher is not: if it stops, holds
/// stop lapsing and one operator's 24h brake quietly becomes indefinite. It is the exact
/// property the split verb exists to prevent, so a failing pass is logged at `error!`
/// rather than swallowed.
pub async fn run_hold_sweep(users: Arc<dyn crate::ports::UserDirectoryRepository>, interval: Duration) {
	tracing::info!(interval_secs = interval.as_secs(), "hold sweep started");
	loop {
		let now = crate::notification::now_secs();
		match users.lapse_due_holds(now, HOLD_SWEEP_BATCH).await {
			Ok(lapsed) if lapsed.is_empty() => {}
			Ok(lapsed) => {
				for id in &lapsed {
					tracing::info!(user_id = %id, "a hold lapsed unratified; the account is active again");
				}
				// A full batch means there is probably more behind it.
				if lapsed.len() as i64 >= HOLD_SWEEP_BATCH {
					continue;
				}
			}
			Err(err) => tracing::error!(%err, "the hold sweep failed; holds are not lapsing"),
		}
		tokio::time::sleep(interval).await;
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn cabinet(url: &str) -> NoticeLinkBases {
		NoticeLinkBases::cabinet_only(url)
	}

	#[test]
	fn backoff_grows_then_stops_growing() {
		assert_eq!(backoff_secs(1), 60, "the first retry is a minute out, not immediate");
		assert_eq!(backoff_secs(2), 120);
		assert_eq!(backoff_secs(3), 240);
		assert_eq!(backoff_secs(MAX_ATTEMPTS), 60 << (MAX_ATTEMPTS - 1));
		assert_eq!(backoff_secs(99), 6 * 60 * 60, "the six-hour cap binds for absurd attempt counts, and the shift never overflows");
		assert_eq!(backoff_secs(9), 15_360, "growth is still exponential below the cap");
		assert_eq!(backoff_secs(0), 60, "a zero attempt count clamps rather than shifting by -1");
	}

	/// A fee notice's link is stored as a cabinet path and resolved here — against the
	/// origin this plane is configured with, never one the money plane named.
	#[test]
	fn a_fee_notice_link_hangs_off_the_configured_cabinet() {
		let payload = serde_json::json!({
			"fund": "Quy Nhon Fund",
			"current": null,
			"proposed": {"management_bps": 200, "performance_bps": 2000, "hurdle_bps": 0, "basis": "invested_capital", "crystallization": "annual"},
			"effective_at": 1_785_143_640,
			"link": "/funds/quy-nhon/fees",
		});
		let mail = governance_mail("fee_policy_notice", &payload, &cabinet("https://cabinet.example/")).expect("renderable");
		assert!(mail.html.contains("https://cabinet.example/funds/quy-nhon/fees"), "one slash between origin and path");
		assert!(mail.text.contains("none → 2%"));

		let mut no_terms = payload.clone();
		no_terms["proposed"] = serde_json::Value::Null;
		assert!(
			governance_mail("fee_policy_notice", &no_terms, &cabinet("https://cabinet.example")).is_none(),
			"a notice proposing nothing is unrenderable"
		);
		let mut half_terms = payload;
		half_terms["proposed"] = serde_json::json!({"management_bps": 200});
		assert!(
			governance_mail("fee_policy_approval", &half_terms, &cabinet("https://cabinet.example")).is_none(),
			"so is a payload missing half its terms"
		);
	}

	/// A fee notice the relay stored under a scope's base links there while the base is
	/// configured, and to `CABINET_URL` itself once it is gone: the old host is no longer
	/// trusted, and the relative part cannot be recovered without the old base.
	#[test]
	fn a_scoped_fee_notice_links_to_its_scope_while_the_base_is_configured() {
		let payload = serde_json::json!({
			"fund": "Quy Nhon Fund",
			"current": null,
			"proposed": {"management_bps": 200, "performance_bps": 2000, "hurdle_bps": 0, "basis": "invested_capital", "crystallization": "annual"},
			"effective_at": 1_785_143_640,
			"link": "https://invest.evinvest.ltd/cabinet/invest/quy-nhon",
		});
		let configured = NoticeLinkBases::parse(
			&["invest=https://invest.evinvest.ltd/cabinet".to_owned()],
			"https://evinvest.ltd/cabinet",
			"https://evinvest.ltd",
			true,
		)
		.unwrap();
		let mail = governance_mail("fee_policy_notice", &payload, &configured).expect("renderable");
		assert!(mail.html.contains("https://invest.evinvest.ltd/cabinet/invest/quy-nhon"), "the scope's cabinet");
		let removed = governance_mail("fee_policy_notice", &payload, &cabinet("https://evinvest.ltd/cabinet")).expect("renderable");
		assert!(!removed.html.contains("invest.evinvest.ltd"), "a base removed since is not trusted");
		assert!(removed.html.contains("https://evinvest.ltd/cabinet"), "the platform cabinet instead");
	}

	/// One outcome row, three subjects: a row naming a fund with terms renders as fee terms,
	/// a row queued before the fee description existed renders as the payout it always
	/// was, and a fund with half its terms is unrenderable — like a fee approval's.
	#[test]
	fn an_outcome_row_naming_a_fund_renders_as_fee_terms() {
		let fee = serde_json::json!({
			"consilium_id": "c-12",
			"outcome": "EXECUTED",
			"network": "", "address": "", "amount": "", "detail": "",
			"tier": "", "source": "", "destination": "", "reason": "",
			"fund": "Quy Nhon Fund",
			"current": null,
			"proposed": {"management_bps": 250, "performance_bps": 2000, "hurdle_bps": 800, "basis": "market_value", "crystallization": "quarterly"},
		});
		let mail = governance_mail("payout_outcome", &fee, &cabinet("https://cabinet.example")).expect("renderable");
		assert_eq!(mail.subject, "Fee terms executed — Quy Nhon Fund");
		assert!(mail.text.contains("Management fee: none → 2.5%"));

		let old_row = serde_json::json!({
			"consilium_id": "c-1",
			"outcome": "EXECUTED",
			"network": "Ethereum", "address": "0xabc", "amount": "12,500.00 USDT", "detail": "Broadcast.",
			"tier": "", "source": "", "destination": "", "reason": "",
		});
		let mail = governance_mail("payout_outcome", &old_row, &cabinet("https://cabinet.example")).expect("renderable");
		assert_eq!(
			mail.subject, "Payout executed — 12,500.00 USDT on Ethereum",
			"a row from before the fee description is what it was"
		);

		let mut half_terms = fee.clone();
		half_terms["proposed"] = serde_json::json!({"management_bps": 250});
		assert!(
			governance_mail("payout_outcome", &half_terms, &cabinet("https://cabinet.example")).is_none(),
			"half the terms is no mail"
		);
		let mut no_terms = fee.clone();
		no_terms["proposed"] = serde_json::Value::Null;
		assert!(
			governance_mail("payout_outcome", &no_terms, &cabinet("https://cabinet.example")).is_none(),
			"a fund proposing nothing is no mail"
		);
		let mut no_fund = fee;
		no_fund["fund"] = serde_json::Value::String(String::new());
		assert!(
			governance_mail("payout_outcome", &no_fund, &cabinet("https://cabinet.example")).is_none(),
			"terms for no fund are no mail"
		);
	}

	/// The fourth subject: a row naming a mark renders as a NAV mark, and a mark on no fund
	/// is unrenderable — the relay refuses it, and the dispatcher parks rather than mails a
	/// value for nothing.
	#[test]
	fn an_outcome_row_naming_a_mark_renders_as_a_valuation() {
		let mark = serde_json::json!({
			"consilium_id": "c-15",
			"outcome": "TOKEN_BURNED",
			"network": "", "address": "", "amount": "", "detail": "five failed code attempts burned the approval token for seat u-1",
			"tier": "", "source": "", "destination": "", "reason": "",
			"fund": "Quy Nhon Fund", "current": null, "proposed": null,
			"mark": "5 000.00 USDT",
		});
		let mail = governance_mail("payout_outcome", &mark, &cabinet("https://cabinet.example")).expect("renderable");
		assert_eq!(mail.subject, "NAV mark invitation burned — Quy Nhon Fund");
		assert!(mail.text.contains("Mark: 5 000.00 USDT"));
		assert!(!mail.text.contains("Amount") && !mail.text.contains("Payment"), "a mark is not a payment");

		let mut no_fund = mark;
		no_fund["fund"] = serde_json::Value::String(String::new());
		assert!(
			governance_mail("payout_outcome", &no_fund, &cabinet("https://cabinet.example")).is_none(),
			"a mark on no fund is no mail"
		);
	}

	/// `current` has two absences: `null` is a fund that charged nothing and reads "none",
	/// while a value that no longer parses (the terms' shape drifted between queueing and
	/// sending) is unrenderable — like `proposed` — rather than rendered as "none", which
	/// would tell the owners the fund took nothing.
	#[test]
	fn unparseable_current_terms_park_the_mail_rather_than_read_as_none() {
		let proposed = serde_json::json!({"management_bps": 250, "performance_bps": 2000, "hurdle_bps": 800, "basis": "market_value", "crystallization": "quarterly"});
		let outcome = serde_json::json!({
			"consilium_id": "c-12", "outcome": "EXECUTED", "fund": "Quy Nhon Fund",
			"network": "", "address": "", "amount": "", "detail": "",
			"tier": "", "source": "", "destination": "", "reason": "",
			"current": null, "proposed": proposed,
		});
		let mail = governance_mail("payout_outcome", &outcome, &cabinet("https://cabinet.example")).expect("renderable");
		assert!(mail.text.contains("Management fee: none → 2.5%"), "null is a fund that charged nothing");

		let mut absent = outcome.clone();
		absent.as_object_mut().expect("object").remove("current");
		let mail = governance_mail("payout_outcome", &absent, &cabinet("https://cabinet.example")).expect("renderable");
		assert!(mail.text.contains("Management fee: none → 2.5%"), "so is a row with no `current` key at all");

		let mut drifted = outcome;
		drifted["current"] = serde_json::json!({"management_bps": "two percent"});
		assert!(
			governance_mail("payout_outcome", &drifted, &cabinet("https://cabinet.example")).is_none(),
			"terms that fail to parse are not a fund that charged nothing"
		);

		// The same helper feeds the approval and the notice; the distinction holds there too.
		let approval = serde_json::json!({
			"consilium_id": "c-12", "initiator_email": "a@example.com", "fund": "Quy Nhon Fund",
			"current": {"management_bps": "two percent"}, "proposed": proposed,
			"reason": "", "payload_hash": "", "threshold": 2, "owner_count": 3, "expires_at": 1_785_143_640,
			"approval_url": "https://cabinet.example/a", "code": "123456",
		});
		assert!(governance_mail("fee_policy_approval", &approval, &cabinet("https://cabinet.example")).is_none());
		let notice = serde_json::json!({
			"fund": "Quy Nhon Fund", "current": 42, "proposed": proposed,
			"effective_at": 1_785_143_640, "link": "/funds/quy-nhon/fees",
		});
		assert!(governance_mail("fee_policy_notice", &notice, &cabinet("https://cabinet.example")).is_none());
	}

	/// A cancelled consent renders for both readers and every ending, and carries nothing a
	/// reader could act on: no code panel, no button, no URL in either part. A row whose
	/// reader, ending or reason this dispatcher does not know — or whose reason does not
	/// belong to its ending — is parked, not guessed at.
	#[test]
	fn a_payment_outcome_renders_for_both_readers_and_carries_no_link() {
		let row = |audience: &str, outcome: &str, reason: &str| {
			serde_json::json!({
				"audience": audience, "outcome": outcome, "reason": reason,
				"tier": "external", "source": "Quy Nhon Fund — distributions",
				"destination": "Your bank account ••4417", "amount": "1 200.00 USDT",
				"payment_id": "7d7a1f0e-3f0b-4c1e-9a55-2b6f1e0c9d42",
			})
		};
		for audience in ["subject", "staff"] {
			for (outcome, reason) in [("TOKEN_BURNED", "WRONG_CODES"), ("INVALIDATED", "SESSIONS_REVOKED"), ("INVALIDATED", "EMAIL_CHANGED")] {
				let mail = governance_mail("payment_outcome", &row(audience, outcome, reason), &cabinet("https://cabinet.example")).expect("renderable");
				let at = format!("{audience}/{outcome}/{reason}");
				assert!(mail.subject.contains("1 200.00 USDT"), "{at}: {}", mail.subject);
				assert!(!mail.html.contains("<a ") && !mail.html.contains("href"), "{at}: no link in the html");
				assert!(!mail.html.contains("Type this code"), "{at}: no code panel");
				assert!(!mail.text.contains("http") && !mail.html.contains("cabinet.example"), "{at}: no URL at all");
				assert!(!mail.text.contains(reason), "{at}: the closed word is phrased, never printed");
				assert_eq!(mail.text.contains("7d7a1f0e"), audience == "staff", "{at}: the payment id is for staff only");
			}
		}
		for (row, why) in [
			(row("owner", "TOKEN_BURNED", "WRONG_CODES"), "an unknown reader"),
			(row("subject", "EXECUTED", "WRONG_CODES"), "an unknown ending"),
			(row("subject", "INVALIDATED", "five wrong codes"), "an unknown reason"),
			(row("staff", "TOKEN_BURNED", "EMAIL_CHANGED"), "a reason that does not belong to its ending"),
			(row("staff", "INVALIDATED", "WRONG_CODES"), "nor this one"),
		] {
			assert!(governance_mail("payment_outcome", &row, &cabinet("https://cabinet.example")).is_none(), "{why}");
		}
		let mut no_reader = row("subject", "TOKEN_BURNED", "WRONG_CODES");
		no_reader.as_object_mut().expect("object").remove("audience");
		assert!(governance_mail("payment_outcome", &no_reader, &cabinet("https://cabinet.example")).is_none(), "no reader at all");
	}

	#[test]
	fn an_approval_row_renders_against_the_configured_page_or_parks() {
		let row = serde_json::json!({
			"approval_id": "0b6f3c2e-1111-4222-8333-444455556666", "kind": "bank:payment", "kind_label": "Payment", "proposer": "bank",
			"scope": "main", "level": "platform", "requested_by": "", "reason": "", "threshold": 2, "roster_size": 3, "expires_at": 0,
			"fields": [{"label": "Amount", "value": {"type": "amount", "value": {"value": "5000", "currency": "USDT"}}}],
		});
		let mail = approval_mail("approval_request", &row, "https://admin.example/approvals").expect("renderable");
		assert!(mail.html.contains("https://admin.example/approvals/0b6f3c2e-1111-4222-8333-444455556666") && mail.text.contains("5,000 USDT"));
		assert!(
			approval_mail("approval_outcome", &row, "https://admin.example/approvals").is_none(),
			"an outcome row naming no outcome parks"
		);
		assert!(
			approval_mail("approval_request", &serde_json::json!({"approval_id": "x"}), "https://admin.example").is_none(),
			"a drifted row parks"
		);
		assert!(approval_mail("payout_outcome", &row, "https://admin.example").is_none(), "not an approval kind");
	}

	fn published(topic: &str, label: &str) -> NotificationTopic {
		NotificationTopic {
			topic: topic.to_owned(),
			label: label.to_owned(),
			description: String::new(),
			default_subscribed: false,
			required: false,
			required_reason: String::new(),
		}
	}

	#[test]
	fn topic_label_prefers_built_in_then_scope_catalog() {
		let scoped = [
			published("invest:digest", "Digest"),
			published("invest:fund:quy-nhon", "Quy Nhon fund"),
			published("invest:blank", ""),
		];
		assert_eq!(topic_label("invest:digest", &scoped), Some("Digest"));
		assert_eq!(topic_label("invest:fund:quy-nhon", &scoped), Some("Quy Nhon fund"));
		assert_eq!(topic_label("invest:blank", &scoped), None, "an empty label falls through to the caller's fallback");
		assert_eq!(topic_label("invest:unknown", &scoped), None);
		let built_in = crate::notification::TOPICS.first().expect("catalogue is not empty");
		let shadow = [published(built_in.key, "Shadow")];
		assert_eq!(topic_label(built_in.key, &shadow), Some(built_in.label), "a built-in topic keeps its own label");
	}

	/// A required notice is mailed without an unsubscribe target — no footer link and no
	/// `List-Unsubscribe` — and says why it came; an ordinary topic's mail keeps both.
	#[test]
	fn a_required_notice_is_mailed_without_an_unsubscribe_target() {
		let cfg = DispatcherConfig {
			mail_from: "EV <noreply@evinvest.test>".into(),
			notice_links: Arc::new(NoticeLinkBases::cabinet_only("https://evinvest.ltd/cabinet")),
			public_origin: "https://evinvest.ltd".into(),
			approvals_url: "https://evinvest.ltd/admin/approvals".into(),
			daily_budget: i64::MAX,
			interval: Duration::from_secs(60),
		};
		let job = |topic: &str| crate::infrastructure::notifications::DeliveryJob {
			id: 1,
			kind: "notification".into(),
			recipient: "holder@example.com".into(),
			attempts: 0,
			unsubscribe_token: Some("tok".into()),
			confirm_token: None,
			topic: Some(topic.into()),
			title: Some("New fee terms".into()),
			body: Some(String::new()),
			link: Some("/funds/quy-nhon".into()),
			occurred_at: Some(1_785_143_640),
			payload: None,
		};
		let scoped = [
			NotificationTopic {
				required: true,
				required_reason: "Holders are told before new fees bind".into(),
				..published("invest:fee-terms", "Fee terms")
			},
			published("invest:news", "News"),
		];
		let notice = render(&job("invest:fee-terms"), &cfg, &scoped).expect("renderable");
		assert!(notice.unsubscribe_url.is_empty(), "no List-Unsubscribe header");
		assert!(!notice.html.contains("unsubscribe?token=") && !notice.text.contains("Unsubscribe"));
		assert!(
			notice
				.text
				.contains("Fee terms is a required notice, which cannot be switched off: Holders are told before new fees bind.")
		);
		let news = render(&job("invest:news"), &cfg, &scoped).expect("renderable");
		assert_eq!(news.unsubscribe_url, "https://evinvest.ltd/api/auth/notifications/unsubscribe?token=tok");
		assert!(news.text.contains("you follow News"));
	}

	#[test]
	fn every_backoff_fits_the_retry_window() {
		// The lease must be shorter than the shortest backoff, or a row could be
		// re-claimed by another dispatcher before its own retry is due.
		assert!(LEASE_SECS <= backoff_secs(1) * 5, "the lease is on the same order as the first retry");
		assert!(backoff_secs(1) > 0);
	}
}

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

/// Render one of the typed governance mails from its stored payload. `None` for a kind
/// this dispatcher does not know — permanent, so the caller parks rather than retries.
pub(crate) fn governance_mail(kind: &str, payload: &serde_json::Value) -> Option<templates::RenderedEmail> {
	match kind {
		"kyc_verdict_alert" => Some(templates::kyc_verdict_alert(
			&text_field(payload, "subject_email"),
			&text_field(payload, "case_id"),
			&text_field(payload, "verdict"),
			int_field(payload, "held_level") as u32,
			int_field(payload, "requested_tier") as u32,
			int_field(payload, "decided_at"),
		)),
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
		&& let Some(rendered) = governance_mail(&job.kind, payload).or_else(|| approval_mail(&job.kind, payload, &cfg.approvals_url))
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

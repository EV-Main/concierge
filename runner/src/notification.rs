//! `notification` module — the platform's notification plane.
//!
//! Owns three things: who may be contacted (subscribers), what they asked to hear
//! about (subscriptions), and the durable record of what was said (the inbox). Email
//! delivery is queued here and drained by the dispatcher in [`crate::dispatch`].
//!
//! AUTHZ SPLIT. [`Notifications::emit`] is service-to-service: it must carry a
//! `typ=service` token, because it writes into someone else's inbox and no end user
//! may do that. Everything else is self-service and acts strictly on the caller's own
//! subscriber row, gated through the shared [`crate::authz`] live-record check — so a
//! suspended or token-revoked principal loses access here exactly as everywhere else.
//! The account-less subscribe/confirm/unsubscribe RPCs also want a `typ=service` token,
//! which this plane neither mints nor admits yet (`MintServiceToken` is reserved), so
//! today nothing reaches them. The account-less path that works is this plane's own HTTP
//! edge (`web::notifications`: the subscribe form behind Turnstile, the confirm and
//! unsubscribe links every mail carries), in process and over the same functions
//! ([`subscribe_accountless`], [`unsubscribe_by_token`]). Both doors are protected by rate
//! limits rather than by identity, since by definition there is no identity yet.
//!
//! SPAM RESISTANCE. An open "email me updates" endpoint is a mail cannon pointed at
//! whoever an attacker names, so the protection is layered rather than one check:
//! (1) the address must parse; (2) a per-IP request budget; (3) a per-address
//! confirmation-send throttle held in Postgres, which caps mail per victim no matter
//! how many requests arrive or from where; (4) double opt-in, so an unconfirmed
//! address only ever receives that one throttled message; and (5) a global daily send
//! budget enforced by the dispatcher as the backstop. Only (2) is memory-resident —
//! the layers that actually bound mail volume are durable.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::{
	collections::HashMap,
	sync::{Arc, Mutex},
	time::{Duration, SystemTime, UNIX_EPOCH},
};

use domain::{
	authz::Notifications as NotificationPermission,
	error::DomainError,
	scope_catalog::NotificationTopic,
	users::{Email, User},
};
use evconcierge_auth::{Claims, claims_of};
use evconcierge_contracts::concierge::v1::{
	Channel, ConfirmSubscriptionRequest, ConfirmSubscriptionResponse, EmitRequest, EmitResponse, GetNotificationSettingsRequest, GetUnreadCountRequest, GetUnreadCountResponse,
	ListNotificationsRequest, ListNotificationsResponse, MarkReadRequest, MarkReadResponse, Notification as NotificationMsg, NotificationSettings, SetChannelEnabledRequest,
	SetTopicSubscriptionRequest, SubscribeAnonymousRequest, SubscribeAnonymousResponse, TopicSubscription, UnsubscribeRequest, UnsubscribeResponse,
	notification_service_server::NotificationService,
};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{
	authz::caller_gate,
	infrastructure::notifications::SubscriberRow,
	ports::{InboxTopics, NotificationRepository, UserDirectoryRepository},
	service_caller::BANK_NAMESPACE,
	support::domain_to_status,
};

/// One of this plane's own topics. Server-owned so every client renders identical wording,
/// and closed so an emitter cannot invent topics nobody can find or unsubscribe from.
pub struct Topic {
	pub key: &'static str,
	pub label: &'static str,
	pub description: &'static str,
	/// False for a trace topic: written by this plane whatever anyone follows
	/// (`NotificationRepository::record`), shown and filtered on in the platform inbox, but
	/// neither offered to follow nor emitted on.
	pub followable: bool,
}

pub const TOPICS: &[Topic] = &[
	Topic {
		key: "account:verification",
		label: "Identity verification",
		description: "Decisions on your KYC submissions",
		followable: true,
	},
	Topic {
		key: "platform:announcements",
		label: "Platform & product",
		description: "Maintenance windows, new features",
		followable: true,
	},
	// The key predates the move of the money topic to `bank:`; the traces of mail about the
	// user's own money kept it, and the previous binary writes them under it too.
	Topic {
		key: "account:money-movement",
		label: "Your money",
		description: "Requests and notices about your own money",
		followable: false,
	},
];

pub fn topic(key: &str) -> Option<&'static Topic> {
	TOPICS.iter().find(|t| t.key == key)
}

/// A key this plane used to own that moved to the scope emitting on it (§6). Until the
/// emitters and pages have moved, the old key is taken wherever a topic is named — an emit,
/// a follow, the account-less subscribe and unsubscribe — and stands for the new one.
/// Dropped at the contract step (ORG-RESTRUCTURE-PLAN §12 p.8); migration 0042 carried the
/// subscriptions across.
pub struct MovedTopic {
	pub from: &'static str,
	pub to: &'static str,
	/// The scope whose members alone the new key reaches; `None` for `bank:`, which the
	/// platform inbox shows to every account.
	pub scope: Option<&'static str>,
}

pub const MOVED_TOPICS: &[MovedTopic] = &[
	MovedTopic {
		from: "fund:quy-nhon",
		to: "invest:fund:quy-nhon",
		scope: Some("invest"),
	},
	MovedTopic {
		from: "account:money-movement",
		to: "bank:money-movement",
		scope: None,
	},
];

/// The key `key` is stored under: its new one if it moved, else itself.
pub fn current_key(key: &str) -> &str {
	MOVED_TOPICS.iter().find(|m| m.from == key).map_or(key, |m| m.to)
}

/// Whether `key` names a topic at all: one of this plane's own, a moved key's new name
/// (taken before its scope publishes it, so the alias works from the first day), or one a
/// scope's catalog in force publishes. A withdrawn scope topic stops being known; the
/// subscriptions and inbox rows under it stay.
pub async fn topic_known(notifications: &dyn NotificationRepository, key: &str) -> Result<bool, DomainError> {
	if topic(key).is_some() || MOVED_TOPICS.iter().any(|m| m.to == key) {
		return Ok(true);
	}
	Ok(scope_topic(notifications, key).await?.is_some())
}

/// [`topic_known`] less this plane's trace topics: what may be followed at all.
pub async fn topic_followable(notifications: &dyn NotificationRepository, key: &str) -> Result<bool, DomainError> {
	match topic(key) {
		Some(t) => Ok(t.followable),
		None => topic_known(notifications, key).await,
	}
}

/// The gRPC metadata that asks for the summary inbox (value `all`). Metadata and not a
/// request field: banking builds these request messages with struct literals, so a new
/// field would break its build at the next pin bump (`docs/SCOPES-AND-APPROVALS.md` §1).
pub const INBOX_VIEW_HEADER: &str = "x-ev-inbox-view";

/// Which inbox a read or a write goes through (D21). The server decides it — from the
/// `Origin` on the web surface, from the credential on gRPC — never from what a request
/// asks for, so a scope's page cannot read another direction's notifications.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboxView {
	/// `PUBLIC_ORIGIN`: this plane's built-in topics and the money plane's (`bank:`), which
	/// every account has.
	Platform,
	/// A scope's host, for a member of the scope: its catalog's topics and nothing else.
	Scope { namespace: String },
	/// A scope's host, for an account the scope has never seen: nothing to show. Not a
	/// refusal — the account is in good standing, it just has nothing there.
	Outsider,
	/// Every namespace: `PUBLIC_ORIGIN` only, behind `concierge:notifications:read_all`.
	All,
}

impl InboxView {
	/// The inbox of `scope` (namespace `namespace`) as `user_id` sees it.
	pub async fn of_scope(notifications: &dyn NotificationRepository, scope: &str, namespace: &str, user_id: Uuid) -> Result<Self, DomainError> {
		Ok(if notifications.is_scope_member(scope, user_id).await? {
			Self::Scope { namespace: namespace.to_owned() }
		} else {
			Self::Outsider
		})
	}

	/// A built-in key never belongs to a scope even when the scope's namespace shares its
	/// prefix: the catalog check refuses to let a scope publish one, and this keeps a stray
	/// row from showing up there either.
	pub fn shows(&self, key: &str) -> bool {
		let built_in = topic(key).is_some();
		let namespace = key.split_once(':').map(|(ns, _)| ns);
		match self {
			Self::Platform => built_in || namespace == Some(BANK_NAMESPACE),
			Self::Scope { namespace: ours } => !built_in && namespace == Some(ours.as_str()),
			Self::Outsider => false,
			Self::All => true,
		}
	}

	/// [`Self::shows`] as the inbox queries take it.
	pub fn topics(&self) -> InboxTopics {
		let built_ins = || TOPICS.iter().map(|t| t.key.to_owned()).collect();
		match self {
			Self::Platform => InboxTopics::Within {
				keys: built_ins(),
				namespaces: vec![BANK_NAMESPACE.to_owned()],
				except: Vec::new(),
			},
			Self::Scope { namespace } => InboxTopics::Within {
				keys: Vec::new(),
				namespaces: vec![namespace.clone()],
				except: built_ins(),
			},
			Self::Outsider => InboxTopics::Within {
				keys: Vec::new(),
				namespaces: Vec::new(),
				except: Vec::new(),
			},
			Self::All => InboxTopics::Every,
		}
	}

	/// The master channel switches are the account's, across every inbox at once, so they
	/// are changed only where every inbox the account has a say in is in view.
	pub fn sets_channels(&self) -> bool {
		match self {
			Self::Platform | Self::All => true,
			Self::Scope { .. } | Self::Outsider => false,
		}
	}
}

/// [`topic_known`] within one inbox: what that inbox offers to filter on.
pub async fn topic_offered(notifications: &dyn NotificationRepository, view: &InboxView, key: &str) -> Result<bool, DomainError> {
	Ok(view.shows(key) && topic_known(notifications, key).await?)
}

/// [`topic_followable`] within one inbox: what that inbox offers to follow.
pub async fn follow_offered(notifications: &dyn NotificationRepository, view: &InboxView, key: &str) -> Result<bool, DomainError> {
	Ok(view.shows(key) && topic_followable(notifications, key).await?)
}

/// The topic a scope's catalog in force publishes under `key`, if any. A key's namespace is
/// its publisher's (the catalog check holds every topic to it), so the key alone names it.
pub async fn scope_topic(notifications: &dyn NotificationRepository, key: &str) -> Result<Option<NotificationTopic>, DomainError> {
	Ok(notifications.scope_topics().await?.into_iter().find(|t| t.topic == key))
}

/// Where an emit lands once the caller has been settled: the key it is stored under and
/// the scope whose ACTIVE members alone it reaches (`None`: every account — this plane's
/// own topics and `bank:`, which the platform inbox shows to everyone).
pub(crate) struct EmitTarget {
	pub topic: String,
	pub scope: Option<String>,
	/// The catalog's `default_subscribed`: an account that never touched the topic follows it.
	pub default_subscribed: bool,
}

/// The checks every emit makes on the message itself, whoever sends it. Checked here as
/// well as by the CHECK constraints, so an over-long title is a clear invalid_argument
/// rather than a constraint violation surfacing as the opaque `unavailable` that
/// `DomainError::Repository` maps to.
pub(crate) fn emit_fields(req: &EmitRequest) -> Result<Uuid, Status> {
	let user_id = Uuid::parse_str(&req.user_id).map_err(|_| Status::invalid_argument("user_id must be a UUID"))?;
	if req.title.is_empty() || req.title.chars().count() > 200 {
		return Err(Status::invalid_argument("title must be 1-200 characters"));
	}
	if req.body.chars().count() > 2000 {
		return Err(Status::invalid_argument("body must be at most 2000 characters"));
	}
	if req.link.chars().count() > 512 {
		return Err(Status::invalid_argument("link must be at most 512 characters"));
	}
	if req.dedupe_key.is_empty() || req.dedupe_key.chars().count() > 128 {
		return Err(Status::invalid_argument("dedupe_key must be 1-128 characters"));
	}
	if req.kind.is_empty() || req.kind.chars().count() > 64 {
		return Err(Status::invalid_argument("kind must be 1-64 characters"));
	}
	Ok(user_id)
}

/// The write behind both emit RPCs. A scope's topic for someone who is not an active member
/// of the scope writes nothing: its inbox is shown to members only, and the mail copy must
/// not reach further than the inbox does.
pub(crate) async fn emit_to(notifications: &dyn NotificationRepository, target: &EmitTarget, req: &EmitRequest) -> Result<EmitResponse, Status> {
	let user_id = emit_fields(req)?;
	if let Some(scope) = &target.scope
		&& !notifications.is_active_scope_member(scope, user_id).await.map_err(domain_to_status)?
	{
		return Ok(EmitResponse::default());
	}
	let occurred_at = if req.occurred_at > 0 { req.occurred_at } else { now_secs() };
	let outcome = notifications
		.emit(
			user_id,
			&target.topic,
			&req.kind,
			&req.title,
			&req.body,
			&req.link,
			&req.dedupe_key,
			occurred_at,
			target.default_subscribed,
		)
		.await
		.map_err(domain_to_status)?;
	let mut channels = Vec::new();
	if outcome.in_app {
		channels.push(Channel::InApp as i32);
	}
	if outcome.email {
		channels.push(Channel::Email as i32);
	}
	Ok(EmitResponse {
		notification_id: outcome.notification_id.map(|id| id.to_string()).unwrap_or_default(),
		delivered: !channels.is_empty(),
		channels,
	})
}

/// Fixed-window request counter keyed by caller-supplied identity (an IP).
///
/// Deliberately per-process and in-memory: this is the cheap first line, not the layer
/// that bounds mail volume — the per-address throttle and the daily send budget live in
/// Postgres precisely so they survive a restart and hold across replicas. Promote this
/// to the existing Redis connection once concierge runs more than one instance.
pub struct RateLimiter {
	window_secs: u64,
	max: u32,
	hits: Mutex<HashMap<String, (u64, u32)>>,
}

impl RateLimiter {
	pub fn new(window: Duration, max: u32) -> Self {
		Self {
			window_secs: window.as_secs().max(1),
			max,
			hits: Mutex::new(HashMap::new()),
		}
	}

	/// Spend one unit of `key`'s budget; true when the call was within it.
	pub fn check(&self, key: &str) -> bool {
		self.hit(key, true)
	}

	/// Whether `key` still has budget, spending none. For a caller that must not be
	/// charged for a call that goes on to do nothing — a validation refusal, or a retry
	/// the dedupe key turns into a no-op — pair this with [`Self::record`] after the work.
	pub fn peek(&self, key: &str) -> bool {
		self.hit(key, false)
	}

	/// Spend one unit of `key`'s budget for work already done. The answer is deliberately
	/// not returned: the decision was [`Self::peek`]'s, and refusing after the fact would
	/// refuse nothing.
	pub fn record(&self, key: &str) {
		self.hit(key, true);
	}

	fn hit(&self, key: &str, spend: bool) -> bool {
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
		let bucket = now / self.window_secs;
		let Ok(mut hits) = self.hits.lock() else {
			// A poisoned lock must not become an open door.
			return false;
		};
		// Bounded memory: stale buckets are dropped wholesale, so a spray of unique
		// keys cannot grow the map without limit.
		if hits.len() > 10_000 {
			hits.retain(|_, (b, _)| *b == bucket);
		}
		let entry = hits.entry(key.to_owned()).or_insert((bucket, 0));
		if entry.0 != bucket {
			*entry = (bucket, 0);
		}
		if spend {
			entry.1 += 1;
		}
		entry.1 < self.max + u32::from(spend)
	}
}

/// Why an account-less subscribe was refused before anything was written.
#[derive(Debug, Eq, PartialEq)]
pub enum SubscribeRefusal {
	UnknownTopic,
	InvalidEmail,
	/// The per-IP budget is spent.
	TooMany,
}

/// Why an unsubscribe by token was refused before anything was written.
#[derive(Debug, Eq, PartialEq)]
pub enum UnsubscribeRefusal {
	MissingToken,
	UnknownTopic,
}

/// The account-less subscribe behind both doors — `SubscribeAnonymous` and the web surface's
/// `POST /auth/notifications/subscribe` — so the two can never guard it differently. Accepted
/// alike whether a confirmation was queued, the address was already confirmed or the
/// database throttle held it back: an unauthenticated caller does not get to tell those apart.
pub async fn subscribe_accountless(
	notifications: &dyn NotificationRepository,
	limiter: &RateLimiter,
	email: &str,
	topic: &str,
	client_ip: &str,
) -> Result<Result<AccountlessSubscribe, SubscribeRefusal>, DomainError> {
	// Any topic a catalog in force publishes, as well as this plane's own: the address
	// asked for it by name and confirms it by mail, so `default_subscribed` — which is
	// about accounts that never asked — has no say here.
	let key = current_key(topic);
	if !topic_followable(notifications, key).await? {
		return Ok(Err(SubscribeRefusal::UnknownTopic));
	}
	// Parsed, not merely non-empty: everything downstream treats this as a real
	// mailbox, and a malformed address becomes a hard bounce charged against our
	// sending reputation.
	let Ok(email) = Email::parse(email) else {
		return Ok(Err(SubscribeRefusal::InvalidEmail));
	};

	// The per-IP budget is the cheap gate. An empty client_ip shares one bucket, so
	// a caller that declines to forward it throttles itself rather than everyone.
	let bucket = if client_ip.is_empty() { "anonymous" } else { client_ip };
	if !limiter.check(bucket) {
		return Ok(Err(SubscribeRefusal::TooMany));
	}

	// The database throttle is what actually bounds mail: at most one confirmation
	// per address per window, however many requests arrive and from wherever.
	let queued = notifications.subscribe_anonymous(email.as_str(), key, CONFIRM_THROTTLE_SECS).await?;
	if queued.is_none() {
		tracing::debug!(topic = %key, "anonymous subscribe accepted without queueing confirmation (already confirmed, or throttled)");
	}
	Ok(Ok(AccountlessSubscribe { queued: queued.is_some() }))
}

/// An accepted account-less subscribe. Deliberately not a public field: whether mail was
/// queued must reach the dispatcher's wake-up and never an answer.
pub struct AccountlessSubscribe {
	queued: bool,
}

impl AccountlessSubscribe {
	pub fn queued(&self) -> bool {
		self.queued
	}
}

/// The one-click unsubscribe behind both doors (`Unsubscribe`, `POST
/// /auth/notifications/unsubscribe`). An empty `topic` leaves every mail copy (the
/// List-Unsubscribe behaviour); a moved key stands for its new one. `Ok(Ok(false))` for a
/// token nobody holds.
pub async fn unsubscribe_by_token(notifications: &dyn NotificationRepository, token: &str, topic: &str) -> Result<Result<bool, UnsubscribeRefusal>, DomainError> {
	if token.is_empty() {
		return Ok(Err(UnsubscribeRefusal::MissingToken));
	}
	let topic_filter = match current_key(topic) {
		"" => None,
		t if topic_known(notifications, t).await? => Some(t),
		_ => return Ok(Err(UnsubscribeRefusal::UnknownTopic)),
	};
	Ok(Ok(notifications.unsubscribe(token, topic_filter).await?))
}

fn subscribe_status(refusal: SubscribeRefusal) -> Status {
	match refusal {
		SubscribeRefusal::UnknownTopic => Status::invalid_argument("unknown topic"),
		SubscribeRefusal::InvalidEmail => Status::invalid_argument("email is not a valid address"),
		SubscribeRefusal::TooMany => Status::resource_exhausted("too many subscription attempts"),
	}
}

fn unsubscribe_status(refusal: UnsubscribeRefusal) -> Status {
	match refusal {
		UnsubscribeRefusal::MissingToken => Status::invalid_argument("token is required"),
		UnsubscribeRefusal::UnknownTopic => Status::invalid_argument("unknown topic"),
	}
}

/// How long an address waits before another confirmation mail can be generated.
pub const CONFIRM_THROTTLE_SECS: i64 = 24 * 60 * 60;
const DEFAULT_PAGE: u32 = 20;
const MAX_PAGE: u32 = 100;

/// The notification service. Cheaply cloneable (everything behind `Arc`s).
#[derive(Clone)]
pub struct Notifications {
	notifications: Arc<dyn NotificationRepository>,
	users: Arc<dyn UserDirectoryRepository>,
	limiter: Arc<RateLimiter>,
}

impl Notifications {
	pub fn new(notifications: Arc<dyn NotificationRepository>, users: Arc<dyn UserDirectoryRepository>, limiter: Arc<RateLimiter>) -> Self {
		Self { notifications, users, limiter }
	}

	/// A user's token reads the platform inbox: a scope's own surface signs its users in
	/// with its own client, whose token this service never admits, so a session token here
	/// is always someone on `PUBLIC_ORIGIN`. The summary is asked for by
	/// [`INBOX_VIEW_HEADER`] and needs `concierge:notifications:read_all` on the PERSISTED
	/// seat, as on the web: break-glass elevation opens the console, not everyone's mail.
	async fn view<T>(&self, request: &Request<T>) -> Result<InboxView, Status> {
		match request.metadata().get(INBOX_VIEW_HEADER).map(|v| v.to_str()) {
			None => Ok(InboxView::Platform),
			Some(Ok("all")) => {
				let gate = caller_gate(self.users.as_ref(), request).await?;
				if gate.record.is_some_and(|r| r.role.may(NotificationPermission::ReadAll)) {
					Ok(InboxView::All)
				} else {
					Err(Status::permission_denied("insufficient role"))
				}
			}
			Some(_) => Err(Status::invalid_argument(format!("{INBOX_VIEW_HEADER} is `all` or absent"))),
		}
	}

	/// Resolve the caller's own subscriber row, enforcing the live persisted record.
	/// Created on first touch, so a user never has to switch notifications ON before
	/// they are allowed to switch them off.
	async fn caller<T>(&self, request: &Request<T>) -> Result<SubscriberRow, Status> {
		let gate = crate::authz::caller_gate(self.users.as_ref(), request).await?;
		let id = gate.id.ok_or_else(|| Status::unauthenticated("caller is not a user"))?;
		let user = self.users.find_by_id(id).await.map_err(domain_to_status)?.ok_or_else(|| Status::not_found("user not found"))?;
		subscriber_of(self.notifications.as_ref(), &user).await.map_err(domain_to_status)
	}

	/// Assert a `typ=service` token. A user token must never reach the emit path or
	/// the account-less subscribe path.
	fn require_service<T>(request: &Request<T>) -> Result<(), Status> {
		let claims: &Claims = claims_of(request).ok_or_else(|| Status::unauthenticated("missing claims"))?;
		if claims.is_access() {
			return Err(Status::permission_denied("service token required"));
		}
		Ok(())
	}

	async fn settings_snapshot(&self, view: &InboxView, sub: &SubscriberRow) -> Result<NotificationSettings, Status> {
		settings_of(self.notifications.as_ref(), view, &sub.email, sub.email_verified, Some(sub))
			.await
			.map_err(domain_to_status)
	}
}

/// The user's subscriber row, created on first touch and kept in step with the
/// directory's address. For writes: a read that must create nothing asks
/// `NotificationRepository::subscriber_of_user` and hands [`settings_of`] what it found.
pub async fn subscriber_of(notifications: &dyn NotificationRepository, user: &User) -> Result<SubscriberRow, DomainError> {
	notifications.subscriber_for_user(user.id().raw(), user.email().as_str(), user.email_verified()).await
}

/// The settings screen's whole snapshot: both master switches and every topic `view`
/// offers, with the caller's choice on it. One builder for the RPC and the web surface, so
/// the two can never render the same subscriber differently. With no subscriber row yet it
/// is the state the first write would create: both channels on (the columns' defaults), no
/// topic followed — answered without creating anything. `email` is the address to show,
/// which a read takes from the directory rather than a row it does not refresh.
pub async fn settings_of(
	notifications: &dyn NotificationRepository,
	view: &InboxView,
	email: &str,
	email_verified: bool,
	sub: Option<&SubscriberRow>,
) -> Result<NotificationSettings, DomainError> {
	let held = match sub {
		Some(sub) => notifications.subscriptions(sub.id).await?,
		None => Vec::new(),
	};
	let scoped = notifications.scope_topics().await?;
	let catalogue = TOPICS
		.iter()
		.filter(|t| t.followable)
		.map(|t| (t.key, t.label, t.description, false))
		.chain(scoped.iter().map(|t| (t.topic.as_str(), t.label.as_str(), t.description.as_str(), t.default_subscribed)))
		.filter(|(key, ..)| view.shows(key));
	// A topic the subscriber never touched reads as its catalog's default; one it switched
	// off has a row saying so, which is what lets the default apply at all.
	let topics = catalogue
		.map(|(key, label, description, default_subscribed)| {
			let row = held.iter().find(|s| s.topic == key);
			let subscribed = row.map_or(default_subscribed, |r| r.subscribed);
			TopicSubscription {
				topic: key.to_owned(),
				label: label.to_owned(),
				description: description.to_owned(),
				subscribed,
				email_enabled: row.filter(|r| r.subscribed).is_none_or(|r| r.email_enabled),
			}
		})
		.collect();
	Ok(NotificationSettings {
		in_app_enabled: sub.is_none_or(|s| s.in_app_enabled),
		email_enabled: sub.is_none_or(|s| s.email_enabled),
		email: email.to_owned(),
		email_verified,
		topics,
	})
}

/// The web surface's JSON for a [`NotificationSettings`], field for field with the
/// message: the one place the two shapes are mapped, so adding a field to one without
/// the other is a single diff.
pub fn settings_json(settings: &NotificationSettings) -> serde_json::Value {
	serde_json::json!({
		"in_app_enabled": settings.in_app_enabled,
		"email_enabled": settings.email_enabled,
		"email": settings.email,
		"email_verified": settings.email_verified,
		"topics": settings.topics.iter().map(|t| serde_json::json!({
			"topic": t.topic,
			"label": t.label,
			"description": t.description,
			"subscribed": t.subscribed,
			"email_enabled": t.email_enabled,
		})).collect::<Vec<_>>(),
	})
}

/// One page of `sub`'s inbox within `view`. Shared by the user's RPC and a scope's
/// ([`crate::scope_inbox`]), so the two can never page or filter differently.
pub(crate) async fn inbox_page(
	notifications: &dyn NotificationRepository,
	sub: &SubscriberRow,
	view: &InboxView,
	req: &ListNotificationsRequest,
) -> Result<ListNotificationsResponse, Status> {
	// Switching the in-app channel off hides the inbox rather than deleting it:
	// the record survives, so turning the channel back on restores history.
	if !sub.in_app_enabled {
		return Ok(ListNotificationsResponse::default());
	}

	let limit = match req.limit {
		0 => DEFAULT_PAGE,
		n => n.min(MAX_PAGE),
	};
	let cursor = match req.cursor.as_str() {
		"" => None,
		raw => Some(Uuid::parse_str(raw).map_err(|_| Status::invalid_argument("cursor must be a notification id"))?),
	};
	let topic_filter = match req.topic.as_str() {
		"" => None,
		t if topic_offered(notifications, view, t).await.map_err(domain_to_status)? => Some(t),
		_ => return Err(Status::invalid_argument("unknown topic")),
	};
	let within = view.topics();

	// One extra row tells us whether a further page exists, with no second query.
	let mut rows = notifications
		.list(sub.id, cursor, i64::from(limit) + 1, req.unread_only, topic_filter, &within)
		.await
		.map_err(domain_to_status)?;
	let next_cursor = if rows.len() > limit as usize {
		rows.truncate(limit as usize);
		rows.last().map(|r| r.id.to_string()).unwrap_or_default()
	} else {
		String::new()
	};

	let unread_count = notifications.unread_count(sub.id, &within).await.map_err(domain_to_status)? as u32;
	Ok(ListNotificationsResponse {
		notifications: rows
			.into_iter()
			.map(|r| NotificationMsg {
				id: r.id.to_string(),
				topic: r.topic,
				kind: r.kind,
				title: r.title,
				body: r.body,
				link: r.link,
				occurred_at: r.occurred_at,
				created_at: r.created_at,
				read_at: r.read_at,
			})
			.collect(),
		next_cursor,
		unread_count,
	})
}

/// Unread within `view`; nothing while the in-app channel is off.
pub(crate) async fn inbox_unread(notifications: &dyn NotificationRepository, sub: &SubscriberRow, view: &InboxView) -> Result<u32, Status> {
	if !sub.in_app_enabled {
		return Ok(0);
	}
	Ok(notifications.unread_count(sub.id, &view.topics()).await.map_err(domain_to_status)? as u32)
}

/// The most ids one mark-read names: bounds the `ANY($ids)` a caller can hand Postgres.
pub const MAX_MARK_IDS: usize = 500;

/// Marks `ids` (or everything unread with `all`) within `view` only.
pub(crate) async fn inbox_mark_read(notifications: &dyn NotificationRepository, subscriber_id: Uuid, view: &InboxView, ids: &[String], all: bool) -> Result<MarkReadResponse, Status> {
	if ids.len() > MAX_MARK_IDS {
		return Err(Status::invalid_argument(format!("at most {MAX_MARK_IDS} ids per call")));
	}
	let ids = ids
		.iter()
		.map(|raw| Uuid::parse_str(raw).map_err(|_| Status::invalid_argument("notification id must be a UUID")))
		.collect::<Result<Vec<_>, _>>()?;
	if !all && ids.is_empty() {
		return Err(Status::invalid_argument("provide notification ids or set all"));
	}
	let within = view.topics();
	let marked = notifications.mark_read(subscriber_id, &ids, all, &within).await.map_err(domain_to_status)? as u32;
	let unread_count = notifications.unread_count(subscriber_id, &within).await.map_err(domain_to_status)? as u32;
	Ok(MarkReadResponse { marked, unread_count })
}

#[tonic::async_trait]
impl NotificationService for Notifications {
	async fn emit(&self, request: Request<EmitRequest>) -> Result<Response<EmitResponse>, Status> {
		Self::require_service(&request)?;
		let req = request.into_inner();
		emit_fields(&req)?;
		let target = if let Some(moved) = MOVED_TOPICS.iter().find(|m| m.from == req.topic) {
			// The alias predates namespaced emitters, so a token that names no namespace may
			// still use it; the new key's catalog decides the default once it is published.
			let published = scope_topic(self.notifications.as_ref(), moved.to).await.map_err(domain_to_status)?;
			EmitTarget {
				topic: moved.to.to_owned(),
				scope: moved.scope.map(str::to_owned),
				default_subscribed: published.is_some_and(|t| t.default_subscribed),
			}
		} else {
			match topic(&req.topic) {
				Some(t) if t.followable => EmitTarget {
					topic: req.topic.clone(),
					scope: None,
					default_subscribed: false,
				},
				Some(_) => return Err(Status::permission_denied("a trace topic is written by this plane alone")),
				// A `typ=service` token names no namespace, so a scope's topic is emitted only
				// through `ScopeInboxService.EmitScopeNotification`, where the credential does.
				None if topic_known(self.notifications.as_ref(), &req.topic).await.map_err(domain_to_status)? => {
					return Err(Status::permission_denied(
						"a scope's topic is emitted by its own namespace, through ScopeInboxService.EmitScopeNotification",
					));
				}
				None => return Err(Status::invalid_argument("unknown topic")),
			}
		};
		Ok(Response::new(emit_to(self.notifications.as_ref(), &target, &req).await?))
	}

	async fn list_notifications(&self, request: Request<ListNotificationsRequest>) -> Result<Response<ListNotificationsResponse>, Status> {
		let view = self.view(&request).await?;
		let sub = self.caller(&request).await?;
		let req = request.get_ref();

		Ok(Response::new(inbox_page(self.notifications.as_ref(), &sub, &view, req).await?))
	}

	async fn get_unread_count(&self, request: Request<GetUnreadCountRequest>) -> Result<Response<GetUnreadCountResponse>, Status> {
		let view = self.view(&request).await?;
		let sub = self.caller(&request).await?;
		let unread_count = inbox_unread(self.notifications.as_ref(), &sub, &view).await?;
		Ok(Response::new(GetUnreadCountResponse { unread_count }))
	}

	async fn mark_read(&self, request: Request<MarkReadRequest>) -> Result<Response<MarkReadResponse>, Status> {
		let view = self.view(&request).await?;
		let sub = self.caller(&request).await?;
		let req = request.get_ref();
		Ok(Response::new(inbox_mark_read(self.notifications.as_ref(), sub.id, &view, &req.ids, req.all).await?))
	}

	async fn get_notification_settings(&self, request: Request<GetNotificationSettingsRequest>) -> Result<Response<NotificationSettings>, Status> {
		let view = self.view(&request).await?;
		let sub = self.caller(&request).await?;
		Ok(Response::new(self.settings_snapshot(&view, &sub).await?))
	}

	async fn set_channel_enabled(&self, request: Request<SetChannelEnabledRequest>) -> Result<Response<NotificationSettings>, Status> {
		let view = self.view(&request).await?;
		let sub = self.caller(&request).await?;
		let req = request.get_ref();

		// Both channels off is explicitly allowed — "stop contacting me" is a supported
		// product state, so there is deliberately no floor keeping one of them on.
		let (in_app, email) = match Channel::try_from(req.channel) {
			Ok(Channel::InApp) => (Some(req.enabled), None),
			Ok(Channel::Email) => (None, Some(req.enabled)),
			_ => return Err(Status::invalid_argument("channel must be in-app or email")),
		};
		self.notifications.set_channel_enabled(sub.id, in_app, email).await.map_err(domain_to_status)?;

		// Re-read rather than patch the local copy, so the snapshot the caller renders
		// from is what the database actually holds.
		let sub = self.caller(&request).await?;
		Ok(Response::new(self.settings_snapshot(&view, &sub).await?))
	}

	async fn set_topic_subscription(&self, request: Request<SetTopicSubscriptionRequest>) -> Result<Response<NotificationSettings>, Status> {
		let view = self.view(&request).await?;
		let sub = self.caller(&request).await?;
		let req = request.get_ref();
		let key = current_key(&req.topic);
		if !follow_offered(self.notifications.as_ref(), &view, key).await.map_err(domain_to_status)? {
			return Err(Status::invalid_argument("unknown topic"));
		}
		self.notifications
			.set_topic_subscription(sub.id, key, req.subscribed, req.email_enabled)
			.await
			.map_err(domain_to_status)?;
		Ok(Response::new(self.settings_snapshot(&view, &sub).await?))
	}

	async fn subscribe_anonymous(&self, request: Request<SubscribeAnonymousRequest>) -> Result<Response<SubscribeAnonymousResponse>, Status> {
		Self::require_service(&request)?;
		let req = request.into_inner();
		subscribe_accountless(self.notifications.as_ref(), &self.limiter, &req.email, &req.topic, &req.client_ip)
			.await
			.map_err(domain_to_status)?
			.map_err(subscribe_status)?;
		Ok(Response::new(SubscribeAnonymousResponse { accepted: true }))
	}

	async fn confirm_subscription(&self, request: Request<ConfirmSubscriptionRequest>) -> Result<Response<ConfirmSubscriptionResponse>, Status> {
		Self::require_service(&request)?;
		let token = request.into_inner().token;
		if token.is_empty() {
			return Err(Status::invalid_argument("token is required"));
		}
		let confirmed = self.notifications.confirm(&token).await.map_err(domain_to_status)?;
		Ok(Response::new(ConfirmSubscriptionResponse { confirmed }))
	}

	async fn unsubscribe(&self, request: Request<UnsubscribeRequest>) -> Result<Response<UnsubscribeResponse>, Status> {
		Self::require_service(&request)?;
		let req = request.into_inner();
		let unsubscribed = unsubscribe_by_token(self.notifications.as_ref(), &req.token, &req.topic)
			.await
			.map_err(domain_to_status)?
			.map_err(unsubscribe_status)?;
		Ok(Response::new(UnsubscribeResponse { unsubscribed }))
	}
}

pub(crate) fn now_secs() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn topics_are_unique_and_bounded() {
		for t in TOPICS {
			assert!(topic(t.key).is_some(), "every catalogue entry resolves through the lookup");
			assert!(t.key.len() <= 64, "topic keys must fit the notifications.topic CHECK constraint");
			assert_eq!(TOPICS.iter().filter(|o| o.key == t.key).count(), 1, "duplicate topic key {}", t.key);
		}
		assert!(topic("fund:does-not-exist").is_none(), "the catalogue is closed — unknown topics are rejected, not created");
	}

	#[test]
	fn a_moved_key_names_a_scope_s_topic_and_no_followable_built_in() {
		for moved in MOVED_TOPICS {
			assert!(topic(moved.from).is_none_or(|t| !t.followable), "{} is still offered under its old key", moved.from);
			assert!(topic(moved.to).is_none(), "{} moved onto a built-in", moved.to);
			let namespace = moved.to.split_once(':').map(|(ns, _)| ns);
			assert_eq!(moved.scope.or(Some(BANK_NAMESPACE)), namespace, "{} reaches the scope it is named after", moved.to);
			assert_eq!(current_key(moved.from), moved.to);
			assert!(moved.to.len() <= 64, "the topic CHECK constraints");
		}
		assert_eq!(current_key("account:verification"), "account:verification");
		assert!(InboxView::Platform.shows("account:money-movement"), "the trace topic stays in the platform inbox");
	}

	#[test]
	fn each_inbox_shows_its_own_namespace() {
		let scope = InboxView::Scope { namespace: "invest".into() };
		for (key, platform, invest) in [
			("account:verification", true, false),
			("bank:payments", true, false),
			("invest:fund:quy-nhon", false, true),
			("sa:leads:new", false, false),
			("bankish:x", false, false),
		] {
			assert_eq!(InboxView::Platform.shows(key), platform, "{key}");
			assert_eq!(scope.shows(key), invest, "{key}");
			assert!(InboxView::All.shows(key) && !InboxView::Outsider.shows(key), "{key}");
		}
		let account = InboxView::Scope { namespace: "account".into() };
		assert!(!account.shows("account:verification"), "a built-in never lands in a scope sharing its prefix");
	}

	#[test]
	fn rate_limiter_admits_up_to_the_budget_then_refuses() {
		let limiter = RateLimiter::new(Duration::from_secs(60), 3);
		assert!(limiter.check("1.2.3.4"), "first call is within budget");
		assert!(limiter.check("1.2.3.4"));
		assert!(limiter.check("1.2.3.4"), "the budget is inclusive of its last slot");
		assert!(!limiter.check("1.2.3.4"), "the fourth call in the window is refused");
		assert!(limiter.check("5.6.7.8"), "budgets are per key — one noisy caller must not lock everyone out");
	}

	#[test]
	fn rate_limiter_bounds_its_own_memory() {
		let limiter = RateLimiter::new(Duration::from_secs(60), 1);
		for i in 0..10_100 {
			limiter.check(&format!("key-{i}"));
		}
		let len = limiter.hits.lock().expect("uncontended").len();
		assert!(len <= 10_100, "a spray of unique keys must not grow the map without bound (was {len})");
	}
}

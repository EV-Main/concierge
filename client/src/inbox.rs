//! The direction's own inbox: `ScopeInboxService`, called by the direction's backend on
//! behalf of a user it knows from its own session (docs/SCOPES-AND-APPROVALS.md §6 of
//! concierge).
//!
//! Every call carries the client credential. concierge answers only for the namespace of
//! this client's own scope, whatever the request says.
//!
//! - Reads ([`list_scope_notifications`](ConciergeClient::list_scope_notifications),
//!   [`scope_unread_count`](ConciergeClient::scope_unread_count),
//!   [`scope_notification_settings`](ConciergeClient::scope_notification_settings)) name
//!   the user by concierge's `user_id` (the `sub` of this client's access token for them,
//!   `ScopeEvent.user_id`). A user who is not an active member of the scope reads empty.
//! - Writes ([`mark_scope_notifications_read`](ConciergeClient::mark_scope_notifications_read),
//!   [`set_scope_topic_subscription`](ConciergeClient::set_scope_topic_subscription)) need
//!   the user's say, because following a topic turns on mail to their address: they take
//!   the access token this client was issued for the user, and concierge takes the user
//!   from it. A non-member is [`ConciergeError::Rejected`] with FAILED_PRECONDITION.
//! - [`emit_scope_notification`](ConciergeClient::emit_scope_notification) is this client's
//!   services writing into the inbox, on a topic of its own namespace that its scope catalog
//!   publishes. A non-member is not an error: nothing is written and `delivered` is false.

use tonic::{Request, metadata::MetadataValue};
use uuid::Uuid;

use super::{
	ConciergeClient, ConciergeError,
	proto::{
		EmitRequest, EmitResponse, GetScopeNotificationSettingsRequest, GetScopeUnreadCountRequest, ListNotificationsResponse, ListScopeNotificationsRequest, MarkReadResponse,
		MarkScopeNotificationsReadRequest, NotificationSettings, SetScopeTopicSubscriptionRequest,
	},
};

/// The page size a list asks for unless told otherwise. Sent explicitly: concierge reads
/// an absent `limit` as its own default, and a client should not depend on that.
pub const DEFAULT_INBOX_LIMIT: u32 = 20;

/// The metadata key a write carries the user's access token in — raw, no `Bearer`: the
/// `authorization` header already holds the client secret.
const USER_TOKEN_HEADER: &str = "x-ev-user-token";

/// One page of a user's inbox. `Default` is the newest [`DEFAULT_INBOX_LIMIT`] of every
/// topic, read or not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboxQuery {
	/// The previous page's `next_cursor`; empty starts at the newest.
	pub cursor: String,
	/// 0 means [`DEFAULT_INBOX_LIMIT`]. concierge clamps it to 100.
	pub limit: u32,
	pub unread_only: bool,
	/// One topic of this inbox; empty is every topic of it.
	pub topic: String,
}

impl Default for InboxQuery {
	fn default() -> Self {
		Self {
			cursor: String::new(),
			limit: DEFAULT_INBOX_LIMIT,
			unread_only: false,
			topic: String::new(),
		}
	}
}

/// What to mark read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MarkRead {
	/// These notifications, at most 500. An id of another inbox is neither marked nor
	/// reported.
	Ids(Vec<String>),
	/// Every unread notification of this inbox.
	All,
}

impl ConciergeClient {
	/// Newest first; `next_cursor` is empty on the last page.
	pub async fn list_scope_notifications(&self, user_id: Uuid, query: InboxQuery) -> Result<ListNotificationsResponse, ConciergeError> {
		let limit = if query.limit == 0 { DEFAULT_INBOX_LIMIT } else { query.limit };
		let request = self.with_credential(ListScopeNotificationsRequest {
			user_id: user_id.to_string(),
			cursor: query.cursor,
			limit,
			unread_only: query.unread_only,
			topic: query.topic,
		});
		Ok(self.inbox.clone().list_scope_notifications(request).await?.into_inner())
	}

	pub async fn scope_unread_count(&self, user_id: Uuid) -> Result<u32, ConciergeError> {
		let request = self.with_credential(GetScopeUnreadCountRequest { user_id: user_id.to_string() });
		Ok(self.inbox.clone().get_scope_unread_count(request).await?.into_inner().unread_count)
	}

	/// The user's settings with this inbox's topics only. The master channel switches in it
	/// are the account's, and are not set from here.
	pub async fn scope_notification_settings(&self, user_id: Uuid) -> Result<NotificationSettings, ConciergeError> {
		let request = self.with_credential(GetScopeNotificationSettingsRequest { user_id: user_id.to_string() });
		Ok(self.inbox.clone().get_scope_notification_settings(request).await?.into_inner())
	}

	/// `user_access_token` is the access token this client holds for the user; the answer's
	/// `marked` counts what was flipped.
	pub async fn mark_scope_notifications_read(&self, user_access_token: &str, what: MarkRead) -> Result<MarkReadResponse, ConciergeError> {
		let (ids, all) = match what {
			MarkRead::Ids(ids) => (ids, false),
			MarkRead::All => (Vec::new(), true),
		};
		let request = self.as_user(user_access_token, MarkScopeNotificationsReadRequest { user_id: String::new(), ids, all })?;
		Ok(self.inbox.clone().mark_scope_notifications_read(request).await?.into_inner())
	}

	/// Follow or leave a topic of this inbox, and say whether it may mail. A topic outside
	/// the namespace's catalog is [`ConciergeError::Rejected`] with INVALID_ARGUMENT.
	pub async fn set_scope_topic_subscription(&self, user_access_token: &str, topic: &str, subscribed: bool, email_enabled: bool) -> Result<NotificationSettings, ConciergeError> {
		let request = self.as_user(
			user_access_token,
			SetScopeTopicSubscriptionRequest {
				user_id: String::new(),
				topic: topic.to_owned(),
				subscribed,
				email_enabled,
			},
		)?;
		Ok(self.inbox.clone().set_scope_topic_subscription(request).await?.into_inner())
	}

	/// One notification for `notification.user_id`, idempotent on its `dedupe_key`. Another
	/// namespace's topic is [`ConciergeError::Rejected`] with PERMISSION_DENIED, one the
	/// catalog in force does not publish with INVALID_ARGUMENT.
	pub async fn emit_scope_notification(&self, notification: EmitRequest) -> Result<EmitResponse, ConciergeError> {
		let request = self.with_credential(notification);
		Ok(self.inbox.clone().emit_scope_notification(request).await?.into_inner())
	}

	/// The client credential plus the user's token. `user_id` stays empty: concierge takes
	/// the user from the token, and a mismatch would only be a way to fail.
	fn as_user<T>(&self, user_access_token: &str, message: T) -> Result<Request<T>, ConciergeError> {
		let mut token = MetadataValue::try_from(user_access_token).map_err(|_| ConciergeError::Config("the user access token is not a valid header value".into()))?;
		token.set_sensitive(true);
		let mut request = self.with_credential(message);
		request.metadata_mut().insert(USER_TOKEN_HEADER, token);
		Ok(request)
	}
}

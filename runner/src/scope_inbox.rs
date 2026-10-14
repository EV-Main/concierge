//! `scope_inbox` module — `ScopeInboxService`, a direction's own inbox read by its backend
//! (D21, `docs/SCOPES-AND-APPROVALS.md` §6).
//!
//! A service seam like `ScopeEvents`: mounted OUTSIDE the user auth layer and authenticated
//! by the client credential ([`crate::service_caller`]). The browser on a scope's host
//! talks to its own backend, never to this plane: the account routes stay off the scope
//! hosts' CORS list, and a client's user token keeps opening `GetMe` alone.
//!
//! The namespace is the calling client's scope's, never a request field and never an
//! observed scope's: observing a scope's stream is not reading its users' mail. The user is
//! named by the request because a client credential names no user; what keeps that from
//! being a key to anyone's inbox is that the user must be an active member of the client's
//! own scope and only that scope's topics are ever reached.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use domain::users::UserId;
use evconcierge_contracts::concierge::v1::{
	GetScopeNotificationSettingsRequest, GetScopeUnreadCountRequest, GetUnreadCountResponse, ListNotificationsRequest, ListNotificationsResponse, ListScopeNotificationsRequest,
	MarkReadResponse, MarkScopeNotificationsReadRequest, NotificationSettings, SetScopeTopicSubscriptionRequest, scope_inbox_service_server::ScopeInboxService,
};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{
	notification::{InboxView, inbox_mark_read, inbox_page, inbox_unread, settings_of, subscriber_of, topic_offered},
	ports::{NotificationRepository, UserDirectoryRepository},
	service_caller::{ServiceCaller, ServiceCallers},
	support::domain_to_status,
};

const SEAM: &str = "scope inbox";

#[derive(Clone)]
pub struct ScopeInbox {
	callers: ServiceCallers,
	notifications: Arc<dyn NotificationRepository>,
	users: Arc<dyn UserDirectoryRepository>,
}

/// Whose inbox, through which scope. `member` is `None` for anyone the scope may not show
/// one to — an unknown id, a non-member and a disabled account are deliberately one case.
struct Reader {
	view: InboxView,
	member: Option<Uuid>,
}

impl ScopeInbox {
	pub fn new(callers: ServiceCallers, notifications: Arc<dyn NotificationRepository>, users: Arc<dyn UserDirectoryRepository>) -> Self {
		Self { callers, notifications, users }
	}

	async fn reader<T>(&self, request: &Request<T>, user_id: &str) -> Result<Reader, Status> {
		let client = match self.callers.authenticate(request, SEAM).await? {
			ServiceCaller::Client(client) => client,
			ServiceCaller::Bridge => return Err(Status::permission_denied("the money plane's topics are in the platform inbox, not a scope's")),
		};
		if client.scope_closed {
			return Err(Status::failed_precondition("the scope is closed"));
		}
		let user = Uuid::parse_str(user_id).map_err(|_| Status::invalid_argument("user_id must be a concierge user id"))?;
		let member = self.notifications.is_active_scope_member(&client.scope, user).await.map_err(domain_to_status)?;
		Ok(Reader {
			view: InboxView::Scope { namespace: client.namespace },
			member: member.then_some(user),
		})
	}

	fn member_only(reader: &Reader) -> Result<Uuid, Status> {
		reader.member.ok_or_else(|| Status::failed_precondition("not an active member of this scope"))
	}

	async fn settings(&self, view: &InboxView, user: Uuid) -> Result<NotificationSettings, Status> {
		let found = self.users.find_by_id(UserId::from_raw(user)).await.map_err(domain_to_status)?;
		// A member's row exists (`scope_members` references it); its absence is a race with
		// nothing, so it reads as the non-member's empty answer rather than an error.
		let Some(account) = found else {
			return Ok(NotificationSettings::default());
		};
		let sub = self.notifications.subscriber_of_user(user).await.map_err(domain_to_status)?;
		settings_of(self.notifications.as_ref(), view, account.email().as_str(), account.email_verified(), sub.as_ref())
			.await
			.map_err(domain_to_status)
	}
}

#[tonic::async_trait]
impl ScopeInboxService for ScopeInbox {
	async fn list_scope_notifications(&self, request: Request<ListScopeNotificationsRequest>) -> Result<Response<ListNotificationsResponse>, Status> {
		let reader = self.reader(&request, &request.get_ref().user_id).await?;
		let Some(user) = reader.member else {
			return Ok(Response::new(ListNotificationsResponse::default()));
		};
		let Some(sub) = self.notifications.subscriber_of_user(user).await.map_err(domain_to_status)? else {
			return Ok(Response::new(ListNotificationsResponse::default()));
		};
		let req = request.into_inner();
		let page = ListNotificationsRequest {
			cursor: req.cursor,
			limit: req.limit,
			unread_only: req.unread_only,
			topic: req.topic,
		};
		Ok(Response::new(inbox_page(self.notifications.as_ref(), &sub, &reader.view, &page).await?))
	}

	async fn get_scope_unread_count(&self, request: Request<GetScopeUnreadCountRequest>) -> Result<Response<GetUnreadCountResponse>, Status> {
		let reader = self.reader(&request, &request.get_ref().user_id).await?;
		let sub = match reader.member {
			Some(user) => self.notifications.subscriber_of_user(user).await.map_err(domain_to_status)?,
			None => None,
		};
		let unread_count = match sub {
			Some(sub) => inbox_unread(self.notifications.as_ref(), &sub, &reader.view).await?,
			None => 0,
		};
		Ok(Response::new(GetUnreadCountResponse { unread_count }))
	}

	async fn mark_scope_notifications_read(&self, request: Request<MarkScopeNotificationsReadRequest>) -> Result<Response<MarkReadResponse>, Status> {
		let reader = self.reader(&request, &request.get_ref().user_id).await?;
		let user = Self::member_only(&reader)?;
		let req = request.get_ref();
		let Some(sub) = self.notifications.subscriber_of_user(user).await.map_err(domain_to_status)? else {
			return Ok(Response::new(MarkReadResponse::default()));
		};
		Ok(Response::new(inbox_mark_read(self.notifications.as_ref(), sub.id, &reader.view, &req.ids, req.all).await?))
	}

	async fn get_scope_notification_settings(&self, request: Request<GetScopeNotificationSettingsRequest>) -> Result<Response<NotificationSettings>, Status> {
		let reader = self.reader(&request, &request.get_ref().user_id).await?;
		// A non-member's snapshot is empty to the address: the client is not told whose id
		// it named.
		let Some(user) = reader.member else {
			return Ok(Response::new(NotificationSettings::default()));
		};
		Ok(Response::new(self.settings(&reader.view, user).await?))
	}

	async fn set_scope_topic_subscription(&self, request: Request<SetScopeTopicSubscriptionRequest>) -> Result<Response<NotificationSettings>, Status> {
		let reader = self.reader(&request, &request.get_ref().user_id).await?;
		let user = Self::member_only(&reader)?;
		let req = request.get_ref();
		if !topic_offered(self.notifications.as_ref(), &reader.view, &req.topic).await.map_err(domain_to_status)? {
			return Err(Status::invalid_argument("unknown topic"));
		}
		let account = self
			.users
			.find_by_id(UserId::from_raw(user))
			.await
			.map_err(domain_to_status)?
			.ok_or_else(|| Status::failed_precondition("not an active member of this scope"))?;
		let sub = subscriber_of(self.notifications.as_ref(), &account).await.map_err(domain_to_status)?;
		self.notifications
			.set_topic_subscription(sub.id, &req.topic, req.subscribed, req.email_enabled)
			.await
			.map_err(domain_to_status)?;
		Ok(Response::new(self.settings(&reader.view, user).await?))
	}
}

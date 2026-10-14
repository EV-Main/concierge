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
//! named by the request on a READ because a client credential names no user; what keeps
//! that from being a key to anyone's inbox is that the user must be an active member of
//! the client's own scope and only that scope's topics are ever reached — the scope reads
//! back what its own services emitted. A WRITE needs the user's own say: following a topic
//! turns on mail to their address, so the client must also present the access token it
//! was issued for that user ([`USER_TOKEN_HEADER`]), and the user is taken from it. A
//! leaked client secret alone then reads a scope's own notifications and changes nothing.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use domain::users::UserId;
use evconcierge_auth::{AuthError, Authenticate};
use evconcierge_contracts::concierge::v1::{
	GetScopeNotificationSettingsRequest, GetScopeUnreadCountRequest, GetUnreadCountResponse, ListNotificationsRequest, ListNotificationsResponse, ListScopeNotificationsRequest,
	MarkReadResponse, MarkScopeNotificationsReadRequest, NotificationSettings, SetScopeTopicSubscriptionRequest, scope_inbox_service_server::ScopeInboxService,
};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{
	notification::{InboxView, inbox_mark_read, inbox_page, inbox_unread, settings_of, subscriber_of, topic_offered},
	ports::{NotificationRepository, UserDirectoryRepository},
	relying_party::ClientTokenAuthenticator,
	service_caller::{ClientCaller, ServiceCaller, ServiceCallers},
	support::domain_to_status,
};

const SEAM: &str = "scope inbox";

/// The metadata carrying the user's access token, as the client received it for that user
/// (raw, no `Bearer`): `authorization` already carries the client's secret.
pub const USER_TOKEN_HEADER: &str = "x-ev-user-token";

#[derive(Clone)]
pub struct ScopeInbox {
	callers: ServiceCallers,
	notifications: Arc<dyn NotificationRepository>,
	users: Arc<dyn UserDirectoryRepository>,
	/// The verifier that admits a client's user tokens to `GetMe`: their signature, `typ`,
	/// a client audience and a live session. `None` where no client is configured — every
	/// write is then refused.
	user_tokens: Option<ClientTokenAuthenticator>,
}

/// Whose inbox, through which scope. `member` is `None` for anyone the scope may not show
/// one to — an unknown id, a non-member and a disabled account are deliberately one case.
struct Reader {
	view: InboxView,
	member: Option<Uuid>,
}

impl ScopeInbox {
	pub fn new(callers: ServiceCallers, notifications: Arc<dyn NotificationRepository>, users: Arc<dyn UserDirectoryRepository>, user_tokens: Option<ClientTokenAuthenticator>) -> Self {
		Self {
			callers,
			notifications,
			users,
			user_tokens,
		}
	}

	async fn client<T>(&self, request: &Request<T>) -> Result<ClientCaller, Status> {
		let client = match self.callers.authenticate(request, SEAM).await? {
			ServiceCaller::Client(client) => client,
			ServiceCaller::Bridge => return Err(Status::permission_denied("the money plane's topics are in the platform inbox, not a scope's")),
		};
		if client.scope_closed {
			return Err(Status::failed_precondition("the scope is closed"));
		}
		Ok(client)
	}

	async fn reader<T>(&self, request: &Request<T>, user_id: &str) -> Result<Reader, Status> {
		let client = self.client(request).await?;
		let user = Uuid::parse_str(user_id).map_err(|_| Status::invalid_argument("user_id must be a concierge user id"))?;
		let member = self.notifications.is_active_scope_member(&client.scope, user).await.map_err(domain_to_status)?;
		Ok(Reader {
			view: InboxView::Scope { namespace: client.namespace },
			member: member.then_some(user),
		})
	}

	/// The inbox a write goes to and whose it is: the user the token was issued for, by THIS
	/// client. `user_id`, when the request sets it, must name the same user — a mismatch is
	/// a backend acting for someone the token does not speak for.
	async fn writer<T>(&self, request: &Request<T>, user_id: &str) -> Result<(InboxView, Uuid), Status> {
		let client = self.client(request).await?;
		let Some(tokens) = &self.user_tokens else {
			return Err(Status::unauthenticated("no user token can be verified on this plane"));
		};
		let token = request
			.metadata()
			.get(USER_TOKEN_HEADER)
			.and_then(|v| v.to_str().ok())
			.filter(|t| !t.is_empty())
			.ok_or_else(|| Status::unauthenticated(format!("a write needs the user's access token in {USER_TOKEN_HEADER}")))?;
		let claims = tokens.authenticate(token.to_owned()).await.map_err(|err| match err {
			AuthError::Unavailable => Status::unavailable("user token not verifiable now"),
			_ => Status::unauthenticated("invalid user token"),
		})?;
		if claims.aud != client.audience {
			return Err(Status::permission_denied("the user token was issued to another client"));
		}
		let user = Uuid::parse_str(&claims.sub).map_err(|_| Status::unauthenticated("invalid user token"))?;
		if !user_id.is_empty() && Uuid::parse_str(user_id).ok() != Some(user) {
			return Err(Status::permission_denied("user_id is not the user the token was issued for"));
		}
		if !self.notifications.is_active_scope_member(&client.scope, user).await.map_err(domain_to_status)? {
			return Err(Status::failed_precondition("not an active member of this scope"));
		}
		Ok((InboxView::Scope { namespace: client.namespace }, user))
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
		let (view, user) = self.writer(&request, &request.get_ref().user_id).await?;
		let req = request.get_ref();
		let Some(sub) = self.notifications.subscriber_of_user(user).await.map_err(domain_to_status)? else {
			return Ok(Response::new(MarkReadResponse::default()));
		};
		Ok(Response::new(inbox_mark_read(self.notifications.as_ref(), sub.id, &view, &req.ids, req.all).await?))
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
		let (view, user) = self.writer(&request, &request.get_ref().user_id).await?;
		let req = request.get_ref();
		if !topic_offered(self.notifications.as_ref(), &view, &req.topic).await.map_err(domain_to_status)? {
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
		Ok(Response::new(self.settings(&view, user).await?))
	}
}

# evconcierge_client — a relying party's calls into concierge

What a direction's backend (invest, admin, the Service-Arb panel) calls on concierge,
the EV identity plane. Server-side only: the client secret never reaches a browser.

- **Sign-in** is concierge's code flow with PKCE: `PkceVerifier` + `random_state` +
  `Authorize::url` send the browser to `/api/auth/authorize`; the callback redeems the
  code with `ConciergeClient::exchange_code`; `refresh_client_token` rotates the pair.
- **`get_me`** — the one RPC a relying party's access token opens, and where the party
  re-reads `permissions`, the only thing it may gate on.
- **`publish_catalog`** (permissions and aliases) and **`publish_scope_catalog`**
  (approval kinds and notification topics), under the client credential.
- **The direction's inbox** (`ScopeInboxService`): `list_scope_notifications` (an
  `InboxQuery`, 20 per page unless told otherwise), `scope_unread_count` and
  `scope_notification_settings` by concierge's `user_id`; `mark_scope_notifications_read`
  and `set_scope_topic_subscription` with the access token this client holds for the
  user, sent as `x-ev-user-token` beside the client credential.

```rust
use evconcierge_client::{Authorize, ClientConfig, ConciergeClient, PkceVerifier, random_state};

let concierge = ConciergeClient::connect_lazy(ClientConfig::new(grpc_addr, "sa", secret))?;
let verifier = PkceVerifier::generate()?;
let state = random_state()?;
let location = Authorize { concierge_origin, client_id: "sa", redirect_uri, state: &state, verifier: &verifier, prompt: None }.url();
// … the browser comes back with `code` …
let tokens = concierge.exchange_code(&code, redirect_uri, &verifier).await?;
let me = concierge.get_me(&tokens.access_token).await?;
```

Errors are values (`ConciergeError`), one arm per reaction: `Refused` ends the session,
`Unavailable` is worth a retry (`is_transient`), `Rejected` carries concierge's own
reason. Every call has a timeout (`ClientConfig::timeout`, 5 s by default).

The wire types are concierge's own `evconcierge_contracts` of the same release,
re-exported as `evconcierge_client::proto`. Building needs no `protoc` on `PATH`.

Keeping a copy of concierge's users (suspensions, grants, MEMBER_JOINED) is a different
job: the `evconcierge_projection` crate.

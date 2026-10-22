# Scopes, approvals and the relying-party event streams — contract

Status: **partly implemented.** The wire is in `contracts/proto/concierge/v1/scopes.proto`,
`approvals.proto` and the comments on `events.proto`. Implemented in `runner/`: the
registry (§3: `tenants` columns from migration 0031, `ScopeRegistry` mounted inside the
user auth layer; a CLOSED scope's clients are refused), sign-in from a scope's hosts
(§3.1: CORS and the `Origin` check on the closed route list, the passkey verifier's
origins, OAuth `returnTo`, the sign-up ticket of migration 0032), the micro-frontend
bundles under `/auth/mfe/*` (§3.1), the relying-party streams (§4: `ScopeEvents` and
`UserEvents` read by a client credential, migration 0034), the scope catalog's storage
(`ScopeCatalogService`, §5.1, §6), the scope topics in every inbox (§6: emit by namespace,
`default_subscribed`, the account-less subscribe, the move of the fund and money topics;
migrations 0041–0042) and the approvals of the kinds a namespace publishes
(§5.7: both approval services, this plane's own `concierge:*` kinds and their executor,
stored scope policies, the proven initiator and the pause after the owners change (D24(1),
(2)), the floor on the known money kinds and `ESCALATION_TEST_COUNT_ABOVE` (§5.3);
migrations 0036–0038) and the approval mail (§5.5, migration 0039). Banking, the `lib` projections, invest and admin build against this document.

Source decisions: the owner's D1–D20 and the approval levels and thresholds of the
organisation plan (2026-10-14). Where this document departs from the plan's wording it
says so and why.

---

## 1. Surface

| Service | File | Caller | Where it is mounted | Today |
| ------- | ---- | ------ | ------------------- | ----- |
| `ScopeRegistry` | scopes.proto | first-party session, `typ=service` token | inside the user auth layer | served (`runner/src/scopes.rs`) |
| `ScopeCatalogService` | scopes.proto | service credential (§2) | outside the layer, `BIND` and the TLS listener | served (`runner/src/scope_catalog.rs`) |
| `ScopeEvents` | scopes.proto | service credential (§2) | outside the layer, `BIND` and the TLS listener | served (`runner/src/scope_events.rs`) |
| `ScopeInboxService` | scope_inbox.proto | a relying party's client credential (§2); the bridge token on `EmitScopeNotification` only | outside the layer, `BIND` and the TLS listener | served (`runner/src/scope_inbox.rs`, §6) |
| `ApprovalService` | approvals.proto | first-party session | inside the user auth layer | served (`runner/src/approvals.rs`) |
| `ApprovalExecutionService` | approvals.proto | service credential (§2) | outside the layer, `BIND` and the TLS listener | served (`runner/src/approvals.rs`) |
| `UserEvents.PullUserLifecycle` | events.proto (unchanged wire) | bridge token, **and** a relying party's client credential | as today | served for both |

A relying party's restricted access token still opens exactly one RPC,
`UserDirectory.GetMe`. Votes are cast over a first-party session on `evinvest.ltd`,
which every direction's user already holds because sign-in happens there (D6, D7); the
restricted verifier is not widened.

### What did not change, and why

`auth.proto`, `directory.proto` and `governance.proto` are byte-identical to `7c71775`.
Banking vendors those three through its pin and `concierge-pin-check` compares their
bytes against `origin/main`, so an edit there turns banking's drift check red until it
bumps. More importantly, compatibility here is a property of Rust **source**, not only
of the wire: consumers build some messages with struct literals and implement some
server traits in their fakes, and either breaks at the next pin bump when the contract
grows a field or an RPC. As of banking `origin/main`:

| Banking does | With |
| ------------ | ---- |
| implements the server trait (test fakes) | `UserDirectory`, `AuthService`, `UserEvents` |
| builds with a struct literal | `PullUserLifecycleRequest`, `UserLifecycleEvent`, `SendGovernanceMailRequest` and its mail payloads, `UserProfile`, `PermissionGrant`, `GrantHolder`, `ListGrantsResponse`, the `UserDirectory` request/response messages |

So nothing was added to those messages or services. A catalog of approval kinds is
therefore **not** a new field on `PublishCatalogRequest`: it is
`ScopeCatalogService.PublishScopeCatalog`, which also gives banking — a service that
executes approvals but signs nobody in and owns no client secret — somewhere to publish.
Until it is implemented the new service answers `UNIMPLEMENTED` rather than accepting a
catalog and dropping half of it, which is what an ignored field on `PublishCatalog`
would have done. `contracts/tests/user_lifecycle_event.rs` pins
`PullUserLifecycleRequest` to its two fields and `UserLifecycleEvent.Kind` to its eight
values.

---

## 2. Service callers

The services marked "service credential" resolve the caller to a **namespace** (and the
scope it belongs to) from metadata alone:

| Credential | Caller |
| ---------- | ------ |
| `authorization: Bearer <BRIDGE_SERVICE_TOKEN>` | namespace `bank`, scope `main` — the money plane |
| `x-ev-client-id: <client_id>` + `authorization: Bearer <client_secret>` | the client's tenant namespace and scope |

Both are compared in constant time (a digest for the client secret, as
`relying_party` already stores it). A disabled client, an unknown client and a wrong
secret are the same `UNAUTHENTICATED`. Credentials never ride in a request body on
these services, so a logged request carries none.

Cost to weigh: the bridge token already opens `UserEvents` and `MailRelayService`; it
now also opens approval execution for `bank`. One secret, one trust relationship, as
before — and a bigger blast radius if it leaks. Graduating to `typ=service` tokens
(`AuthService.MintServiceToken`, reserved) replaces both forms without a wire change on
the request messages.

---

## 3. Scopes

A scope is a concierge tenant seen as a direction: `main`, `invest`, `sa`. It contains
resources (allocations and tooling alike, D16) and admins are appointed to it, never to
a resource (D2): an admin of a scope holds the `<scope>:admin` alias, which delegates
`<scope>:operator` as `sa:admin` does today.

- **`main`** is the implicit root: no tenant row, no namespace (`namespace` empty), its
  permissions are the seats' (`concierge:*`, `iam:*`, `bank:*`) and its deciders are
  the platform owners. Every other scope has `parent = "main"`. A scope id is
  `[a-z][a-z0-9_]{0,31}` here and on the money plane alike.
- **`state`**: `ACTIVE`, `FROZEN` (reversible: no new proposal opens in it and the money
  plane refuses new debits of its accounts; its clients still sign people in and its
  streams are still read) or `CLOSED` (terminal: its clients sign nobody in, nothing new
  opens, history stays readable).
- **`clients`**: a scope may have several relying-party clients (today one each: client
  `sa` in scope `sa`, client `invest` in scope `invest`, migrations 0025 and 0031).
- **`observers`**: client ids that may also READ this scope's events and its users'
  lifecycle. invest runs allocations of other scopes (the `service_arb` allocation lives
  in `sa`) and checks `sa:admin` to authorise `sa`'s admins there, so `sa` names
  `invest` as an observer. **An observer holds no right on the money plane**: which
  accounts a service may open, debit or read there is banking's own configuration of
  service grants, and nothing on this plane widens it.
- **Registry writes** are migrations and configuration, as `rp_clients` is today; there
  is no write RPC. Every change bumps `version` (migration 0031's triggers, a client's
  audience, `disabled_at` or scope included); `SCOPE_CHANGED` is to carry it once
  `ScopeEvents` is served.

### 3.1 `origins`: sign-in from a scope's hosts

`origins` are the scope's hosts exactly as a browser sends `Origin`, and they are held to
rules a configuration slip cannot loosen:

- `https` only; the host ends in `.evinvest.ltd` — the bare `evinvest.ltd` is
  `PUBLIC_ORIGIN`, never a scope's; a port (1-65535) only when non-default; no path, no
  trailing slash, no wildcard, never `null`;
- compared byte for byte; the answer carries `Access-Control-Allow-Origin` set to exactly
  the matched origin and `Vary: Origin`.

They widen CORS for a **closed list** of sign-in routes and nothing else:

| Accepts a scope origin | `PUBLIC_ORIGIN` only |
| ---------------------- | -------------------- |
| `/auth/code/request`, `/auth/code/verify`, `/auth/password/signin`, `/auth/password/signup`, `/auth/password/signup/confirm`, `/auth/password/signup/resend`, `/auth/passkey/signin/*`, `GET /auth/session` (answers `{authenticated, user, permissions}`, never a token), `POST /auth/notifications/subscribe` (account-less; acts for no account) | everything acting on an open session or reading the account: `/auth/email/verify/*`, `/auth/password/set`, `/auth/passkey/register/*`, `/auth/passkey/remove`, `/auth/sessions`, `/auth/username`, `/auth/methods`, `/auth/me`, `/auth/notifications/settings*`, `/auth/logout`, `/auth/logout/confirm`, `/kyc/*` |

Signing out on a scope host ends the `evinvest.ltd` session too when the host sends the
browser — a top-level navigation, not a call — to
`https://evinvest.ltd/api/auth/logout/confirm?return_to=<scope origin + one of its return
paths>`. That is a page on this origin, styled in the platform palette and localized from
`Accept-Language` (en, ru, de, fr, vi), with one button and a Cancel link back to the
checked `return_to`; the button's form carries the session's CSRF token and comes back
with a 303 to `return_to`. Its CSP opens `style-src 'unsafe-inline'` for the page's own
`<style>` and nothing else. Without a session the page
answers the 303 at once.

**Every scope whose hosts mount the account chip or the account page lists `/` in its
`return_paths`.** Both (`web/` and `@evinvest/concierge` in `sdk/`) sign out to the host's
root, `<scope origin>/`, and the page above answers any `return_to` whose path is not in
the list with 400 — the host's own session ends and the `evinvest.ltd` one stays. `sa` has
listed `/` since migration 0031; `invest` since 0035, which appended it beside `/cabinet`.

A route on the left accepts an `Origin` that is `PUBLIC_ORIGIN` or an origin of a scope
that is `ACTIVE` or `FROZEN` — a frozen scope's clients still sign people in — and never
one of a `CLOSED` scope. The right column carries the CSRF double-submit, whose cookie a
scope host cannot read, so email verification is not offered there. A password sign-up
started on a scope host is confirmed instead by `/auth/password/signup/confirm` with the
ticket the sign-up answered (migration 0032; the ticket lives a day, and
`/auth/password/signup/resend` mails a new code under it): the address is verified and the
password kept, where a code SIGN-IN on that mailbox would take the unverified account
over. The sign-up hands a ticket out only when it was asked to mail a code (`verify`);
if the ticket cannot be stored the answer says `ticket: null` with
`ticket_error: "ticket_unavailable"` and the address is confirmed on `evinvest.ltd`
instead. A ticket that is unknown, spent, expired or outlived by a revoke-all or a new
password answers `/confirm` as a wrong code does, and `/resend` with `{ok: true}` and no
mail.

The allowlist is re-read from the registry at most 30 s apart (`web::allowlist`), so
closing a scope or removing an origin takes effect without a restart. An absolute OAuth
`returnTo` must be one of these origins plus a path from the scope's `return_paths`,
matched exactly, or `/auth/login` answers 400; a relative or empty one lands on `/` as it
always did.

**Micro-frontend bundles.** `GET /auth/mfe/*` — publicly
`https://evinvest.ltd/api/auth/mfe/*`, under the conductor's `/api/auth/*` rewrite — serves
the directory `WEB_MFE_DIR` names; the manifest hosts read is `registry.json`. It is
public and read-only: a scope origin gets `Access-Control-Allow-Origin` (no credentials)
and `Vary: Origin`, files only (no index, no listing, no dotfile, nothing resolving
outside the directory), esbuild-hashed names cached for a year and everything else for
five minutes. With `WEB_MFE_DIR` unset or unreadable the route is not mounted and sign-in
is unaffected; the image sets it only once `web/` exists in this repository.

---

## 4. Event streams for relying parties

### 4.1 Visibility

Implemented in `runner/` as `scope_members` (migration 0034): a row is inserted, never
deleted, on the user's first relying-party session with one of the scope's clients
(`joined_by = sign_in`) or their first grant in its namespace (`grant`), in the same
transaction. Grants and sessions that predate the table are backfilled at boot.

A user is **visible to scope S** once they have signed in through one of S's clients, or
held a grant in S's namespace. Visibility only grows: an account whose grants are all
revoked stays visible, because the direction still has to learn that it was suspended.
That also keeps a re-pull of an old position stable, which parking (§4.3) relies on.

A client sees the users and the scope events of its own scope and of every scope that
names it an observer. The bridge token sees everything.

### 4.2 The two streams

**Cursor, on every concierge pull stream:** `next_position` is the **maximum position
scanned** for the caller — past the last event returned when the rows after it were not
the caller's to see, so a filtered reader never re-scans them; unchanged when nothing
was scanned. To the unfiltered reader (the bridge token) that is the max position
returned, which is what banking stores today. A page that **fills `limit`** stops scanning at its last
event, so its `next_position` is exactly that event's `position`; with `limit = 1` and
one event returned, `next_position` is that event's position. The
`evconcierge_projection` crate (`projection/`) relies on this to replay a parked event (§4.3) and confirm it got
that one; the scan runs past the last event only when the page did not fill.

**`UserEvents.PullUserLifecycle`**, read by a client credential: same request,
filtered by visibility, and each row redacted — `seat_permissions` absent and
`permissions` empty. `kyc_level` is carried: directions layer their own policy on the
KYC level and may not manage it (D5).

**`ScopeEvents.PullScopeEvents`** is a separate stream because `UserLifecycleEvent.Kind`
is the money plane's vocabulary: banking stops its single cursor on a kind it cannot
name (`piggybank/core/src/infrastructure/bridge.rs`), so `SCOPE_CHANGED` or
`GRANTS_CHANGED` there would freeze the mirror of every suspension and KYC change behind
it until banking redeployed. Kinds:

| Kind | Carries | Ordered by |
| ---- | ------- | ---------- |
| `SCOPE_CHANGED` | the whole `Scope` after the change, `state` included | the scope's `version` |
| `GRANTS_CHANGED` | the user's whole concrete permission set in that scope (present-and-empty = holds nothing, apply it) | per (scope, user) `sequence` |
| `MEMBER_JOINED` | the identity snapshot a projection seeds from (`ScopeMember`) and the lifecycle `sequence` it is as of | per (scope, user) `sequence` |

A user is keyed by `auth_subject` on every plane and in every approval field. A
direction seeds a user's row from `MEMBER_JOINED` and applies lifecycle events whose
`sequence` exceeds `lifecycle_sequence`. Parking a lifecycle event whose
`MEMBER_JOINED` has not arrived yet is a requirement on `lib`'s projection; the
contract does not change for it. Snapshots, not deltas, so a redelivery is harmless and
two events can never disagree about the current set.

Banking reads `ScopeEvents` with the bridge token, learns scopes and their `state` from
`SCOPE_CHANGED` and opens compartments only for known scopes.

As implemented (`scope_events`, `bridge`, `infrastructure::scope_events`):

- every event is written in the transaction of the change it describes — a grant or
  revocation, a tenant catalog publication, a ROLE_CHANGED (a seat moves what it holds
  where `granting_seats_hold_all`), a relying-party session — and `SCOPE_CHANGED` by a
  trigger on `tenants`, which also fires for a client's audience, disabled flag or tenant
  moving (0031 bumps the scope's `version` for those);
- `GRANTS_CHANGED` carries what `GetMe` answers that scope's client — by the PERSISTED seat;
  emergency access is per request and never on the stream — and is written only when the
  set actually moved;
- a client is served lifecycle rows of a user only past the `lifecycle_sequence` its
  `MEMBER_JOINED` carried: history before the user became visible is not a direction's;
- a filtered scan reads at most 5 000 rows per call, and the cursor moves past what it
  scanned;
- what a binary of the previous release changes during a rollout (a grant, a role, a
  catalog) reaches the stream at the next boot (`scope_events::reconcile`), not before.

### 4.3 A kind the consumer cannot name

Concierge ships ahead of its consumers, so an unknown kind is the ordinary shape of a
mid-rollout event; prost decodes it as `KIND_UNSPECIFIED`. The rule depends on what a
swallowed event would cost (decided):

- **Money (banking): Halt, on both streams.** The cursor stops on the event and the
  consumer alerts; upgrading the binary is the only thing that unblocks it. Marking it
  applied is how a freeze or a scope closure gets swallowed while money keeps moving
  under rules this plane already revoked.
- **Directions (invest, sa, admin, via the `evconcierge_projection` crate): Park.** Record
  the event's `position` and `event_id`, advance the cursor, and replay after an
  upgrade by re-pulling with `after_position = position - 1, limit = 1`. Park the
  POSITION, not the decoded event: prost drops fields it does not know, so a stored
  decode is exactly the copy that lost what the new kind carried, while concierge keeps
  every row at full fidelity for ever.

An unknown FIELD on a known kind is ignored by every consumer (proto3). An emitter that
needs an old consumer to act differently therefore needs a new kind, never just a new
field — `seat_permissions` was built that way. Deploy order stays: consumers before
emitters.

---

## 5. Approvals

The owners' consilium (`governance.proto`, banking's `docs/CONSILIUM.md`) generalised to
every scope. `GovernanceService` and `MailRelayService` stay as they are until the
contract step of the reorganisation (the people's decisions have a second home in the
`concierge:*` kinds below); the new kinds replace banking's consilium
tables, whose foreign keys become `subject_ref`s on banking's side.

### 5.1 One owner per kind: proposer = executor

A kind belongs to the namespace that published it (`ApprovalKindSpec.proposer`), and
that namespace is the kind's **only proposer and only executor**: only it opens a
proposal of the kind (`Propose`), reads it as a service (`GetProposal`), pulls its
decisions (`PullApproved`) and reports their outcome (`ReportOutcome`). Nobody presents
someone else's decision as authority for an act of their own — a decision is never a
token another service can carry to the money plane.

So a direction that needs money moved does not hold an approval: it asks banking
(banking's `RequestPayout`/`RequestTransfer`), banking stores the request whole, opens
the `bank:*` proposal with every money field, executes it from `PullApproved` — one
decision, one execution, unique by approval id on banking's side — and reports the
outcome. Banking opens these proposals with `subject_ref = pending_operation:<operation_id>`,
and the direction follows the operation by that `subject_ref` on banking's money stream.

Kinds are published whole with `ScopeCatalogService.PublishScopeCatalog` (versioned like
`PublishCatalog`); `concierge:*` kinds are this plane's own, built in at version 0. A
relying party opens proposals of its kinds in its OWN scope only; the bridge token
(`bank`) in any registered `ACTIVE` scope, because the money plane holds every scope's
accounts (decided at review, 2026-10-14). ⚠️ This departs from the earlier wording, under
which invest would propose `invest:valuation_override` in `sa` because the allocation is
there: as decided, that proposal is refused until the rule is revisited.

`Approval.proposer` is the kind's namespace; `Approval.requested_by_client` is the
client whose credential opened it, for the audit trail only.

A kind declares (`ApprovalKindSpec`): a label and description in plain text; its
**level** before escalation; its **fields**, each with a type from a closed set
(`TEXT`, `AMOUNT`, `BPS`, `FLAG`, `USER`, `TIMESTAMP`, `COUNT`) that this plane knows
how to render; and its **escalations**, each naming a field, a test and a default
threshold. A `USER` field carries an `auth_subject`. An escalation must test a REQUIRED
field: a test over a field the proposer may leave out is one it may switch off.

### 5.2 Who decides

| Level | Roster | Threshold | Delay (veto window) | Lifetime |
| ----- | ------ | --------- | ------------------- | -------- |
| `PLATFORM` | persisted `owner` seats (break-glass seats nobody) | more than half of the roster | 24 h, veto by any roster member | 72 h |
| `SCOPE` | active holders of `<scope>:admin` | the scope policy's `quorum_bps`, default more than half of the roster | the policy's `delay_secs`, default 1 h, veto by any roster member or any platform owner | the policy's `ttl_secs`, default and ceiling 72 h |

At either level a passed decision is executable for 72 hours after its delay and then
lapses to `VOID`; any persisted owner may veto ANY proposal inside its delay (decided:
containment is never slower than the grant).

- **Quorum is over the whole roster frozen at open:**
  `threshold = max(1, ceil(roster × quorum_bps / 10000))`, platform at 5001 bps. For a
  service's proposal nobody is excluded: a service cannot prove which person asked it, so
  the person it names (`requested_by`, an `auth_subject`) is information shown to voters
  — it moves no quorum and keeps nobody off the roster. For a `concierge:*` proposal the
  opener is proven by their session and is kept off the roster (D23), and so is the
  account a `scope_admin_grant` would seat, when an owner: nobody votes on
  what they asked for, or on their own seat. A `PLATFORM` proposal is refused at open (`FAILED_PRECONDITION`)
  with fewer than two owners, or when nobody besides the one who asked and the one it would
  seat is left to decide. ⚠️ For the owner's attention, kept as decided: with three owners,
  one opening a grant for another leaves a roster of one, so that grant is decided by a
  single owner.
- **A proven initiator of a money decision does not decide it** (D24(1)): a proposer may
  present, in metadata `x-ev-user-token`, an access token of this plane that `requested_by`
  holds (banking forwards the owner's). Verified as every RPC here verifies one, its `sub`
  must be `requested_by`, the account still active at that token's `token_version`, the
  token minted no more than 120 s before the call, its `auth_time` no more than 120 s
  before the call too (concierge#171), neither claim dated more than 30 s after the call
  (the replicas' and the database's clocks may drift that much, and no more), and never
  used before. The transaction that opens the proposal spends two digests in
  `approval_initiator_proofs`: the token's SHA-256, and the SHA-256 of
  `reauth:<user id>:<auth_time>`. So one token proves one request, and so does one
  re-authentication: every refresh inside the window mints another token with the same
  `auth_time`. A young token alone is not
  enough: a refresh mints one and keeps the session's old `auth_time`, so it shows only
  that the session was alive. The person re-authenticates first (`/auth/reauth/*` moves
  `auth_time` to now and re-sets `ev_access`), and the proposer then presents that token.
  Every refusal of the proof itself is `FAILED_PRECONDITION` with a message that starts
  with `reauth_required: `: a token or an `auth_time` older than 120 s or more than 30 s
  ahead, a missing `auth_time`, and a spent proof ("this proof was already spent"). A
  proposer matches that word, sends the person through re-authentication and retries with
  the new token. An `auth_time` ahead of the clock does not move back on a
  re-authentication (the session store never moves it backwards), so that message asks
  the person to sign in again. What that proves is honest and narrow: the person proved
  themselves to this plane within the last two minutes and the service held the token that
  says so — not that they read the proposal. When the proposal resolves to `PLATFORM` that person is kept off the roster,
  the proposal says `requested_by_proven`, and — if they were on that roster, i.e. an
  owner — they get an inbox notice (topic `account:money-movement`, no link, no code) that a
  decision was opened in their name: if they did not ask for it, their veto stops it. A
  proven account that is no owner has no vote and no veto there, and is not told. A retry
  under the same `dedupe_key` with a token is checked as the first call was and spends
  nothing; a proposer mints a fresh token for each retry. Two OTHER ACTIVE owners must remain
  (`FAILED_PRECONDITION`, code word `not_enough_owners_besides_initiator`; a proposer must
  not retry it without the token): one owner must not decide another's money alone, so
  0036's floor of two for a service's proposal is not relaxed, and a held owner, who has no
  say, does not count towards it. At scope level a proven initiator stays on the roster, as
  every admin does. Without a token the name stays information.
- **The platform pauses after its owners change** (D24(2)): any change of the owner roster
  — a seat granted or taken, an owner suspended indefinitely by the consilium's verdict
  (`suspended_by = governance`) or reinstated from one, on any path, written by any binary —
  voids every live `PLATFORM` proposal in the same transaction (`void_reason` "the
  platform owners changed while it was live", history event `roster_changed`) and stamps
  `roster_changed_at`; for the platform policy's `cooldown_secs` after it (default 48 h,
  0..=14 days, changed only by `concierge:platform_policy`) no `PLATFORM` proposal opens
  (`FAILED_PRECONDITION`) — a service's escalated one, a money one and this plane's own
  alike. A scope's own decisions do not pause. A temporary HOLD on an owner (`admin_hold`)
  and its release, by the sweep or by `ReinstateUser`, are not a change (owner's decision):
  the held owner simply has no vote while held, and one operator's brake must not also void
  the owners' decisions and pause the platform.
- **A vote is the seat's** (decided): a vote counts only while its voter still holds the
  seat the roster was drawn from — for an owner, the persisted `owner` role AND an active
  account, so a suspended owner has no say. Removing an admin after their FOR takes it
  back and the proposal needs another vote to pass. It is `REJECTED` only when seated
  voters cast more AGAINSTs than the roster can spare (more than roster − threshold); a
  proposal that can no longer be carried only because seats were lost stays `OPEN` until it
  expires — a removal is not a vote against (review of #140). `voters` on
  `Approval` still shows every vote as cast: whether one counts is decided from the seats
  at each vote, not stored on it. A proposal that already PASSED is not reopened when its
  voters lose their seats: inside the delay any owner (or remaining roster member) vetoes
  it (§5.6).
- **Escalation to `PLATFORM`** happens at open and is frozen with the roster
  (`Approval.escalated_by` says why):
  - any declared escalation test fires against the scope's threshold (or the kind's
    default when the policy names none);
  - **`sole_admin`**: the scope has fewer than two admins, so one person would decide;
  - a proposal in scope `main` is always `PLATFORM`.
- **Tests:** `AMOUNT_ABOVE` (an amount in another currency than the parameter's escalates
  — fail safe); `ROLLING_24H_AMOUNT_ABOVE` — the amount plus, among scope-level proposals
  of the same kind and scope, every **live** one (open, or passed and not lapsed) however
  long ago it was opened, and every one **executed** in the trailing 24 h, counted from
  its execution (decided: counting only executed ones would let proposals opened together
  each pass under the window and then execute together above it; counting from the
  opening instant would let a proposal kept open a day drop out while still able to pass,
  and an execution count from when it was asked rather than when the money moved; a
  proposal that ends rejected, vetoed, expired, cancelled or void stops counting);
  `ABS_BPS_ABOVE`; `FLAG_SET`; `COUNT_ABOVE` (a COUNT field above an integer threshold —
  a payout to more recipients than that).
- **The scope policy** (`ScopeApprovalPolicy`: quorum, delay, lifetime, threshold
  overrides) is changed only by `concierge:scope_policy_change`, which is always
  `PLATFORM`: a scope able to lower its own thresholds would decide for itself what
  needs the owners. It does not carry compartment limits — those are the money plane's
  `bank:compartment_policy`. The new policy is validated at open and again at execution
  against the catalogs then in force.

### 5.3 Kinds

**The floor this plane keeps** (D24, decided by the session; `domain::floors`, one
table). Whatever a publisher's catalog says:

- `bank:payment`, `bank:scope_transfer`, `bank:seed_capital`, `bank:treasury_surplus`,
  `bank:compartment_policy`, `invest:holder_grant` and `invest:fee_policy` are decided by
  the platform owners. A fee change is the owners' whole (EV-Fund/invest#37, 2026-10-22):
  an escalation on a raised ceiling alone would leave a hurdle-only lowering to the scope.
  So is any kind of the `bank` and `invest` namespaces the table does not name — an
  allow-list: a money kind added to a catalog before it is added here goes to the owners. A
  kind of those namespaces that moves no money is named in the table as unbounded.
- `bank:account_transfer` escalates above 1000 USDT on `amount` and above 5000 USDT a day.
- `bank:scope_payout` escalates above 1000 USDT on `total`, above 5000 USDT a day, above one
  `recipients` (COUNT), above one recipient a day (`ROLLING_24H_COUNT_ABOVE` — a payout
  split into single-recipient ones is still one distribution), when `distribution` (FLAG,
  a dividend to every holder) is set, when `over_scope_budget` (FLAG, the single daily scope
  budget) is set, and when `recipients` is 0.
- `invest:valuation_override` escalates above 10 % (`deviation`, 1000 bps).

The two money caps — 1000 USDT per operation and 5000 USDT a day, one pair for both kinds —
are defaults: the runner reads them at boot from `APPROVAL_FLOOR_PER_OPERATION_USDT` and
`APPROVAL_FLOOR_DAILY_USDT` and refuses to start on anything but a positive canonical amount.
They are environment and not data because the table guards against a compromised publisher:
moving them is a reviewed change in the devops repo, by the platform owners, with no release.

It binds twice. A publication of such a kind at scope level without a field the floor
tests, or with an escalation of that test and field above the cap or in another currency,
is refused; at the platform level it is stricter and accepted as it is. A proposal is
measured against the kind as `ListApprovalKinds` shows it: the catalog's escalations
capped at the table's, and the table's own beside them, always, under names this plane
reserves (`floor_*`, which no publisher may use) — so a catalog stored before the table,
or published wrong, cannot keep from the owners what the table sends them.
`GetScopeCatalog` still answers the publisher what it published.

A scope policy may only tighten, from the stricter of the table and the catalog. Its
threshold binds by what it tests, not by name: it holds every escalation of the same test,
field and currency as the one it names, and an executed policy change anchors a threshold
on a catalog escalation onto the floor's parameter of the same test. A publisher's next
catalog — dropping, renaming or loosening its own escalation — therefore never loosens a
scope's stored tightening (review of #142). A catalog is republished whole, so one stored
kind that breaks the floor blocks the namespace's next publication until that kind is
fixed.

`bank:*` — final; banking is the only proposer and executor of each.

| Kind | Level | Escalations (default) | Fields |
| ---- | ----- | --------------------- | ------ |
| `bank:payment` — from a scope account off the platform (L1) only | PLATFORM | — | tier, source, destination (TEXT), amount |
| `bank:scope_transfer` — between two scopes; opened in the SOURCE scope | PLATFORM, always | — | from_account, to_account (TEXT), amount |
| `bank:account_transfer` — between accounts of one scope | SCOPE | `per_operation` AMOUNT_ABOVE 1000 USDT; `daily` ROLLING_24H_AMOUNT_ABOVE 5000 USDT | from_account, to_account (TEXT), amount |
| `bank:scope_payout` — discretionary payout from a scope account to users | SCOPE | `per_operation` AMOUNT_ABOVE 1000 USDT on `total`; `daily` ROLLING_24H_AMOUNT_ABOVE 5000 USDT on `total`; `distribution` FLAG_SET | from_account (TEXT), total (AMOUNT), recipients (COUNT), recipient (USER, only when there is one line), lines_digest (TEXT), distribution (FLAG) |
| `bank:seed_capital` | PLATFORM | — | to_account (TEXT), amount |
| `bank:treasury_surplus` | PLATFORM | — | amount, destination (TEXT) |
| `bank:compartment_policy` — a scope's compartment limits, default mandates, automatic ceilings | PLATFORM | — | banking's to define |

`lines_digest` is SHA-256, lowercase hex, over the UTF-8 bytes of the payout's lines,
each `<auth_subject>|<amount>` with the amount in this plane's canonical decimal, sorted
bytewise and joined by `\n` with no trailing `\n` — the same definition as banking's,
which computes it over the payout it stored. A
distribution to every holder of an allocation is a `bank:scope_payout` with
`distribution` set, which always escalates — there is no separate dividend kind.

`invest:*` — **proposals; invest confirms them.**

| Kind | Level | Escalations (default) | Fields |
| ---- | ----- | --------------------- | ------ |
| `invest:valuation_override` | SCOPE | `max_deviation` ABS_BPS_ABOVE 1000 (10 %) | allocation (TEXT), mark (AMOUNT), deviation (BPS) — invest still refuses beyond the 50 % cap before proposing |
| `invest:fee_policy` — a fund's fee terms beyond the house envelope, or a lower hurdle; published by invest | PLATFORM | — | allocation (TEXT, the fund); current_ and proposed_ management, performance, hurdle (BPS); current_ and proposed_ basis, crystallization (TEXT); raises_ceiling (FLAG, informs only); effective_from (TIMESTAMP); holders_notified (COUNT). The reason is the proposal's own `reason` |
| `invest:holder_grant` | PLATFORM | — | allocation (TEXT), holder (USER), units (AMOUNT, unit code) |

`concierge:*` — this plane's own, built in at catalog version 0 (listed by
`ListApprovalKinds` first), opened over `ApprovalService` and carried out by this plane's
executor loop once passed (D23).

| Kind | Level | Opened by | Fields | Executed as |
| ---- | ----- | --------- | ------ | ----------- |
| `concierge:scope_admin_grant` | PLATFORM | a seat holding `iam:tenants:grant`, for an account with a VERIFIED address | account (USER) | a grant of `<namespace>:admin`, `granted_by` the opener; VOID if the account is no longer active or verified, or the scope no longer active |
| `concierge:platform_policy` | PLATFORM | a persisted owner | cooldown_secs (COUNT) | the platform's next policy `version` |
| `concierge:scope_policy_change` | PLATFORM | such a seat, or an admin of the scope | quorum_bps, delay_secs, ttl_secs, thresholds (COUNT), and one `threshold` TEXT field per override, `<kind>/<parameter>=<value>` — the values are in `payload_hash`; the whole policy is also `Approval.proposed_policy` | the scope's next policy `version`, checked again against the catalogs then in force; VOID if it no longer fits |

The decisions about **people**, moved here from `GovernanceService` (expand step; the old
service keeps working beside them until the contract step). All five are `PLATFORM`, in
scope `main`, with `account (USER)` and `reason (TEXT)` fields, opened over `ApprovalService`
by an active persisted owner, who is kept off the roster, as is the account they are about
(`Action::People`; subject_ref `user:<uuid>`, one live decision per kind and account).

| Kind | Bar | Executed as |
| ---- | --- | ----------- |
| `concierge:owner_admission` | UNANIMITY of the owners besides the opener | `Role::Owner`; VOID if the account holds the seat, is inactive or unverified |
| `concierge:owner_removal` | UNANIMITY of the owners besides the opener and the target | back to `investor`; VOID if it would leave fewer than two seats (`MIN_OWNERS`) |
| `concierge:user_suspension` | more than half of the owners besides the opener | `suspended_by = governance`, no expiry |
| `concierge:user_reinstatement` | as suspension | lifts a verdict the owners imposed; VOID if there is none |
| `concierge:admin_admission` | as suspension | `Role::Admin`; VOID over an owner or an admin |

Unanimity is the quorum at 10000 bps over the frozen roster (`platform_quorum_bps`): the
reason the legacy consilia were unanimous holds — a minority able to add or remove owners by
majority grows itself into a majority. The target of a removal is not asked, as the legacy
peer set did not ask them, and the emailed self-accept is gone: the target has no vote and
no veto over a decision about their own standing (nobody judges their own seat); any other
owner vetoes inside the delay, as on every platform decision. A FOR counts only while its
voter holds the seat, so a held owner cannot carry a unanimous decision, and execution
counts the seated FORs again against the threshold (a decision whose voters left is VOID).
The floor, the 48 h pause (D24(2)) and the voiding of live platform decisions on a change
of the owners apply as to every platform decision. `Role::Owner` is written by genesis and
by the executor of an executed `owner_admission`, and (until the contract step) by the
legacy service. An execution takes the governance revision, every owner's `users` row and
the two accounts, and only then the proposal; it records its outcome BEFORE writing the
seat, so the trigger that voids live platform decisions finds this one already executed.

`ApprovalService.ListOwners` and `ResignOwnership` (same gate, same typed confirmation, same
floor) replace the legacy pair, and `GetApprovalsRevision` replaces `WatchGovernance`: a
number that moves whenever an approval or the owner roster does, which a console polls and
refetches on a change — no stream. `GOVERNANCE_NEW_VOTES_CLOSED=true` closes the legacy
openings (they answer `FAILED_PRECONDITION` naming the RPC above) and
`GovernanceService.DrainLegacyProposals` voids the open legacy proposals by list, so the
window can be emptied.

Review hardening of these kinds:

- **The floor counts seats that can still decide.** `MIN_OWNERS` is measured over owners that
  are active or only on a temporary hold (`admin_hold` lapses); an owner suspended by the
  owners' verdict keeps the role and has no say, so it is not counted — by an owner removal,
  at open and at execution, and by `ResignOwnership` (the legacy resignation shares the code).
  Two suspensions and a resignation cannot leave one voice.
- **A person is not told the tally of a decision about them** (`Reader::Subject`: they read
  that it exists and its state, not who voted what, nor the deciders' addresses), cannot veto
  it, and cannot hold anyone while a live `owner_removal` or `user_suspension` names them
  (`hold_user` refuses). A hold extends only under a LIVE decision — open and not past its
  deadline, or passed and inside its execution window — the same predicate
  `Decision::effective_state` projects.
- **One owner holds at most `MAX_LIVE_PEOPLE_PER_OPENER` (5) live decisions about people**
  (`ResourceExhausted`); the proposer's cap of 200 is not theirs to fill.
- **An execution writes the person under `FOR NO KEY UPDATE`**, so a vote or an opening (an
  insert into `approval_voters`, a foreign key to `users`) is not queued behind it.
- **A stored `action` this binary cannot decode reads as none**: the proposal lists, votes and
  vetoes, and the executor voids it. That protects reads in a rollback, not execution.
- **Legacy decisions are void when an owner they never asked is seated** meanwhile (admission,
  removal and the user proposals compare the roster at settlement with their snapshot).
- `UserDirectory`'s raw `set_role` exists only under the `test-support` feature; a test scans
  the source for every call site of the aggregate's `set_role`, raw `SET role` and user
  inserts. A database trigger on `role = 'owner'` was weighed and left out: `update_row`
  rewrites `role` on every account mutation, genesis and the legacy consilium write it, and
  older binaries run beside this one during a rollout.
- **To do later:** `Propose*`, `ResignOwnership` and voting should require a fresh `auth_time`
  (re-authentication, #168); they do not yet.

**Rollout order (the window).** (1) deploy with `GOVERNANCE_NEW_VOTES_CLOSED=true`; (2)
`DrainLegacyProposals` every open legacy proposal (list them with the `List*` RPCs of
`GovernanceService`); (3) only then admit owners through `approvals` — a legacy decision still
open when an owner is seated that way is void, but the window is cleanest empty. To roll the
binary back, close the openings, withdraw or veto the live `concierge:owner_*`,
`user_suspension`, `user_reinstatement` and `admin_admission` decisions, and
`UPDATE approvals SET action = NULL WHERE kind IN (...)` for any left, before starting the old
binary: it cannot decode the `people` action.

Assigning an operator in a scope is still a delegated `GrantPermission` by a
`<scope>:admin`, with no approval.

### 5.4 Life of a proposal

```
OPEN ──(threshold met)──▶ PASSED ──(executable_at passes; proposer pulls)──▶ EXECUTED
  │                         │                                               EXECUTION_FAILED
  │                         ├─ veto ─▶ VETOED                                VOID
  ├─ votes against ─▶ REJECTED
  ├─ expires_at ─▶ EXPIRED   (lazy, like the governance consilia)
  └─ proposer withdraws ─▶ CANCELLED   (also from PASSED inside the delay)
```

- **Propose** (`ApprovalExecutionService.Propose`): the proposer has already decided the
  person may ask (it owns that surface). `subject_ref` is `<type>:<uuid>` — `type`
  `[a-z][a-z0-9_]{0,31}`, a lowercase hyphenated UUID, at most 128 bytes, the same rule
  on both planes — opaque here beyond that shape and never shown to voters; at most one
  live (`OPEN`/`PASSED`) proposal per kind, scope and `subject_ref`. Idempotent by
  `dedupe_key` per namespace.
- **Text** — `TEXT` fields, `reason`, a veto reason, an outcome detail — is one line,
  bounded, refused if it carries a control character or a link (`://`, `www.`), and
  rendered attributed to whoever wrote it, never as this plane's own words. There is no
  free-form markup anywhere: the mail is rendered here from the kind's labels and the
  typed values (`USER` resolved from its `auth_subject` to the account's email here,
  `BPS` to a percentage here).
- **Veto** by any roster member who still holds the seat, or by any persisted owner on any
  proposal, and **withdrawal** by the proposer
  (`WithdrawProposal`) — or, for a `concierge:*` proposal, by the person who opened it
  over a session (`CancelApproval`) — are possible while `OPEN` and while `PASSED`
  before `executable_at`. After that the proposer owns the proposal and only
  `ReportOutcome` moves it.
- **Pull** (`PullApproved`) serves `PASSED` proposals of the caller's namespace whose
  `executable_at` is behind the clock and whose `execute_by` (`executable_at` + 72 h, on
  `Approval`) is more than an hour ahead, with no outcome, oldest first: whatever a
  proposer pulls it still has an hour to report. At `execute_by` the decision lapses to
  `VOID` (`void_reason` says so, no outcome) and a report on it is refused. A pull
  claims nothing: the same proposal is served on every pull until its outcome is
  reported, so the proposer is idempotent per proposal id. A pulled decision can still go
  `VOID` before the proposer acts — the owners changed (§5.2) — and a pull is not told:
  the money plane re-reads the proposal (`GetProposal`) immediately before it moves money,
  and acts only on `PASSED`. Executable is a time
  predicate over `PASSED`, not a state, so nothing has to sweep for a proposal to become
  pullable.
- **`payload_hash`** binds what was approved to what is executed. The proposer computes
  it over the operation it STORED when it proposed, compares it at execution, and
  refuses to act on a mismatch: SHA-256, lowercase hex, over the UTF-8 bytes of

  ```
  ev-approval-v1\n<kind>\n<scope>\n<subject_ref>\n
  ```
  followed by one line per field, sorted by key: `<key>\t<type>\t<value>\n`, where
  `<type>` is the enum suffix (`AMOUNT`, `BPS`, …) and `<value>` is the text verbatim,
  `<value> <currency>` for an amount (the canonical decimal is enforced at Propose for
  exactly this reason), the decimal integer for `BPS`/`TIMESTAMP`/`COUNT`,
  `true`/`false` for a flag, and the `auth_subject` for a user. No field may contain a
  tab or a newline, so the encoding is unambiguous.
- **ReportOutcome**: `EXECUTED`, `FAILED` (terminal; a retry is a new proposal) or
  `VOID` (no longer applies; nothing attempted). Repeating the same outcome is a no-op.
- **What a service reads**: the state, the fields and the votes — never who the deciders
  are. `ApprovalExecutionService` answers with `voters[].auth_subject`, `voters[].email`,
  `requested_by_email` and `vetoed_by` empty; a person who sees a proposal only as its
  `requested_by` reads no voter's email.
- **Bounds**: a namespace holds at most 200 live proposals in one scope
  (`RESOURCE_EXHAUSTED` past that); an amount has at most 30 whole digits.

### 5.5 Mail

On open, every roster member with an ACTIVE account at a VERIFIED address gets the
request (`approval_request`), queued in the opening transaction and keyed
`approval_request:<id>:<user>`, so a retried `Propose` queues nothing new. The person named
in `requested_by` (same rule) gets the outcome (`approval_outcome`) when the proposal is
approved (`passed`) and again when it ends — executed, failed, rejected, vetoed, expired,
withdrawn or void — keyed `approval_outcome:<id>:<state>`. ⚠️ Narrower than first
written here (the roster was to get the outcome too): the deciders see it on the approvals
page, and one mail per decider per outcome is noise that teaches people to skip the
request. The outcome is queued by a sweep in the executor loop (`mail_outcomes`, every
pass), not by the act that ends a proposal: an expiry and a lapse are lazy and a void on a
change of the owners is written by a trigger, so no single path sees every ending;
`approvals.mailed_state` records the last state told.

Both are rendered here, by one template per purpose, from a TYPED row: the kind's label
and field labels from the catalog in force, the typed values (an `AMOUNT` grouped by
thousands and never rounded, `BPS` as a percentage, a `USER` as the account's address),
the scope, the level, the requester, the threshold and the deadline. The values sit under
"Submitted by <proposer>", the reason, a veto reason and a proposer's report under labels
saying whose words they are; every value is folded to one line and escaped. They bypass
notification preferences (an approval nobody can switch off, like the governance mails),
carry no code — voting happens over a session, not from a mailbox — and link only to
`<APPROVALS_URL>/<id>` (default `https://evinvest.ltd/admin/approvals`), built at send
time: no row stores a link.

### 5.6 Scope admins (decided)

`UserDirectory.GrantPermission` refuses a `<scope>:admin` target to every caller — an
`admin` seat, an owner, emergency access — and names `ApprovalService.ProposeScopeAdminGrant`,
the behaviour `SetRole` has for `admin`; the alias is granted only by an executed
`concierge:scope_admin_grant`. No catalog may delegate `<namespace>:admin`
(`Catalog::check`): a seat able to hand out the alias could fill a scope's roster with
accounts it controls and pass its quorum with no owner asked. The account must have a
VERIFIED address, checked at open and again at execution: the seat is reached by the
approvals' mail, and an unproven address hands it to whoever holds the mailbox.
Removing an admin takes back their votes on OPEN proposals at once (§5.2); a proposal they
already carried to PASSED is stopped only by a veto inside its delay — any owner may cast
it. **Removing a scope admin is immediate, with no
approval** (`RevokePermission` by a seat holding `iam:tenants:grant`): containing a
rogue admin must never be the slower path, the rule this plane already keeps for
`Role::Admin`.

### 5.7 As implemented

`runner/src/approvals.rs` (both services and the executor loop), `infrastructure::approvals`
(migration 0036: `approvals`, the frozen roster `approval_voters`, the history
`approval_events`; migration 0037: `approvals.action`, `scope_approval_policies`), the rules
in `domain::approvals`.

- **Opening** resolves everything inside one transaction: the kind is the one in the
  proposer's catalog in force; the scope must be registered and `ACTIVE` (`main` always
  is); `requested_by` and every `USER` field must name an account; the escalation tests,
  `sole_admin` and the roster are decided and frozen there. Opens are serialised per
  proposer namespace by a transaction-scoped advisory lock, which is what makes the rolling
  window and the live cap hold for a batch opened at once — without it eight simultaneous
  1 000 USDT proposals each see an empty window. The owner roster is read before `tenants`,
  without a row lock: a seat that moves afterwards is caught at the vote, and holding every
  owner row for each open would queue every role change behind it. `dedupe_key` is
  **required** (1-128 bytes): an executor that cannot repeat a `Propose` safely cannot be
  idempotent either.
- **Time** is the database's — `clock_timestamp()`, read once the locks an act needs are
  held — never a replica's clock: a delay, an expiry and a lapse are compared on one clock
  however many replicas write, at the instant the act takes effect.
- **The executor** (`approvals::run_executor`, every 30 s) is the second loop in this plane
  that acts on its own, beside the hold sweep: it pulls the passed `concierge:*` decisions
  as a service would and carries each out with its outcome in ONE transaction, so a grant
  or an installed policy never exists without the executed decision behind it. If it stops,
  passed decisions lapse to `VOID` unexecuted after 72 hours — nothing is done that was not
  decided. A decision whose execution fails waits out its own backoff — doubled per
  failure, up to 15 minutes — while every other due decision is executed every 30 s: one
  poisoned decision does not hold the healthy ones back (review of #142).
- **The scope roster** is the ACTIVE accounts holding an unrevoked grant of exactly
  `<namespace>:admin`. A seat that holds every permission of a namespace without a row
  (`granting_seats_hold_all`) is not on it: what it may do on the scope's surface is not a
  say in the scope's decisions. **The platform roster** is every persisted `owner`, as the
  consilia count it.
- **A frozen roster keeps its size, not its votes.** A member who lost the seat it was
  drawn from after open (an `owner` seat, the `<namespace>:admin` grant) is refused
  `PERMISSION_DENIED` on a vote and a veto, and a FOR they cast before is not counted,
  while the threshold stays what it was: removing an admin is the containment step and
  must bite at once (§5.6), and shrinking the roster would let a removal lower the bar.
- **A scope may only tighten** (decided, until this plane keeps its own floor on the known
  money kinds, D24): a policy's threshold is never above the kind's own
  `default_threshold`.
- **Policy**: a scope with no installed policy is on the default (`version` 1, 5001 bps,
  3600 s, 72 h, no overrides); an executed `concierge:scope_policy_change` installs the next
  version (`scope_approval_policies`, every version kept). A scope's delay is never under
  an hour, in the domain and in a CHECK on both tables. `GetScopeApprovalPolicy` answers
  the scope's admins and the owners, and `INVALID_ARGUMENT` for `main`.
- **Visibility** of one proposal to a person: a persisted owner, an admin of its scope,
  the account it names as `requested_by`, or a member of its roster. Anything else, and
  an unknown id, is one `NOT_FOUND` — on the execution side too, for a proposal of another
  namespace.
- **History**: one `approval_events` row per transition in the transaction that made it —
  the actor is the person, else the client id or `bridge`; a lazy expiry or lapse
  (`lapsed`) names nobody and is dated at its deadline. A write that finds a proposal past
  its deadline commits the expiry or lapse even when the act is then refused.
- **`awaiting_my_vote`** asks only for votes the vote RPC would accept: a member who lost
  the seat is not listed as awaited.
- **An escalation that cannot be measured fires**: an absent AMOUNT or BPS field, or an
  amount in another currency, sends the proposal to the owners; only an unset FLAG stays
  down.
- **The roster change is a trigger** on `users` (migration 0038,
  `platform_roster_changed`, on `role` and `suspended_by`): the seat moves on many paths —
  admission, removal, resignation, genesis, a suspension verdict, a reinstatement from one
  — and from the previous binary during a rollout; the row is the one place all of them
  pass. A hold only moves `status` and `suspended_by = admin_hold`, which the trigger
  ignores. It
  stamps `platform_roster` first, which `propose` holds `FOR SHARE` while it opens a
  platform decision, so an open and a change never miss each other.
- **The pause is the store's too**: a `BEFORE INSERT` trigger on `approvals`
  (`approvals_platform_pause`, migration 0038) refuses a `PLATFORM` row created inside the
  pause, with the same lock and arithmetic as the code — a binary that predates the rule,
  or a check that raced a change, cannot open one. `platform_roster` is seeded from the
  last executed owner admission, removal, or suspension / reinstatement of a current owner
  in `governance_event`; a resignation and the genesis seed leave no event and are not
  dated.
- **The executor locks accounts before the proposal**: a grant takes the two `users` rows
  it names first, then the proposal row — the order a change of the owners takes them
  (its `users` row, then the trigger's `approvals` rows) — so the two cannot deadlock.
- **One daily budget per scope** (D24(4)) is the money plane's to count: everything that
  leaves a scope without the owners — its automatic payouts and its scope-level decisions
  — draws on it, and when a request would exceed it banking sets a FLAG field
  (`over_scope_budget`) with a `FLAG_SET` escalation, which sends that proposal to the
  owners. A kind's own thresholds here are the backstop behind that budget, not the
  budget.
- **A catalog already stored that delegates `<namespace>:admin`** (published before
  `Catalog::check` refused it) hands nobody the alias: `domain::iam::delegable` drops it
  whatever the catalog says, so a holder of the delegating alias can neither grant nor
  revoke it. The rest of that catalog's delegations still hold.

---

## 6. Notification topics

Topics a direction emits on are published with its scope catalog
(`NotificationTopicSpec`): `<namespace>:<segment>…`, a label and a description in plain
text, and whether an account that never touched the topic receives it (default no). A
service may emit only its own namespace's topics (`ScopeInboxService.EmitScopeNotification`). Topics a user cannot be without (the
payment-consent trace, security notices) stay this plane's own. Today's
`fund:quy-nhon` and `account:money-movement` move to `invest:` and `bank:`; carrying the
existing subscriptions across is the implementation's migration.

**Each direction has its own inbox (D21).** Which one a request reads is decided by the
server from where the request came from, never by a request field
(`notification::InboxView`):

| Asked through | Inbox | Topics offered, inbox rows shown |
| ------------- | ----- | -------------------------------- |
| web, `Origin` = `PUBLIC_ORIGIN` or absent (a same-origin GET sends none) | platform | this plane's built-in topics and `bank:*`, for everyone |
| web, `Origin` = an origin of a scope that still signs in (§3.1) | that scope's | its catalog's topics only, and only for a MEMBER of the scope (`scope_members`, §4.1); anyone else gets an empty list, not a refusal |
| web, any other `Origin` | — | `403 {"error":"origin_not_allowed"}` |
| gRPC `NotificationService` with a user's access token | platform | as above |
| gRPC `ScopeInboxService` with a client credential, `user_id` in the request | the client's own scope's | as for the scope's host above, for an ACTIVE member; anyone else reads empty and writes `FAILED_PRECONDITION` |
| web `?all=1` on `PUBLIC_ORIGIN` / gRPC metadata `x-ev-inbox-view: all` | summary | every namespace; needs `concierge:notifications:read_all` (seats `admin` and `owner`), else `403 {"error":"forbidden"}` / `PERMISSION_DENIED`; on a scope's host always `403` |

The rule covers the settings read, following a topic (a topic outside the inbox is
`unknown_topic` / `INVALID_ARGUMENT`, exactly like one that does not exist), the inbox
list, its topic filter, the unread count and mark-read (`all` marks only that inbox). The
two master channel switches are the account's across every inbox, so they are set only
where the platform inbox is in view: from a scope's host `403 {"error":"platform_only"}`.
On the web the summary is decided from the PERSISTED seat; break-glass elevation opens the
console, not everyone's notifications. The summary is metadata on gRPC and not a request
field because banking builds these request messages with struct literals (§1).

**How a direction reaches its own inbox (decided 2026-10-14).** Its frontend talks to its
own backend, and the backend calls `ScopeInboxService` with the client credential. A READ
names the user by the concierge id it knows from its own session (its access token's
`sub`, `ScopeEvent.user_id`): the inbox holds only what the scope's own services emitted.
A WRITE — mark-read, following a topic — also carries the user's access token issued to
THIS client (metadata `x-ev-user-token`), checked as `GetMe` checks it plus `aud` = the
calling client's audience, and the user is taken from its `sub`: following a topic turns
on mail to the user's address, and a client secret alone (or a leaked one) must not be
able to do that to anyone. No or a bad token is `UNAUTHENTICATED`; another client's token,
or a `user_id` that is not the token's user, `PERMISSION_DENIED`. Neither credentialed
CORS on the account routes nor the client's user token on `NotificationService`: the
account routes stay off the scope hosts' CORS list (§3.1), and a client's user token is
admitted by the auth layer on `GetMe` alone — here it is a second proof beside the
client's secret, never a credential on its own.

- The namespace is the calling client's scope's, never a request field. An observer of a
  scope (§3) gets its stream, never its inbox.
- The user must be an ACTIVE member (`scope_members`, §4.1). An unknown id, a non-member
  and a disabled account are one case: the list, the count and the settings answer empty
  (the settings carry no address either), mark-read and following a topic answer
  `FAILED_PRECONDITION`. The client learns nothing its stream did not tell it.
- A topic outside the namespace's catalog in force is `INVALID_ARGUMENT`, as an unknown one;
  mark-read of another inbox's id marks nothing (`marked` counts what flipped).
- A disabled or unknown client and a wrong secret are `UNAUTHENTICATED`, a closed scope
  `FAILED_PRECONDITION`, the bridge token `PERMISSION_DENIED` (`bank:` topics are the
  platform inbox's).
- The master channel switches are not offered: they act on every inbox, so they stay on
  `PUBLIC_ORIGIN` (`NotificationService.SetChannelEnabled`, the account MFE).
- Pages are explicit: `limit` 0 means 20, at most 100, `next_cursor` empty on the last. A
  mark-read names at most 500 ids, here and on `NotificationService.MarkRead`.
- The gRPC summary (`x-ev-inbox-view: all`) reads the PERSISTED seat, as the web does:
  break-glass elevation (`OWNER_SUBJECTS`) does not open it.

As implemented: a scope catalog's topics are offered in the inbox of their scope (gRPC and
`/auth/notifications/settings`), may be followed and filtered on there, and disappear from
the offer when a later catalog withdraws them.

- **Emit is bound to the caller's namespace.** A service emits on a scope topic through
  `ScopeInboxService.EmitScopeNotification` with the credential of §2: a relying party for
  its scope's namespace, the bridge token for `bank` (the one RPC of that service the bridge
  opens). The topic must be the caller's namespace's and published in its catalog in force:
  another namespace's or this plane's own is `PERMISSION_DENIED`, an unpublished one
  `INVALID_ARGUMENT`. A scope's topic reaches only an ACTIVE member of the scope — for anyone
  else nothing is written and `delivered` is false — while a `bank:` topic reaches any
  account, as the platform inbox shows it to everyone. `NotificationService.Emit` with a
  `typ=service` token keeps this plane's own topics and refuses a scope's
  (`PERMISSION_DENIED`): that token names no namespace.
- **A notice links into the cabinet of the scope it names** (banking#580). `link` is empty or a
  cabinet path: one leading `/` (not `//` or `/\`), printable ASCII without spaces, else
  `INVALID_ARGUMENT` — the rule the money plane's fee notice link already had
  (`notice_link::cabinet_path`), so an emitter never names a host. `link_scope` names the
  cabinet (`[a-z][a-z0-9_]{0,31}`, else `INVALID_ARGUMENT`). A relying party may name only
  its own scope, else `PERMISSION_DENIED`; the bridge token names any, because a `bank`
  notice is about money held for a scope and is read in that scope's cabinet. When `NOTICE_LINK_BASES` has a
  base for it, the emit stores the absolute link `base + link`; otherwise the link stays
  relative and the mail joins it onto `CABINET_URL`. A stored link is checked again
  whenever it leaves this plane (`notice_link::NoticeLinkBases`), because rows outlive both
  the emit rule and the configuration: it passes only as a cabinet path or as an absolute
  link under `CABINET_URL` or a base configured NOW. Anything else — a row from before the
  rule, a base removed since — makes the mail link to `CABINET_URL` itself, and an inbox
  read (`ListNotifications`, `ListScopeNotifications`) return the notice with an empty
  link. The emit path is
  the same on both RPCs (`EmitScopeNotification`, `NotificationService.Emit`).
- **`default_subscribed` applies.** Switching a topic off writes a row to
  `notification_topic_optouts` (migration 0041) beside deleting the subscription, so "never
  touched" and "switched off" read differently. A default topic is followed — with its mail
  copy on — by every account in its inbox that never touched it, in the settings snapshot
  and on emit, which creates the subscriber row as a trace does. Following again clears the
  opt-out. The subscription row is still deleted on unsubscribe, so the previous binary,
  which ignores the new table, keeps reading "not following".
- **The account-less subscribe takes a scope's topic** that a catalog in force publishes,
  under the same double opt-in; `default_subscribed` has no say there, the address asks by
  name. Its working door is this plane's web surface, not the RPC: `SubscribeAnonymous`,
  `ConfirmSubscription` and `Unsubscribe` want a `typ=service` token nothing mints yet.
  `POST https://evinvest.ltd/api/auth/notifications/subscribe` (JSON `{email, topic,
  turnstileToken}`) accepts `PUBLIC_ORIGIN` and a signing-in scope's origin (§3.1) — it acts
  for no account, it names an address that only the confirmation mail can bind — checks
  Turnstile, the per-IP budget the RPC spends and the per-address mail throttle, and answers
  `{accepted: true}` whether a mail was queued or not (`400 invalid_email | unknown_topic`,
  `429 throttled`, `403 origin | captcha`). The mail's links are
  `/api/auth/notifications/confirm?token=` and `/api/auth/notifications/unsubscribe?token=`
  on `PUBLIC_ORIGIN`: a page with one button on GET (mail scanners fetch links), the change
  on POST; the unsubscribe URL is also the RFC 8058 one-click target (`POST` with
  `List-Unsubscribe=One-Click`, 200, no redirect), and a token nobody holds answers as one
  that worked.
- **Account-less subscribers get no broadcast (decided, #152).** A confirmed address with no
  account is not mailed topic updates on its own: nothing fans a topic out to bare addresses.
  Whoever later registers with that address picks up the subscription and receives topic mail
  from then on. Do not add a bulk send for account-less rows.
- **The move has happened.** `fund:quy-nhon` is `invest:fund:quy-nhon` (invest's members
  only) and `account:money-movement` is `bank:money-movement`; migration 0042 carried the
  subscriptions, account-less ones included, and the fund's inbox history. Until banking and
  invest publish those topics and emit on them, the old keys are aliases wherever a topic is
  named — `Emit` (by `typ=service` token), following, the account-less subscribe and unsubscribe —
  and stand for the new ones (`notification::MOVED_TOPICS`); the aliases go at the contract
  step. `account:money-movement` itself stays this plane's TRACE topic: the in-app trace of a
  payment consent, a fee notice, a payment outcome or a decision opened in someone's name is
  filed there whatever they follow, so it is shown and filterable in the platform inbox but
  neither offered to follow nor emitted on.

---

## 7. Decisions and open questions

**Decided (review of 2026-10-14):** proposer = executor per kind (§5.1); quorum over the
whole roster, `requested_by` informational (§5.2); the `bank:*` kinds of §5.3, with no
`invest:dividend_distribution`; compartment limits in `bank:compartment_policy`, not in
`scope_policy_change`; removing a scope admin is immediate (§5.6); the daily window
counts live and executed proposals (§5.2); banking halts on an unknown kind on both
streams (§4.3); `observers` grant nothing on the money plane (§3); the closed CORS route
list and the `origins` rules (§3.1); `auth_subject` as the user key everywhere;
`subject_ref` as `<type>:<uuid>` of at most 128 bytes; `next_position` as the maximum
position scanned (§4.2); `Scope.state` (§3).

**Open**

1. Is the bridge token acceptable as banking's approvals credential (§2) until service
   tokens exist, or does banking want a separate secret?
2. A direction receives `kyc_level` on the lifecycle stream and in `ScopeMember` (D5),
   although `GetMe` withholds it from relying parties today.
3. Topic labels are one language; the frontends carry five locales.
4. ~~How a scope's host reaches its own inbox~~ — decided 2026-10-14: through its own
   backend and `ScopeInboxService` with the client credential (§6).

**Known limitation until `typ=service` tokens:** a namespace is the unit of
`ApprovalExecutionService`, so several clients of one namespace are indistinguishable
there — any of them may withdraw, pull or report on a proposal another opened.
`requested_by_client` records which one opened it, for the audit trail, and authorises
nothing.

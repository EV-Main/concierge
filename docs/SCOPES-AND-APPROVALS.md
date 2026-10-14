# Scopes, approvals and the relying-party event streams — contract

Status: **partly implemented.** The wire is in `contracts/proto/concierge/v1/scopes.proto`,
`approvals.proto` and the comments on `events.proto`. Implemented in `runner/`: the
registry (§3: `tenants` columns from migration 0031, `ScopeRegistry` mounted inside the
user auth layer) and sign-in from a scope's hosts (§3.1: CORS and the `Origin` check on
the closed route list, the passkey verifier's origins, OAuth `returnTo`). Every other
service below is not mounted yet and answers `UNIMPLEMENTED`. Banking, the `lib`
projections, invest and admin build against this document.

Source decisions: the owner's D1–D20 and the approval levels and thresholds of the
organisation plan (2026-10-14). Where this document departs from the plan's wording it
says so and why.

---

## 1. Surface

| Service | File | Caller | Where it is mounted |
| ------- | ---- | ------ | ------------------- |
| `ScopeRegistry` | scopes.proto | first-party session, `typ=service` token | inside the user auth layer |
| `ScopeCatalogService` | scopes.proto | service credential (§2) | outside the layer, like `UserEvents` |
| `ScopeEvents` | scopes.proto | service credential (§2) | outside the layer, `BIND` and the TLS listener |
| `ApprovalService` | approvals.proto | first-party session | inside the user auth layer |
| `ApprovalExecutionService` | approvals.proto | service credential (§2) | outside the layer, `BIND` and the TLS listener |
| `UserEvents.PullUserLifecycle` | events.proto (unchanged wire) | bridge token, **and now** a relying party's client credential | as today |

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
- **`clients`**: a scope may have several relying-party clients (today one, `sa`).
- **`observers`**: client ids that may also READ this scope's events and its users'
  lifecycle. invest runs allocations of other scopes (the `service_arb` allocation lives
  in `sa`) and checks `sa:admin` to authorise `sa`'s admins there, so `sa` names
  `invest` as an observer. **An observer holds no right on the money plane**: which
  accounts a service may open, debit or read there is banking's own configuration of
  service grants, and nothing on this plane widens it.
- **Registry writes** are migrations and configuration, as `rp_clients` is today; there
  is no write RPC. Every change bumps `version` and emits `SCOPE_CHANGED`.

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
| `/auth/code/request`, `/auth/code/verify`, `/auth/password/signin`, `/auth/password/signup`, `/auth/passkey/signin/*`, `GET /auth/session` (answers `{authenticated, user}`, never a token) | everything acting on an open session: `/auth/email/verify/*`, `/auth/password/set`, `/auth/passkey/register`, `/auth/passkey/remove`, sessions, username, logout, `/kyc/*` |

A route on the left accepts an `Origin` that is `PUBLIC_ORIGIN` or an origin of a scope
that is `ACTIVE` or `FROZEN` — a frozen scope's clients still sign people in — and never
one of a `CLOSED` scope. The right column carries the CSRF double-submit, whose cookie a
scope host cannot read, so email verification is not offered there: a scope host proves
a mailbox by signing in with a code. The allowlist is re-read from the registry at most
30 s apart (`web::allowlist`), so closing a scope or removing an origin takes effect
without a restart. An absolute OAuth `returnTo` must be one of these origins plus a path
from the scope's `return_paths`, matched exactly, or `/auth/login` answers 400; a
relative or empty one lands on `/` as it always did.

---

## 4. Event streams for relying parties

### 4.1 Visibility

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
one event returned, `next_position` is that event's position. `lib`'s
`concierge_projection` relies on this to replay a parked event (§4.3) and confirm it got
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

### 4.3 A kind the consumer cannot name

Concierge ships ahead of its consumers, so an unknown kind is the ordinary shape of a
mid-rollout event; prost decodes it as `KIND_UNSPECIFIED`. The rule depends on what a
swallowed event would cost (decided):

- **Money (banking): Halt, on both streams.** The cursor stops on the event and the
  consumer alerts; upgrading the binary is the only thing that unblocks it. Marking it
  applied is how a freeze or a scope closure gets swallowed while money keeps moving
  under rules this plane already revoked.
- **Directions (invest, sa, admin, via `lib`'s `concierge_projection`): Park.** Record
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
contract step of the reorganisation; the new kinds below replace banking's consilium
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
proposer may open proposals of its kinds in any registered `ACTIVE` scope — invest
proposes `invest:valuation_override` in `sa` because the allocation is there.

`Approval.proposer` is the kind's namespace; `Approval.requested_by_client` is the
client whose credential opened it, for the audit trail only.

A kind declares (`ApprovalKindSpec`): a label and description in plain text; its
**level** before escalation; its **fields**, each with a type from a closed set
(`TEXT`, `AMOUNT`, `BPS`, `FLAG`, `USER`, `TIMESTAMP`, `COUNT`) that this plane knows
how to render; and its **escalations**, each naming a field, a test and a default
threshold. A `USER` field carries an `auth_subject`.

### 5.2 Who decides

| Level | Roster | Threshold | Delay (veto window) | Lifetime |
| ----- | ------ | --------- | ------------------- | -------- |
| `PLATFORM` | persisted `owner` seats (break-glass seats nobody) | more than half of the roster | 24 h, veto by any roster member | 72 h |
| `SCOPE` | active holders of `<scope>:admin` | the scope policy's `quorum_bps`, default more than half of the roster | the policy's `delay_secs`, default 1 h, veto by any roster member | the policy's `ttl_secs`, default and ceiling 72 h |

- **Quorum is over the whole roster frozen at open:**
  `threshold = max(1, ceil(roster × quorum_bps / 10000))`, platform at 5001 bps. Nobody
  is excluded. A service cannot prove which person asked it, so the person it names
  (`requested_by`, an `auth_subject`) is information shown to voters — it moves no
  quorum and keeps nobody off the roster. A `PLATFORM` proposal with fewer than two
  owners on the roster is refused at open (`FAILED_PRECONDITION`).
- **Escalation to `PLATFORM`** happens at open and is frozen with the roster
  (`Approval.escalated_by` says why):
  - any declared escalation test fires against the scope's threshold (or the kind's
    default when the policy names none);
  - **`sole_admin`**: the scope has fewer than two admins, so one person would decide;
  - a proposal in scope `main` is always `PLATFORM`.
- **Tests:** `AMOUNT_ABOVE` (an amount in another currency than the parameter's escalates
  — fail safe); `ROLLING_24H_AMOUNT_ABOVE` — the amount plus every **live or executed**
  scope-level proposal of the same kind and scope opened in the trailing 24 h (decided:
  counting only executed ones would let proposals opened together each pass under the
  window and then execute together above it; a proposal that ends rejected, vetoed,
  expired, cancelled or void stops counting); `ABS_BPS_ABOVE`; `FLAG_SET`.
- **The scope policy** (`ScopeApprovalPolicy`: quorum, delay, lifetime, threshold
  overrides) is changed only by `concierge:scope_policy_change`, which is always
  `PLATFORM`: a scope able to lower its own thresholds would decide for itself what
  needs the owners. It does not carry compartment limits — those are the money plane's
  `bank:compartment_policy`. The new policy is validated at open and again at execution
  against the catalogs then in force.

### 5.3 Kinds

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
| `invest:fee_policy` | SCOPE | `ceiling` FLAG_SET on raises_ceiling | allocation, basis, crystallization (TEXT); current and proposed management/performance/hurdle (BPS); raises_ceiling (FLAG) |
| `invest:holder_grant` | PLATFORM | — | allocation (TEXT), holder (USER), units (AMOUNT, unit code) |

`concierge:*` — this plane's own, opened over `ApprovalService` and executed by this
plane's own puller.

| Kind | Level | Opened by |
| ---- | ----- | --------- |
| `concierge:scope_admin_grant` | PLATFORM | a seat holding `iam:tenants:grant` |
| `concierge:scope_policy_change` | PLATFORM | such a seat, or an admin of the scope |

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
- **Veto** by any roster member, and **withdrawal** by the proposer
  (`WithdrawProposal`) — or, for a `concierge:*` proposal, by the person who opened it
  over a session (`CancelApproval`) — are possible while `OPEN` and while `PASSED`
  before `executable_at`. After that the proposer owns the proposal and only
  `ReportOutcome` moves it.
- **Pull** (`PullApproved`) serves `PASSED` proposals of the caller's namespace whose
  `executable_at` is behind the clock and that have no outcome, oldest first. A pull
  claims nothing: the same proposal is served on every pull until its outcome is
  reported, so the proposer is idempotent per proposal id. Executable is a time
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

### 5.5 Mail

On open, every roster member at a VERIFIED address gets the approval mail; on the
terminal state, the roster and the person named in `requested_by` get the outcome. Both
are rendered here by one template per purpose from the kind's spec, bypass notification
preferences (an approval nobody can switch off, like the governance mails), and link
only to this plane's own approvals page on `PUBLIC_ORIGIN`. They carry no code: voting
happens over a session, not from a mailbox.

### 5.6 Scope admins (decided)

While `concierge:scope_admin_grant` exists, `UserDirectory.GrantPermission` refuses a
`<scope>:admin` target and names `ApprovalService.ProposeScopeAdminGrant` — the
behaviour `SetRole` has for `admin`. **Removing a scope admin is immediate, with no
approval** (`RevokePermission` by a seat holding `iam:tenants:grant`): containing a
rogue admin must never be the slower path, the rule this plane already keeps for
`Role::Admin`.

---

## 6. Notification topics

Topics a direction emits on are published with its scope catalog
(`NotificationTopicSpec`): `<namespace>:<segment>…`, a label and a description in plain
text, and whether an account that never touched the topic receives it (default no). A
service may `Emit` only its own namespace's topics. Topics a user cannot be without (the
payment-consent trace, security notices) stay this plane's own. Today's
`fund:quy-nhon` and `account:money-movement` move to `invest:` and `bank:`; carrying the
existing subscriptions across is the implementation's migration.

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

**Known limitation until `typ=service` tokens:** a namespace is the unit of
`ApprovalExecutionService`, so several clients of one namespace are indistinguishable
there — any of them may withdraw, pull or report on a proposal another opened.
`requested_by_client` records which one opened it, for the audit trail, and authorises
nothing.

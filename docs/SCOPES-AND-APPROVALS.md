# Scopes, approvals and the relying-party event streams — contract

Status: **contract only.** The wire is in `contracts/proto/concierge/v1/scopes.proto`,
`approvals.proto` and the comments on `events.proto`; nothing here is implemented in
`runner/` yet, no service below is mounted, and calling one answers `UNIMPLEMENTED`.
Banking, the `lib` projections, invest and admin build against this document.

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
  the platform owners. Every other scope has `parent = "main"`.
- **`origins`** are the scope's hosts as a browser sends `Origin`. The sign-in surface
  answers CORS for them and accepts a credential POST whose `Origin` is one of them or
  `PUBLIC_ORIGIN`. Nothing else widens: OAuth `returnTo` must be on one of these origins.
- **`clients`**: a scope may have several relying-party clients (today one, `sa`).
- **`observers`**: client ids that may also read this scope's events and its users'
  lifecycle. invest runs allocations of other scopes (the `service_arb` allocation lives
  in `sa`) and checks `sa:admin` to authorise `sa`'s admins there, so `sa` names
  `invest` as an observer. Without this invest could not see the grants it authorises on.
- **Registry writes** are migrations and configuration, as `rp_clients` is today; there
  is no write RPC. Every change bumps `version` and emits `SCOPE_CHANGED`.

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

**`UserEvents.PullUserLifecycle`**, read by a client credential: same request, same
cursor semantics, filtered inside the query by visibility (so invisible rows never hold
the cursor back), and each row redacted — `seat_permissions` absent and `permissions`
empty. `kyc_level` is carried: directions layer their own policy on the KYC level and
may not manage it (D5).

**`ScopeEvents.PullScopeEvents`** is a separate stream because `UserLifecycleEvent.Kind`
is the money plane's vocabulary: banking stops its single cursor on a kind it cannot
name (`piggybank/core/src/infrastructure/bridge.rs`), so `SCOPE_CHANGED` or
`GRANTS_CHANGED` there would freeze the mirror of every suspension and KYC change behind
it until banking redeployed. Kinds:

| Kind | Carries | Ordered by |
| ---- | ------- | ---------- |
| `SCOPE_CHANGED` | the whole `Scope` after the change | the scope's `version` |
| `GRANTS_CHANGED` | the user's whole concrete permission set in that scope (present-and-empty = holds nothing, apply it) | per (scope, user) `sequence` |
| `MEMBER_JOINED` | the identity snapshot a projection seeds from (`ScopeMember`) and the lifecycle `sequence` it is as of | per (scope, user) `sequence` |

A direction seeds a user's row from `MEMBER_JOINED` and applies lifecycle events whose
`sequence` exceeds `lifecycle_sequence`. A lifecycle event for a user whose
`MEMBER_JOINED` has not arrived yet is parked by subject, as banking parks a subject it
has not provisioned. Snapshots, not deltas, so a redelivery is harmless and two events
can never disagree about the current set.

Banking reads `ScopeEvents` with the bridge token, learns scopes from `SCOPE_CHANGED`
and opens compartments only for known scopes.

### 4.3 A kind the consumer cannot name

Concierge ships ahead of its consumers, so an unknown kind is the ordinary shape of a
mid-rollout event; prost decodes it as `KIND_UNSPECIFIED`. The rule depends on what a
swallowed event would cost:

- **Money (banking): Halt.** The cursor stops on the event and the consumer alerts;
  upgrading the binary is the only thing that unblocks it. Marking it applied is how a
  freeze or a scope closure gets swallowed while money keeps moving under rules this
  plane already revoked. This is banking's behaviour today and applies to both streams.
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

### 5.1 Kinds and catalogs

A kind is declared by the service that executes it, in its namespace:
`bank:payment`, `invest:valuation_override`, `concierge:scope_admin_grant`. It is
published whole with `ScopeCatalogService.PublishScopeCatalog` (versioned like
`PublishCatalog`); `concierge:*` kinds are this plane's own, built in at version 0. A
service may open proposals only for kinds of its own namespace, in any registered scope
— invest proposes `invest:valuation_override` in `sa` because the allocation is there.

A kind declares (`ApprovalKindSpec`): a label and description in plain text; its
**level** before escalation; its **fields**, each with a type from a closed set
(`TEXT`, `AMOUNT`, `BPS`, `FLAG`, `USER`, `TIMESTAMP`, `COUNT`) that this plane knows
how to render; and its **escalations**, each naming a field, a test and a default
threshold.

### 5.2 Who decides

| Level | Roster | Threshold | Delay (veto window) | Lifetime |
| ----- | ------ | --------- | ------------------- | -------- |
| `PLATFORM` | persisted `owner` seats (break-glass seats nobody) | more than half of the voters | 24 h, veto by any voter | 72 h |
| `SCOPE` | active holders of `<scope>:admin` | the scope policy's `quorum_bps`, default more than half of the voters | the policy's `delay_secs`, default 1 h, veto by any voter | the policy's `ttl_secs`, default and ceiling 72 h |

- **Voters** are the roster frozen at open minus the initiator; the initiator never
  votes. `threshold = max(1, ceil(voters × quorum_bps / 10000))`, platform at 5001 bps.
  A proposal whose voters would be nobody is refused at open (`FAILED_PRECONDITION`).
- **Escalation to `PLATFORM`** happens at open and is frozen with the roster
  (`Approval.escalated_by` says why):
  - any declared escalation test fires against the scope's threshold (or the kind's
    default when the policy names none);
  - **`sole_admin`**: the scope has fewer than two admins, so one person would decide;
  - a proposal in scope `main` is always `PLATFORM`.
- **Tests:** `AMOUNT_ABOVE` (an amount in another currency than the parameter's escalates
  — fail safe); `ROLLING_24H_AMOUNT_ABOVE` — the amount plus every **live or executed**
  scope-level proposal of the same kind and scope opened in the trailing 24 h;
  `ABS_BPS_ABOVE`; `FLAG_SET`.

  *Departure from the plan:* the plan counts the daily window over executed decisions.
  Counting only executed ones lets several proposals opened together each pass under the
  window and then execute together above it, so open and passed ones count too. A
  proposal that ends rejected, vetoed, expired, cancelled or void stops counting.

- **The scope policy** (`ScopeApprovalPolicy`: quorum, delay, lifetime, threshold
  overrides) is changed only by `concierge:scope_policy_change`, which is always
  `PLATFORM`: a scope able to lower its own thresholds would decide for itself what
  needs the owners. The new policy is validated at open and again at execution against
  the catalogs then in force.

### 5.3 Defaults (the plan's table, as kinds)

Suggested specs; names and fields of `bank:*` and `invest:*` are their owners' to
confirm (§7).

| Kind | Level | Escalations (default) | Fields |
| ---- | ----- | --------------------- | ------ |
| `bank:payment` — from a scope account off the platform (L1) or into another scope | PLATFORM | — | tier, source, destination (TEXT), amount |
| `bank:seed_capital` | PLATFORM | — | allocation (TEXT), amount |
| `bank:treasury_surplus` | PLATFORM | — | amount, destination (TEXT) |
| `bank:scope_transfer` — between accounts of one scope | SCOPE | `per_operation` AMOUNT_ABOVE 1000 USDT; `daily` ROLLING_24H_AMOUNT_ABOVE 5000 USDT | from_account, to_account (TEXT), amount |
| `bank:scope_payout` — from a scope account to one user | SCOPE | `per_operation` AMOUNT_ABOVE 1000 USDT | from_account (TEXT), recipient (USER), amount |
| `invest:valuation_override` | SCOPE | `max_deviation` ABS_BPS_ABOVE 1000 (10 %) | allocation (TEXT), mark (AMOUNT), deviation (BPS) — invest still refuses beyond the 50 % cap before proposing |
| `invest:fee_policy` | SCOPE | `ceiling` FLAG_SET on raises_ceiling | allocation, basis, crystallization (TEXT); current and proposed management/performance/hurdle (BPS); raises_ceiling (FLAG) |
| `invest:holder_grant` | PLATFORM | — | allocation (TEXT), holder (USER), units (AMOUNT, unit code) |
| `invest:dividend_distribution` — to every holder | PLATFORM | — | allocation (TEXT), amount, holders (COUNT) |
| `concierge:scope_admin_grant` | PLATFORM | — | scope, grantee |
| `concierge:scope_policy_change` | PLATFORM | — | scope, the policy |

Assigning an operator in a scope is still a delegated `GrantPermission` by a
`<scope>:admin`, with no approval. This plane's own two kinds are opened over
`ApprovalService`: `scope_admin_grant` by a seat holding `iam:tenants:grant`,
`scope_policy_change` by such a seat or by an admin of the scope.

### 5.4 Life of a proposal

```
OPEN ──(threshold met)──▶ PASSED ──(executable_at passes; executor pulls)──▶ EXECUTED
  │                         │                                               EXECUTION_FAILED
  │                         ├─ veto ─▶ VETOED                                VOID
  ├─ votes against ─▶ REJECTED
  ├─ expires_at ─▶ EXPIRED   (lazy, like the governance consilia)
  └─ initiator / proposing service ─▶ CANCELLED   (also from PASSED inside the delay)
```

- **Propose** (`ApprovalExecutionService.Propose`): the proposing service has already
  decided the initiator may ask (it owns that surface); this plane checks the
  initiator is an active account and keeps them off the roster. `subject_ref` is the
  service's own reference, opaque here (≤ 256 bytes printable ASCII, never shown to
  voters); at most one live (`OPEN`/`PASSED`) proposal per kind, scope and
  `subject_ref`. Idempotent by `dedupe_key` per namespace.
- **Text** — `TEXT` fields, `reason`, a veto reason, an outcome detail — is one line,
  bounded, refused if it carries a control character or a link (`://`, `www.`), and
  rendered attributed to whoever wrote it, never as this plane's own words. There is no
  free-form markup anywhere: the mail is rendered here from the kind's labels and the
  typed values (`USER` resolved to the account's email here, `BPS` to a percentage here).
- **Veto and cancel** are possible while `OPEN` and while `PASSED` before
  `executable_at`. After that the executor owns the proposal and only `ReportOutcome`
  moves it.
- **Pull** (`PullApproved`) serves `PASSED` proposals of the caller's namespace whose
  `executable_at` is behind the clock and that have no outcome, oldest first. A pull
  claims nothing: the same proposal is served on every pull until its outcome is
  reported, so the executor is idempotent per proposal id. Executable is a time
  predicate over `PASSED`, not a state, so nothing has to sweep for a proposal to become
  pullable. Concierge's own kinds are executed by this plane's own puller.
- **`payload_hash`** binds what was approved to what is executed. The executor
  recomputes it from its own record of the subject and refuses to act on a mismatch:
  SHA-256, lowercase hex, over the UTF-8 bytes of

  ```
  ev-approval-v1\n<kind>\n<scope>\n<subject_ref>\n
  ```
  followed by one line per field, sorted by key: `<key>\t<type>\t<value>\n`, where
  `<type>` is the enum suffix (`AMOUNT`, `BPS`, …) and `<value>` is the text verbatim,
  `<value> <currency>` for an amount (the canonical decimal is enforced at Propose for
  exactly this reason), the decimal integer for `BPS`/`TIMESTAMP`/`COUNT`,
  `true`/`false` for a flag, and the lowercase UUID for a user. No field may contain a
  tab or a newline, so the encoding is unambiguous.
- **ReportOutcome**: `EXECUTED`, `FAILED` (terminal; a retry is a new proposal) or
  `VOID` (no longer applies; nothing attempted). Repeating the same outcome is a no-op.

### 5.5 Mail

On open, every voter at a VERIFIED address gets the approval mail; on the terminal
state, the voters and the initiator get the outcome. Both are rendered here by one
template per purpose from the kind's spec, bypass notification preferences (an approval
nobody can switch off, like the governance mails), and link only to this plane's own
approvals page on `PUBLIC_ORIGIN`. They carry no code: voting happens over a session,
not from a mailbox.

### 5.6 Granting a scope admin

While `concierge:scope_admin_grant` exists, `UserDirectory.GrantPermission` refuses a
`<scope>:admin` target and names `ApprovalService.ProposeScopeAdminGrant` — the
behaviour `SetRole` has for `admin`. **Taking the grant away stays one act**
(`RevokePermission` by a seat holding `iam:tenants:grant`): the plan's table puts
removal at the platform level too, but containing a rogue admin must never be the
slower path, which is the rule this plane already keeps for `Role::Admin`. Open question
for the owner (§7).

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

## 7. Open questions

**To banking**

1. Kind names and fields in §5.3: is `bank:payment` the right home for both L1 and
   cross-scope transfers, or two kinds? Are on-chain revenue payouts (today's
   `PAYOUT_APPROVAL`) `bank:payment` with tier `external`?
2. `subject_ref` format. Suggested `<type>:<uuid>` (`payment:4f…`, `transfer:…`) so a
   proposal list reads without a lookup; this plane never parses it.
3. Compartment limits (`scope_policies`, §3.2 of the plan) are platform-level changes:
   a `bank:compartment_policy` kind of banking's own, or should
   `concierge:scope_policy_change` carry them?
4. Is the bridge token acceptable as the approvals credential (§2), or does banking want
   a separate secret before service tokens exist?
5. Halt on an unknown `ScopeEvent` kind as on lifecycle kinds — confirm, since banking
   will see every scope's events.

**To the owner**

6. Scope-admin removal: one act (as proposed here) or a platform approval (as the plan's
   table says).
7. The daily window counts live as well as executed proposals (§5.2).
8. A direction receives `kyc_level` on the lifecycle stream and in `ScopeMember` (D5),
   although `GetMe` withholds it from relying parties today.
9. A service may propose its kinds in any scope (§5.1); the alternative is an explicit
   per-scope list, at the cost of one more thing to configure per allocation move.
10. Topic labels are one language; the frontends carry five locales.

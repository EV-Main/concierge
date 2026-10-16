# evconcierge_projection — keeping a direction's users

A direction (invest, admin, the Service-Arb panel) needs to know its users: who they
are, whether they are suspended, what they may do inside its scope. concierge owns all
of that and never calls a direction; the direction **pulls** two streams and keeps a
projection. This crate is the pull engine; the projection — your tables — is yours.

The contract this follows is concierge's `docs/SCOPES-AND-APPROVALS.md` §4 and the
comments on `events.proto` / `scopes.proto`. Both live in the same repository as this
crate, and the wire types come from `evconcierge_contracts` of the same release, so a
version of `evconcierge_projection` always speaks the contract it was built against.

## Wiring

```rust
use evconcierge_projection::{pg, GrpcSource, PgProjectionStore, Projection, ProjectionConfig};

pg::migrate(&pool).await?; // before serving, every boot; idempotent
let projection = Projection::new(
    PgProjectionStore::new(pool.clone()),
    MyUsers { pool },                                   // impl Handler
    GrpcSource::connect_lazy(&concierge_grpc, CLIENT_ID, &client_secret, Duration::from_secs(10))?,
    ProjectionConfig::default(),                        // UnknownKind::Park
);
tokio::select! { () = projection.run() => {}, () = shutdown => {} }
```

`Cargo.toml`: `evconcierge_projection = { version = "…", features = ["pg"] }` (or
`["sqlite"]`). Building needs no `protoc` on `PATH`: `evconcierge_contracts` falls back
to a vendored one when `PROTOC` is unset.

`GrpcSource` reads both streams with the relying party's **client credential** — its
`rp_clients` id and secret, sent as `x-ev-client-id` + `authorization: Bearer <secret>`.
concierge filters each stream to what that client may see. Every pull names its
`limit` (the configured `batch`, at most `MAX_BATCH` = concierge's own ceiling; a
pull without one is served a single row), and the cursor stored after a page is the
page's `next_position`, never the last event's position.

`migrate` creates `concierge_projection_{schema,cursor,applied,sequence,parked}` with
its own version table, apart from your `sqlx::migrate!` history. It runs at boot, so
**a release that bumps `evconcierge_projection` past a new schema step is a schema rollout**: read the
step in the diff, and do not roll back below it (the old build refuses a newer schema
version).

## What to keep — and what never

Keep only what the events give you, keyed by **`auth_subject`** (never parse it, never
key on concierge's `user_id`):

| From | Keep |
| ---- | ---- |
| `MemberJoined` | email, email_verified, username, preferred_name, status, kyc_level, token_version — seeds the row |
| `UserEvent` (every kind) | the snapshot fields: status (from the kind), kyc_level, role, token_version, email |
| `GrantsChanged` | the user's whole permission set in your scope — replace, never merge; empty = holds nothing |
| `ScopeChanged` | the scope, `state` included; anything but `Active` (and `Unrecognized`) is not active |

Never copy into a direction:

- **identity-document / KYC data** — legal name, date of birth, address, nationality,
  tax residence, phone, documents. The streams do not carry them; do not fetch them
  elsewhere to fill the gap. `kyc_level` is the most a direction holds, to layer its
  own policy on — it does not manage KYC.
- **money** — balances, holdings, payouts, accounts. That is banking's plane; read it
  there, never mirror it here.
- tokens and secrets of any kind.

The projection is a cache of concierge, not a source of truth: authorisation of a
request still comes from the caller's token / `GetMe`, not from a row you copied.

## The handler

- **Snapshots, not deltas.** Every event says the whole current value; upsert it. The
  engine calls you at least once per event — a crash between your write and its
  bookkeeping repeats the call.
- The engine drops duplicates (`event_id`) and anything at or below the key's stored
  `sequence`, so a stale `Reinstated` can never undo a later `Suspended`.
- Return `Err` only for what a retry fixes (your database is down). The cycle stops
  there and retries from the same cursor with backoff.

## Ordering, parking, replay

- Keys: lifecycle `user:<auth_subject>`; grants and members `scope:<scope>:user:<subject>`;
  scope changes `scope:<scope>`.
- **Lifecycle before MEMBER_JOINED.** A lifecycle event for a subject the projection has
  not seeded yet is parked by `auth_subject` and replayed when MEMBER_JOINED lands;
  lifecycle events at or below its `lifecycle_sequence` are skipped as already
  reflected. The scope stream is pulled before the lifecycle stream each cycle, so this
  is rare.
- **Unknown kind** (concierge ships ahead of you): `UnknownKind::Park` records the
  *position* and moves on; the next start re-pulls it with `after = position - 1,
  limit = 1` and applies it if the new build can read it. `UnknownKind::Halt` stops the
  stream instead — for a consumer where a swallowed event costs money (banking does its
  own).
- Anything parked holds its key: later events of the same key queue behind it, so the
  sequence guard never runs past an event still to apply. Other keys keep flowing.
- Log lines `needs intervention` (target `evconcierge_projection`) mean a parked
  position no longer resolves, or a halted stream: a human looks.

## Lag

Each cycle logs `cursor`, `applied`, `parked`, `parked_total` and `lag_secs` (now minus
the last applied event's `occurred_at`) at `info` when it did something, `debug` when
idle. Alert on `lag_secs` and on `parked_total` growing.

## Rebuilding (and surviving a rewind)

concierge never deletes stream rows, so the projection can always be rebuilt:

1. Stop the projection.
2. Truncate your projection tables **and** `concierge_projection_{cursor,applied,sequence,parked}`
   together — never one side alone: a cursor with no `applied`/`sequence` re-applies
   history over newer rows' guards; guards with an empty projection skip every event.
3. Start: both cursors begin at 0 and replay everything visible to your client.

Restoring your database from a backup is a rewind of both sides at once, which is safe:
the cursor goes back with the data, and re-pulled events re-apply as snapshots. What
is not safe is restoring one side without the other.

If concierge's visibility for your client grows (a new observer grant), old rows become
visible but the cursor is past them: the MEMBER_JOINED that the grant emits seeds the
user; a full history needs a rebuild.

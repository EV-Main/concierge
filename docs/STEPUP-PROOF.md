# Step-up proof: an operation-bound confirmation by a second factor

A page of a trusted host (the SA panel, the invest cabinet, the platform's own wallet) asks
the signed-in account to confirm ONE operation of the money plane. The flow:

1. Concierge keeps the ceremony and offers the account's second factors (`second_factor`,
   enrolled at `/auth/second-factor/*`).
2. It checks the answer.
3. It answers a short **proof**.

The bank's BFF accepts the proof only for an `intent_hash` it stored itself.

The proof says how much assurance the answer gave (`aal`). It never says which factor gave
it, so a factor kind added here changes nothing the bank does. Re-authentication
(`/auth/reauth/*`, which moves `auth_time`) is a different thing and is not touched.

The page should not speak these routes itself. It mounts `mfe-concierge-stepup`
(`@evinvest/concierge`'s `StepupDialog` / `useStepup`) with the hash and the level, and
receives the proof in an event. Factor pickers and per-kind forms live in that element.

## Routes

Both are `POST`, JSON only, publicly under `/api/auth/stepup/*`. They are **not mounted**
(404) unless `STEPUP_PROOF_ORIGINS` names an origin. With no `SECOND_FACTOR_SEAL_KEY_FILE`,
the factor ceremony answers 404.

| Check | Rule |
| --- | --- |
| `Origin` | exactly one of `STEPUP_PROOF_ORIGINS` (no pattern, no port or path variants, `null` and empty refused) → else `403 origin` |
| `Sec-Fetch-Site` | `same-origin` or `same-site`; missing or anything else → `403 fetch_site` |
| `Content-Type` | `application/json` → else `415 content_type` |
| CORS | preflight approved only for the listed origins: `POST`, `content-type`, credentials, `Max-Age: 60`, `Vary: Origin` |
| Session | `__Host-ev_session` / `__Host-ev_access` cookies (same-site `fetch` with `credentials: "include"`); the refresh family is checked first-hand |
| CSRF | no double-submit token (a script on another host cannot read the `__Host-` cookie); the three rows above stand in for it |

Responses carry `Cache-Control: no-store`. The session's `auth_time` and cookies are not
moved; the only `Set-Cookie` is the rotation any session read owes the browser. A proof
does not make the session "factor-fresh" for changing the account's factors, and a
factor-fresh session mints no proof.

### `POST /auth/stepup/options`

```json
{ "intent_hash": "<64 lowercase hex>", "min_aal": 2 }
```

→ `{ "ceremony_id", "factors": [{ "id", "kind", "label", "challenge" }], "expires_at" }`:
every factor of the account that gives at least `min_aal`, each with its kind's challenge.
`kind`, `label` and `challenge` are for the element's own forms.

Refusals:
- `409 no_second_factor`: the account holds no factor that gives that much. The page
  sends the person to enrol at the platform's account page.
- `400 invalid_aal`: a level below 2.
- `400 invalid_intent`.
- `429 throttled`: 10 asks per account per 5 min. A factor's answer is not counted here: each
  ceremony takes one, and the account's guard counts the wrong ones.

Unknown fields are refused.

### `POST /auth/stepup/verify`

```json
{ "ceremony_id": "...", "factor": "<factor id>", "response": <the kind's answer> }
```

→ `{ "proof": "<JWT>", "aal": 2, "expires_at": <unix s> }`.

The ceremony is held as follows:
- It remembers the account, the `intent_hash` (the client cannot change it here), the
  asking origin and the factors it offered.
- It lives ≤ 120 s and is spent by its first answer, right or wrong.
- The answer must come from the same account and the same origin.

Wrong answers are counted per account across every factor and recovery code, in Postgres
(five in 15 min lock every answer for 15 min, twenty a day until the day's window ends;
`429 factor_locked`). A TOTP code is accepted once.

Refusals: `400 invalid_answer`, `400 ceremony_expired`, `400 unknown_factor`, `429 factor_locked`.

## The proof

EdDSA (Ed25519) JWT signed with the key of the access tokens; `kid` selects the key in the
same JWKS (`AuthService.Jwks`).

```json
{ "iss": "<concierge issuer>", "aud": "banking-bff", "typ": "stepup",
  "sub": "<account id, = the access token's sub>",
  "intent_hash": "<64 lowercase hex>", "aal": 2,
  "origin": "https://invest.evinvest.ltd",
  "jti": "<uuid v4>", "iat": 1790000000, "exp": 1790000120 }
```

* `aal` is the level the answered factor gives, never the `min_aal` the page asked for.
  The levels follow NIST SP 800-63B's authenticator assurance numbering:
  * 2 is the sign-in plus an enrolled second factor (every kind today: TOTP).
  * A device-bound, phishing-resistant kind may give 3.
  * The claim is a number, so a higher level passes every verifier that asks for less.
* `exp - iat ≤ 120`. Verifiers allow 5 s of skew.
* `typ: "stepup"` is not an access/service `TokenType`, so every existing verifier refuses it
  at parse; `aud: "banking-bff"` is on no access policy; an access token has neither `typ` nor
  `intent_hash`, so it cannot pass as a proof. Pinned by tests on both sides.
* The claim set is pinned to exactly these ten keys: no factor kind or id reaches the bank.

## What the bank MUST do

1. Verify with `evconcierge_auth::stepup::verify_stepup_proof` (0.3) against the cached JWKS. It:
   - pins EdDSA and checks `iss`, `aud`, `exp`, `typ` and the lifetime cap;
   - checks the proof is not dated ahead of the verifier's clock (`iat <= now + 5 s`,
     `exp <= now + 120 s + 5 s`);
   - checks `sub`, `intent_hash` and `origin` are exactly the expected ones and
     `aal >= min_aal`.

   On `StepupError::UnknownKid`, refresh the JWKS and retry — **at most once per 30 s**
   per process, or a flood of forged `kid`s becomes a flood of `Jwks` calls (the `Verifier`
   here does the same).
2. Pass the values **the bank stored**: the intent's own hash, the intent's owner and the
   origin the intent was created from. Never a value read from the request or the proof.
   `sub` is the **user id of the access token** the confirm request carries (the same value
   as the access token's `sub`), compared with the proof's.
3. **Choose the level per operation**: `Aal::SECOND_FACTOR` for every withdrawal and every
   other money-out act. A higher level, once a kind gives one, is how the bank asks for more
   on a large amount, without naming a kind.
4. **Spend the `jti` once.** Concierge cannot know whether a proof was used: it never calls
   the bank. The bank must remember each accepted `jti` until its `exp` in a store shared by
   all BFF replicas (Redis `SET stepup:jti:<jti> 1 NX EX <exp - now + 5>`) and refuse a proof
   whose `SET NX` fails. An in-process set is not enough with more than one replica.
5. **Order of the confirm:** verify the proof → compare-and-set the intent
   (`created → authorized`, one winner) → `SET NX` the `jti` → execute. A lost CAS or a lost
   `SET NX` is a refusal; a proof is never spent for an intent that did not move.
6. **Make the hash unique to the intent.** `intent_hash` is computed by the bank over a
   random `intent_id` plus everything the person is to confirm (amount, fee, recipient,
   network, scope, host origin, `expires_at`); two intents never share one. A proof whose
   `iat` is earlier than the intent's `created_at` is refused: it cannot be for this intent.
7. **Re-check at confirm, not only at create:** the account is not frozen, its
   `token_version` is current and its session is the one that created the intent. A proof
   authorises the stored intent only, so a second confirm of an executed intent is refused
   regardless of the `jti`.

```rust
use evconcierge_auth::{JwksCache, stepup::{Aal, Expected, StepupError, verify_stepup_proof}};

// `cache` is built from the Jwks RPC: JwksCache::from_wire(&response.keys)?
let intent_hash: [u8; 32] = stored_intent.hash;
let expected = Expected {
    intent_hash: &intent_hash,
    sub: &access_token_user_id,          // from the verified access token, not the body
    origin: &stored_intent.origin,
    min_aal: Aal::SECOND_FACTOR,         // per operation
};
let claims = match verify_stepup_proof(&proof, &cache, &issuer, &expected) {
    Ok(claims) => claims,
    Err(StepupError::UnknownKid(_)) => { /* refresh the JWKS (<= once / 30 s), retry */ return retry() }
    Err(_) => return Err(Refused),
};
if !intent_cas_authorized(&stored_intent).await? { return Err(Refused) }
if !redis_set_nx(format!("stepup:jti:{}", claims.jti), claims.exp).await? { return Err(Replayed) }
```

## Limits worth knowing

* A ceremony is held **in process**, like every ceremony in this plane. With several
  replicas the verify must reach the replica that answered `options`: run one replica, or
  make the route sticky. A verify that lands elsewhere fails (`ceremony_expired`) and the
  page begins again; it never yields a wrong proof. The wrong-answer count is in Postgres
  and holds across replicas.
* Request fields are snake_case (`intent_hash`, `ceremony_id`, `min_aal`), unlike the
  camelCase of the older routes; a body that does not parse, or names an unknown field,
  answers `400 {"error":"invalid_request"}`.
* An account holds at most 3 open ceremonies; a fourth evicts its oldest.

# Step-up proof — an operation-bound confirmation

A page of a trusted host (the SA panel, the invest cabinet) asks the signed-in account to
confirm ONE operation of the money plane. Concierge keeps the ceremony, checks a passkey
assertion or a mailed code, and answers a short **proof**. The bank's BFF accepts the proof
only for an `intent_hash` it stored itself. Re-authentication (`/auth/reauth/*`, which moves
`auth_time`) is a different thing and is not touched.

## Routes

Both are `POST`, JSON only, publicly under `/api/auth/stepup/*`. They are **not mounted**
(404) unless `STEPUP_PROOF_ORIGINS` names an origin.

| Check | Rule |
| --- | --- |
| `Origin` | exactly one of `STEPUP_PROOF_ORIGINS` (no pattern, no port or path variants, `null` and empty refused) → else `403 origin` |
| `Sec-Fetch-Site` | `same-origin` or `same-site`; missing or anything else → `403 fetch_site` |
| `Content-Type` | `application/json` → else `415 content_type` |
| CORS | preflight approved only for the listed origins: `POST`, `content-type`, credentials, `Max-Age: 60`, `Vary: Origin` |
| Session | `__Host-ev_session` / `__Host-ev_access` cookies (same-site `fetch` with `credentials: "include"`); the refresh family is checked first-hand |
| CSRF | no double-submit token (a script on another host cannot read the `__Host-` cookie); the three rows above stand in for it |

Responses carry `Cache-Control: no-store`. The session's `auth_time` and cookies are not
moved; the only `Set-Cookie` is the rotation any session read owes the browser.

### `POST /auth/stepup/options`

```json
{ "intent_hash": "<64 lowercase hex>", "method": "passkey" | "email_code",
  "summary": "<email_code only, 1..240 printable chars, one line>",
  "turnstile_token": "<email_code only>" }
```

Unknown fields are refused, so a `password` is not silently ignored; **a password is never
accepted** (`method: "password"` → `400 invalid_method`).

* `passkey` → `{ "ceremony_id", "method", "options": <WebAuthn request options, rpId = the
  site's registrable domain>, "expires_at" }`. Only keys created **before the session began**
  are offered (`400 no_passkey` if none).
* `email_code` → mails a code and answers `{ "ceremony_id", "method", "expires_at" }`. The mail
  states what this plane saw — the asking origin, time, address and browser, and a reference
  (the first 8 hex of the hash) — and quotes `summary` under a label saying it is the **page's
  own words**, not checked by us. A Turnstile token is required, as for every mail this plane
  sends on request. The code lives as long as the ceremony; a newer ask supersedes the older
  code and ceremony. Limits: the code budgets of the `stepup` purpose (5 sends per address per
  15 min, 10 per account per day, 20 wrong guesses per day) and 10 asks per account per 5 min.

### `POST /auth/stepup/verify`

```json
{ "ceremony_id": "...", "response": <PublicKeyCredential> }   // passkey
{ "ceremony_id": "...", "code": "123456" }                    // email_code
```

→ `{ "proof": "<JWT>", "method": "passkey"|"email_code", "expires_at": <unix s> }`.

The ceremony remembers the account, the `intent_hash` (the client cannot change it here), the
asking origin and the method; it lives ≤ 120 s. A passkey ceremony is spent by its first
verify; an email ceremony survives a mistyped code (the code burns on its 5th wrong guess).
The finishing request must come from the same account and the same origin, and a passkey
assertion's own `clientDataJSON.origin` must be that origin and not cross-origin framed.

## The proof

EdDSA (Ed25519) JWT signed with the key of the access tokens; `kid` selects the key in the
same JWKS (`AuthService.Jwks`).

```json
{ "iss": "<concierge issuer>", "aud": "banking-bff", "typ": "stepup",
  "sub": "<account id, = the access token's sub>",
  "intent_hash": "<64 lowercase hex>", "method": "passkey" | "email_code",
  "origin": "https://invest.evinvest.ltd",
  "jti": "<uuid v4>", "iat": 1790000000, "exp": 1790000120 }
```

* `exp - iat ≤ 120`. Verifiers allow 5 s of skew.
* `typ: "stepup"` is not an access/service `TokenType`, so every existing verifier refuses it
  at parse; `aud: "banking-bff"` is on no access policy; an access token has neither `typ` nor
  `intent_hash`, so it cannot pass as a proof. Pinned by tests on both sides.
* The `Claims` struct (cross-plane parity with banking) is untouched.

## What the bank MUST do (PR2)

1. Verify with `evconcierge_auth::stepup::verify_stepup_proof` against the cached JWKS — it
   pins EdDSA, checks `iss`, `aud`, `exp`, `typ`, the lifetime cap, then that `sub`,
   `intent_hash` and `origin` are exactly the expected ones. On `StepupError::UnknownKid`,
   refresh the JWKS once and retry (as `Verifier` does).
2. Pass the values **the bank stored**: the intent's own hash, the intent's owner and the
   origin the intent was created from. Never a value read from the request or the proof.
3. **Spend the `jti` once.** Concierge cannot know whether a proof was used: it never calls
   the bank. The bank must remember each accepted `jti` until its `exp` in a store shared by
   all BFF replicas (Redis `SET stepup:jti:<jti> 1 NX EX <exp - now + 5>`) and refuse a proof
   whose `SET NX` fails. An in-process set is not enough with more than one replica.
4. Execute the operation once per intent (its own status CAS); a proof authorises the stored
   intent only, so a second confirm of an executed intent is refused regardless of the `jti`.

```rust
use evconcierge_auth::{JwksCache, stepup::{Expected, StepupError, verify_stepup_proof}};

// `cache` is built from the Jwks RPC: JwksCache::from_wire(&response.keys)?
let intent_hash: [u8; 32] = stored_intent.hash;
let expected = Expected { intent_hash: &intent_hash, sub: &stored_intent.owner, origin: &stored_intent.origin };
let claims = match verify_stepup_proof(&proof, &cache, &issuer, &expected) {
    Ok(claims) => claims,
    Err(StepupError::UnknownKid(_)) => { /* refresh the JWKS once, retry */ return retry() }
    Err(_) => return Err(Refused),
};
if !redis_set_nx(format!("stepup:jti:{}", claims.jti), claims.exp).await? { return Err(Replayed) }
```

## Limits worth knowing

* A ceremony is held **in process**, like every ceremony in this plane. With several
  replicas the verify must reach the replica that answered `options`: run one replica, or
  make the route sticky. A verify that lands elsewhere fails (`passkey_expired`) and the page
  begins again; it never yields a wrong proof.
* The summary of an email code is the page's claim, not ours. The trusted lines of the mail
  are the origin (from the browser's `Origin`), the time, the address and the browser.
* Mail is English only, as every mail of this plane.

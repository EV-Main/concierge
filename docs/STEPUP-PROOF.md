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
   pins EdDSA, checks `iss`, `aud`, `exp`, `typ`, the lifetime cap, that the proof is not dated
   ahead of the verifier's clock (`iat <= now + 5 s`, `exp <= now + 120 s + 5 s`), then that
   `sub`, `intent_hash` and `origin` are exactly the expected ones and `method` is one of the
   `methods` the bank lists for this operation. On `StepupError::UnknownKid`, refresh the JWKS
   and retry — **at most once per 30 s** per process, or a flood of forged `kid`s becomes a
   flood of `Jwks` calls (the `Verifier` here does the same).
2. Pass the values **the bank stored**: the intent's own hash, the intent's owner and the
   origin the intent was created from. Never a value read from the request or the proof.
   `sub` is the **user id of the access token** the confirm request carries (the same value
   as the access token's `sub`), compared with the proof's.
3. **Choose the methods per operation.** The email method rests on a mailbox and on the
   page's own summary; the bank must restrict it on hosts: cap the amount it can authorise
   and require `[Passkey]` for a withdrawal or a mandate when the account has a passkey
   (the proof's `method` is how the verifier tells).
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
use evconcierge_auth::{JwksCache, stepup::{Expected, StepupError, StepupMethod, verify_stepup_proof}};

// `cache` is built from the Jwks RPC: JwksCache::from_wire(&response.keys)?
let intent_hash: [u8; 32] = stored_intent.hash;
let expected = Expected {
    intent_hash: &intent_hash,
    sub: &access_token_user_id,          // from the verified access token, not the body
    origin: &stored_intent.origin,
    methods: &[StepupMethod::Passkey],   // per operation; add EmailCode only below the cap
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
  make the route sticky. A verify that lands elsewhere fails (`passkey_expired`) and the page
  begins again; it never yields a wrong proof.
* The `summary` of an email code is **written by the page**, not by us, and the mail says so.
  The origin and `User-Agent` in the mail are trustworthy only when a browser makes the call
  (a browser fixes `Origin`; a script outside one can write both); the time and the address
  are what this plane saw. A hijacked page can therefore phrase a harmless summary over a
  harmful operation: that is why the email method must be restricted on hosts (bank rule 3).
  Follow-up recorded, not built: the bank signs the operation's summary (`summary_mac`) and
  concierge quotes it only when the MAC verifies, so the mail would state the bank's words.
* Request fields are snake_case (`intent_hash`, `ceremony_id`, `turnstile_token`), unlike the
  camelCase of the older routes; a body that does not parse, or names an unknown field,
  answers `400 {"error":"invalid_request"}`.
* An account holds at most 3 open ceremonies; a fourth evicts its oldest. A step-up code is
  bound to the `intent_hash` it was mailed for and redeems only for it.
* Mail is English only, as every mail of this plane.

# @evinvest/concierge

Host wrappers for the **concierge microfrontends** — the sign-in dialog, the
account page, the account chip, the re-authentication dialog and the step-up
dialog — over
[`@evinvest/mfe`](https://www.npmjs.com/package/@evinvest/mfe). A host
(invest cabinet, the SA panel, admin) mounts them; the elements themselves are
built in this repo's `web/` and served from `https://evinvest.ltd/api/auth/mfe/`
(the site's `/api/auth/*` rewrite to concierge). The package lives next to the
service so a change to the elements' contract and to their host wrappers lands
in one PR.

```sh
npm install @evinvest/concierge @evinvest/mfe
```

- `.` — server-safe core: registry constants, tags, the session shape, the
  RP-login and platform sign-out hrefs.
- `./react` — `SignInDialog`, `AccountPage`, `AccountChip`, `ReauthDialog`,
  `StepupDialog`, `useSignInRequired`, `useReauthRequired`, `useStepup` (a
  `"use client"` bundle; `react` is an optional peer).

`@evinvest/mfe` is a **peer**: its loader caches loads per tag, so the host and
this package must share one copy.

No network calls beyond the registry and the session; the elements do the rest.

## Elements

| Element | Tag | Registry name |
| --- | --- | --- |
| Sign-in dialog | `mfe-concierge-sign-in` | `concierge.sign-in` |
| Account page | `mfe-concierge-account` | `concierge.account` |
| Account chip | `mfe-concierge-account-chip` | `concierge.account-chip` |
| Re-authentication dialog | `mfe-concierge-reauth` | `concierge.reauth` |
| Step-up dialog | `mfe-concierge-stepup` | `concierge.stepup` |

```ts
import { conciergeEntry, fetchConciergeRegistry } from '@evinvest/concierge';

// CONCIERGE_REGISTRY_URL by default; every bundle must sit under CONCIERGE_MFE_PREFIX.
const registry = await fetchConciergeRegistry();
if (!registry.ok) return fallback;
const entry = conciergeEntry(registry.value, 'signIn'); // refused if missing or another tag
if (!entry.ok) return fallback;
const signIn = entry.value;
```

The host's CSP allows the bundle directory, not the whole origin (no hash pins,
D20): `script-src https://evinvest.ltd/api/auth/mfe/` (plus
`https://evinvest.ltd/wallet/mfe/` for the wallet). `fetchConciergeRegistry`
refuses redirects and any `scriptUrl` outside `CONCIERGE_MFE_PREFIX`.

## Sign in when the host gets a 401

```tsx
'use client';
import { SignInDialog, useSignInRequired } from '@evinvest/concierge/react';

const { guardResponse, dialogProps } = useSignInRequired();
// …
const response = await fetch('/api/thing');
if (guardResponse(response)) return; // a 401 opened the dialog

<SignInDialog scriptUrl={signIn.scriptUrl} {...dialogProps} />; // returnTo: this page, no query or hash
```

The element draws its own backdrop and traps focus; the host only drives
`open`. The dialog is mounted on the first open and kept, so a signed-in visitor
never loads the bundle. When the element reports `ev:signed-in`, the dialog
closes and `onSignedIn` runs — by default a full navigation to the host's RP
login, `/auth/login?return_to=<this page>` (`rpLoginHref`), which completes
silently because the evinvest.ltd session now exists. Pass
`useSignInRequired({ onSignedIn })` for another login path.

Element contract, host side:

| | Name | Meaning |
| --- | --- | --- |
| attribute | `open` | present while the dialog is open |
| attribute | `data-intent` | `signin` or `signup`, the first screen |
| attribute | `data-return-to` | origin + path of an absolute https URL on the host an OAuth round trip lands on (http only to loopback); query and hash are always cut, since concierge answers a `returnTo` with `?` or `#` with 400. Concierge accepts it only for an origin in a scope's registry. Relative values are left out (`hostReturnTo`) |
| event | `ev:signed-in` | sign-in finished |
| event | `ev:close` | dismissed by the user (`CLOSE_EVENT`) |

## Confirm again when the host gets `reauth_required`

Some acts need a recent proof of the user, not just a session: concierge
accepts them only from an access token minted by a re-authentication, which
moves the session's `auth_time` to now. A host on **evinvest.ltd** (the admin
console) whose backend answers `403 reauth_required` asks the user to confirm,
then retries the act **once**:

```tsx
'use client';
import { ReauthDialog, useReauthRequired } from '@evinvest/concierge/react';

const { requireReauth, dialogProps } = useReauthRequired();

async function openPayment() {
  let response = await post('/api/payments', body);
  if (isReauthRequired(response)) {           // the host's own BFF vocabulary
    if (!(await requireReauth())) return;     // dismissed: leave the act undone
    response = await post('/api/payments', body); // once; a second refusal is an error
  }
  // …
}

<ReauthDialog scriptUrl={reauth.scriptUrl} {...dialogProps} />;
```

`requireReauth()` resolves `true` after the element reports
`ev:reauthenticated` — concierge has accepted the proof and re-set the
`ev_access` cookie by then — and `false` on `ev:close` or when the host
unmounts. Calls while the dialog is open share one answer. The element offers
an email code, the password or a passkey, whichever the account has.

Re-authentication works only on evinvest.ltd: concierge refuses the
`/api/auth/reauth/*` routes from any other `Origin`. Mounted elsewhere, the
dialog says to confirm on the platform and sends nothing.

Element contract, host side:

| | Name | Meaning |
| --- | --- | --- |
| attribute | `open` | present while the dialog is open; only the host sets or removes it |
| event | `ev:reauthenticated` | confirmed, the fresh `ev_access` is set (`REAUTHENTICATED_EVENT`) |
| event | `ev:close` | dismissed by the user (`CLOSE_EVENT`) |

Both events bubble, are `composed` and carry no detail (`ReauthEventMap`). At
most one of them fires per opening. `ReauthDialog` calls `onReauthenticated`
before `onOpenChange(false)`.

## Prove a second factor for one operation

A money-plane page (on evinvest.ltd or a scope host concierge lists in
`STEPUP_PROOF_ORIGINS`) that needs a second factor for ONE operation asks the
element for a proof and sends it with the operation. The host's backend stored
the operation's `intentHash` and names the least assurance it needs:

```tsx
'use client';
import { StepupDialog, useStepup } from '@evinvest/concierge/react';

const { requestProof, dialogProps } = useStepup();

async function withdraw() {
  const { intentHash, minAal } = await post('/api/withdrawals/intent', body); // the host's own BFF
  const proof = await requestProof(intentHash, minAal);
  if (proof === null) return;                               // dismissed: leave it undone
  await post('/api/withdrawals', { intentHash, proof });
}

<StepupDialog scriptUrl={stepup.scriptUrl} {...dialogProps} />;
```

`requestProof` resolves with the proof after the element reports
`ev:stepup-proof`, and `null` on `ev:close` or when the host unmounts. A call
for the same operation while the dialog is open shares its answer; a call for
another one rejects, because a proof is good for one `intentHash` only. The
host never learns which kinds of factor the account has: the picker and the
per-kind forms are the element's. With no factor that gives `minAal`, the
element enrols one in place on evinvest.ltd and, on a scope host, links to the
platform's account page and offers to ask again.

Element contract, host side:

| | Name | Meaning |
| --- | --- | --- |
| attribute | `open` | present while the dialog is open; only the host sets or removes it |
| attribute | `intent-hash` | the operation's hash, 64 lowercase hex; required |
| attribute | `min-aal` | the least assurance level, an integer; required, no default (missing or malformed, the dialog says so and asks nothing) |
| event | `ev:stepup-proof` | detail `{ proof, expiresAt }` (unix seconds) (`STEPUP_PROOF_EVENT`, `StepupProofDetail`) |
| event | `ev:close` | dismissed by the user (`CLOSE_EVENT`) |

Both events bubble and are `composed` (`StepupEventMap`). At most one of them
fires per opening. `StepupDialog` calls `onProof` before `onOpenChange(false)`.

## Account page and chip

`account` and `chip` are entries taken the same way (`'account'`, `'accountChip'`).

```tsx
<AccountPage
  scriptUrl={account.scriptUrl}
  section={sectionFromUrl} // `?section=` — concierge's own links to /account use it
  onSection={s => router.replace(`/account?section=${s}`)}
  onNavigate={href => (router.push(href), true)}
  onSignOut={signOut}
/>

<AccountChip
  scriptUrl={chip.scriptUrl}
  host={{ name, email, groups }} // host mode; omit for default mode
  onNavigate={href => isMyRoute(href) && (router.push(href), true)}
  onSignOut={signOut}
  fallback={<ChipPlaceholder />}
/>
```

### Sign-out ends both sessions

On `signout` both wrappers call the host's `onSignOut` (awaited when it returns
a promise), then navigate to concierge's confirm page,
`platformSignOutHref(origin + '/')` —
`https://evinvest.ltd/api/auth/logout/confirm?return_to=https%3A%2F%2F<host>%2F` —
which ends the evinvest.ltd session and sends the user to the host's root.
Without it the platform session outlives the host's and the silent RP login
signs the next person at that browser straight back in. The navigation runs
even if `onSignOut` rejects or throws. `platformSignOut={false}` turns it off;
use it only when the host ends the platform session another way, with a
comment saying so.

`onSignOut` ends the host's session with a `fetch` and returns the promise; it
does not navigate. The wrapper's navigation follows and cancels any the
handler started, and a handler that leaves the page first never reaches the
platform sign-out:

```tsx
<AccountChip scriptUrl={chip.scriptUrl} onSignOut={async () => { await fetch('/auth/logout', { method: 'POST' }) }} />
```

**Requirement on every scope that mounts the chip or the account page:** its
`return_paths` in concierge list `/`. Concierge takes `return_to` on
`/auth/logout/confirm` only when the path is byte for byte one of them, and
answers anything else — or no `return_to` — with 400, leaving the
evinvest.ltd session alive.

`onNavigate` (`NavigateHandler`, from `@evinvest/mfe/react`) gets an already
validated root-relative path and returns whether the host took it. In default
mode the chip takes the same `intent` (`signin` | `signup`) and an absolute
`returnTo` as the dialog, with the same default: this page's origin and path.
The chip keeps `apiVersion` 2, `ev:navigate` and `signout`;
host-mode attributes come from `hostAttributes` in `@evinvest/mfe`.

## Session

```ts
import { fetchSession } from '@evinvest/concierge';

const session = await fetchSession(); // GET https://evinvest.ltd/api/auth/session, credentials: include
if (session.ok && session.value.authenticated) session.value.user.email;
```

`{ authenticated, user }`, with `user` cut down to what the chip shows:
`{ userId, email, emailVerified, username, displayName }`. Concierge's
`SessionInfo` also carries the platform role, `isAdmin`, the break-glass flag
and platform `permissions`; the parser drops them, so a host cannot gate its
own UI on platform privileges. Browser only in practice: the session cookie is
first-party to evinvest.ltd and never reaches a host's server. It says who
holds the evinvest.ltd session, not what the host's backend lets them do — that
stays with the host's RP session.

## Develop

```sh
npm install   # @evinvest/mfe comes from npm as a dev dependency
npm run typecheck && npm test && npm run build
```

## Release

Published from this repo by `.github/workflows/npm-publish.yml` through npm
trusted publishing (OIDC, with provenance) on a tag `@evinvest/concierge-v<version>`.
The tag's version must equal `version` in `package.json`, or the job fails
before publishing:

```sh
# in a PR: bump the version
cd sdk && npm version patch --no-git-tag-version   # or minor / major
# after it is merged: tag the merge commit on main
git tag '@evinvest/concierge-v<version>' origin/main
git push origin '@evinvest/concierge-v<version>'
```

A failed run is retried from the Actions tab (`workflow_dispatch` with the same
tag). npm refuses a version it already has, so a published version is never
re-tagged: bump instead.

The tag does not match the container release's `v*` trigger, so it deploys
nothing.

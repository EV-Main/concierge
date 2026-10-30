# concierge web — the identity plane's microfrontends

Five self-registering custom elements, each a single ESM file with its own React,
rendered in the host's light DOM with the shared `@evinvest/uikit` tokens. Hosts mount
them through [`@evinvest/mfe`](https://github.com/EV-Main/lib/tree/main/ts/mfe) /
`@evinvest/concierge` ([`../sdk`](../sdk)) (registry, loader, events, `apiVersion` 2).

| Element | Registry name | Kind |
| --- | --- | --- |
| `mfe-concierge-sign-in` | `concierge.sign-in` | component |
| `mfe-concierge-account` | `concierge.account` | page |
| `mfe-concierge-account-chip` | `concierge.account-chip` | component |
| `mfe-concierge-reauth` | `concierge.reauth` | component |
| `mfe-concierge-stepup` | `concierge.stepup` | component |

The attributes and events of each element are documented at the top of its entry,
`src/entries/<name>.tsx`.

## Where actions run

The plane answers cross-origin only the sign-in steps and `GET /api/auth/session`, for
the registered scope origins (ORG-RESTRUCTURE-PLAN §3.9 F). So on a scope host
(`invest.evinvest.ltd`, `sa.evinvest.ltd`) the elements sign people in and show who is
signed in, and every action on an open session — password, passkeys, sessions,
username, notification settings, platform sign-out — is a link to
`https://evinvest.ltd/account`. On the platform origin they do it in place.
That page is concierge's own: `pages/account.html`, served at `/account` (the apex routes
the path here) with the account element and the chip, which is its sign-in when nobody is.
`src/shared/config/origin.ts` (`isPlatformPage`) is that switch.
A host that embeds the account element on its own route sets `data-profile-href` on the
chip (either mode) and the profile row goes there instead of leaving for that page.

Notification settings are per inbox: the plane picks it by the request's `Origin`. From
the platform the account page shows the platform's inbox (the two delivery channels, the
built-in and money-plane topics). A scope's own topics are not on that page and are not
reachable from a scope host's browser either; the scope's backend reads and writes them
through `ScopeInboxService`, and the host renders them itself.

Sign-out on a scope host (the account page's Security tab, the chip in host mode) first
fires `signout` for the host to end its own session, then navigates to
`<EV_PUBLIC_ORIGIN>/api/auth/logout/confirm?return_to=<this host's origin>/` so the
platform session ends too (`src/shared/element/host-sign-out.ts`). That page
(`runner/src/web/logout.rs`) asks for one click, ends the platform session and returns to
`return_to` once it passes the scope allowlist (so every scope host needs `/` among its
`return_paths`, or sign-out there stops at a 400); it does not sign out on the GET, so a
link elsewhere cannot sign a visitor out. Because the navigation follows
the event at once, a host must end its session with a request that survives unload
(`fetch(..., { keepalive: true })`, `sendBeacon`) or server-side.

Passkey add/remove on a session older than five minutes is answered `403 reauth_required`
(#168). The Security tab then opens a confirmation step in the same panel
(`features/sign-in-methods`: email code, password, passkey — `/auth/reauth/*`) and
retries the act once; a second `reauth_required` is shown as an error, not asked again.

The second-factor card (`features/second-factor`, `/auth/second-factor/*`) does the same
for its two guards: `reauth_required` opens the confirmation step above (composed in by
`views/account`, since one feature does not import another), `second_factor_required` its
own factor step, and the act is retried once after each. It renders nothing when
`/auth/methods` answers `secondFactor: null`. The QR of an enrolment is drawn by `uqr`.

`mfe-concierge-reauth` is the same confirmation as a dialog for a host on the platform
origin whose own backend answers `403 reauth_required` (the admin console before it opens
a payment, #171). The host sets `open`; the element fires `ev:reauthenticated` once the
plane has accepted the proof and re-set `ev_access`, or `ev:close` when dismissed — at most
one per opening. The host retries its act once and drops `open` either way. Off the
platform origin the dialog only says to confirm on the platform: the reauth routes refuse
every other `Origin`.

## Step-up: a second factor for one operation

`mfe-concierge-stepup` is a dialog for a money-plane page, on the platform origin or a
scope host listed in `STEPUP_PROOF_ORIGINS`, that needs the account to prove a second
factor for ONE operation (`docs/STEPUP-PROOF.md`). The page sets `intent-hash` and
`min-aal` (both required, no default) and `open`; the element runs
`/api/auth/stepup/{options,verify}` and fires `ev:stepup-proof` with `{ proof, expiresAt }`,
or `ev:close` — at most one per opening, as the reauth element. These two routes are the
only session acts answered cross-origin: CORS and `Sec-Fetch-Site` stand in for the CSRF
header, which a host could not read. A ceremony is spent by one answer, so every refusal
opens the next before the reader types again.

The factor picker and the per-kind forms are `features/second-factor`'s, so the page never
learns which kinds the account holds. With no factor that gives `min-aal`, the platform
origin enrols one in the dialog (the enrolment routes answer the platform only) and asks
again; a scope host links to the platform's Security page and offers to ask again.

## The platform pages

`dist/` holds two pages beside the bundles, `reauth.html` and `sign-in.html`. The
authorize route sends a browser to them, and concierge serves them at
`/api/auth/mfe/<page>.html` with `no-store`, `no-referrer` and a full CSP (no inline
script; `runner/src/web/mfe.rs`). Pages are not elements, so they are not in
`registry.json`.

Both pages share their first steps (`src/shared/lib/authorize-page.ts`).

The page accepts `return_to` only if it is a relative path that starts with
`/api/auth/authorize?` and contains no backslash, no fragment and no control character (so
no scheme, no `//` and no `/\` at the start; a fragment would ride authorize's 302 onto the
client's `redirect_uri`), if it still resolves to that path on this origin, and
if it names exactly one `client_id` (`src/shared/lib/authorize-return.ts`). Anything else
shows a short error and navigates nowhere: the page runs on the platform origin, and an
open redirect there would lend the platform's address bar to a phishing link.

The page names the app that asks. It takes the `client_id` from the checked `return_to`
only, never a name from the query, and asks `GET /api/auth/clients/{client_id}`
(same-origin, no credentials; `src/shared/api/client-name.ts`). The `display_name` is
written as text. An empty name, a 503, a failed request or a timeout keep the generic
line and open the dialog. A 404 means concierge would not serve the client at authorize,
so the page says the link is not valid and does not open the dialog.

The page leaves with `location.replace`, once: a second outcome from the element is
ignored.

Each page is built from `pages/<page>.html` (template), `src/entries/<page>-page.ts` (the
script, no React) and the shared `styles/platform-page.css` (kit tokens only);
`scripts/build.mjs` fills in the hashed names (`PAGES`). The page text is English only,
and the pages load no font: without a host, the kit's font chain falls back to the system
sans.

### The confirmation page, `reauth.html`

A relying party gets a fresh-sign-in proof by sending
its user to `/api/auth/authorize?…&max_age=N` (D24(1)). When the session is older than
`N`, the authorize route records a confirmation trip and answers 302 to this page with
`return_to` set to the same authorize request, rebuilt with its `max_age`
(`runner/src/web/authorize.rs`, `CONFIRM_PATH`, `confirm_url`). Only a trip that
concierge started yields a code with `auth_time`; nothing in `return_to` marks the way
back. The page mounts `<mfe-concierge-reauth open>` from the same build and, on
`ev:reauthenticated` or `ev:close`, calls `location.replace(return_to)`. It does not
judge the outcome: the authorize route answers with a code or with `access_denied`. A
`display_name` shows as "<name> asks you to confirm it's you".

**Deploy order.** The concierge image with this page and the `max_age` handling ships
first. Only then may invest send `max_age`: before it, a stale session lands on a 404.

### The sign-in page, `sign-in.html`

The authorize route sends a browser here when it has no session to authorize with: no
session at all, `prompt=select_account`, or a session minted before the account's
`token_version`. `return_to` is the authorize request (`runner/src/web/authorize.rs`). The
page mounts `<mfe-concierge-sign-in open data-return-to="<return_to>">`, so an OAuth
provider also lands back on authorize. A `display_name` shows as "Sign in to continue to
<name>". The page text is English, but the element gets `lang` from the browser's
languages (`negotiate` of `@evinvest/i18n`), so the dialog is localized.

- `ev:signed-in`: `location.replace(return_to)`; authorize now finds the session and
  answers with a code.
- `ev:close` (the person dismissed the dialog): `location.replace(return_to +
  "&auth_error=cancelled")`. authorize answers any `auth_error` with `access_denied` to
  the client, so the browser does not come back to this page in a loop.

A failed OAuth round trip also comes back to authorize with `auth_error`, so the client
gets `access_denied` and the dialog does not show the provider's error.

A new account confirms its address in the dialog through the ticket `password/signup`
hands back (`/password/signup/confirm`, `/resend`), which needs no CSRF cookie and so
works on every host; without a ticket the dialog sends the reader to the platform. An
existing account confirms it from Security on the platform (`/email/verify/*`). Never
through `/code/verify`: that opens a session for whoever holds the mailbox.

## Styles

Each bundle inlines its own stylesheet, inserted once as `<style data-mfe="<tag>">`
(hosts' CSP needs `style-src 'unsafe-inline'` or a hash, as for the old chip). Utilities
are compiled `!important` and scoped to the element inside the `reamfe` layer, so the
host's preflight cannot strip the forms and our utilities cannot reach the host's
elements — `scripts/scope-css.mjs` has the reasoning. The bundles ship no preflight; the host brings it,
and on the platform pages `styles/platform-page.css` does. Hosts declare
`@layer reamfe, …` first, as the `@evinvest/mfe` README asks. Overlays (the sign-in
dialog) portal into the element, so mount it outside any transformed ancestor.

## Build

`package-lock.json` is committed: the image's Nix build (`webMfe` in `flake.nix`) reads
it and refuses to build without it.

```sh
npm ci
npm run typecheck && npm run lint && npm run i18n:check
npm run build          # → dist/<name>-<hash>.js + dist/registry.json
                       #   + dist/{reauth,sign-in}.html, dist/<page>-page-<hash>.js
                       #   + dist/platform-page-<hash>.css
```

Build-time configuration (`scripts/config.mjs`, the only place it is read):

| Variable | Default | |
| --- | --- | --- |
| `EV_PUBLIC_ORIGIN` | `https://evinvest.ltd` | the plane's origin; must be `https:` unless `EV_ALLOW_ORIGIN_OVERRIDE` is set |
| `EV_ALLOW_ORIGIN_OVERRIDE` | unset (off) | `1` for dev and stand builds only: elements honour `data-origin`, `EV_PUBLIC_ORIGIN` may be `http:`, and the bare `ev_csrf` cookie is read. Never in production — `data-origin` would let any script on a host page aim the elements' credentialed calls elsewhere |
| `EV_TURNSTILE_SITEKEY` | unset | unset, the forms stay disabled with "Captcha failed to load" |
| `EV_SA_PANEL_URL` | unset | the chip's Services entry |
| `EV_MFE_BASE_PATH` | `/api/auth/mfe/` | where hosts load `dist/` from (concierge's `/auth/mfe/*` behind the conductor's `/api/auth` rewrite); registry `scriptUrl`s are root-relative under it |

## Copy

English is written at the call site (`t("key", "English")`); `npm run i18n:extract`
regenerates `messages/en/common.json` and prunes the translations. Each bundle ships only
the keys its own modules render, resolved by the `@evinvest/i18n` policy at build time.
The locale is the nearest `[lang]` of the element.

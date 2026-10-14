# concierge web — the identity plane's microfrontends

Three self-registering custom elements, each a single ESM file with its own React,
rendered in the host's light DOM with the shared `@evinvest/uikit` tokens. Hosts mount
them through [`@evinvest/mfe`](https://github.com/EV-Main/lib/tree/main/ts/mfe) /
`@evinvest/concierge` (registry, loader, events, `apiVersion` 2).

| Element | Registry name | Kind |
| --- | --- | --- |
| `mfe-concierge-sign-in` | `concierge.sign-in` | component |
| `mfe-concierge-account` | `concierge.account` | page |
| `mfe-concierge-account-chip` | `concierge.account-chip` | component |

The attributes and events of each element are documented at the top of its entry,
`src/entries/<name>.tsx`.

## Where actions run

The plane answers cross-origin only the sign-in steps and `GET /api/auth/session`, for
the registered scope origins (ORG-RESTRUCTURE-PLAN §3.9 F). So on a scope host
(`invest.evinvest.ltd`, `sa.evinvest.ltd`) the elements sign people in and show who is
signed in, and every action on an open session — password, passkeys, sessions,
username, notification settings, platform sign-out — is a link to
`https://evinvest.ltd/admin/account`. On the platform origin they do it in place.
`src/shared/config/origin.ts` (`isPlatformPage`) is that switch.

Proving an address goes through `/code/request` + `/code/verify` on every host: the
`/email/verify/*` routes need the CSRF cookie, which only the platform can read.

## Styles

Each bundle inlines its own stylesheet, inserted once as `<style data-mfe="<tag>">`
(hosts' CSP needs `style-src 'unsafe-inline'` or a hash, as for the old chip). Utilities
are compiled `!important` and scoped to the element inside the `reamfe` layer, so the
host's preflight cannot strip the forms and our utilities cannot reach the host's
elements — `scripts/scope-css.mjs` has the reasoning. Hosts declare
`@layer reamfe, …` first, as the `@evinvest/mfe` README asks. Overlays (the sign-in
dialog) portal into the element, so mount it outside any transformed ancestor.

## Build

```sh
npm install
npm run typecheck && npm run lint && npm run i18n:check
npm run build          # → dist/<name>-<hash>.js + dist/registry.json
```

Build-time configuration (`scripts/config.mjs`, the only place it is read):

| Variable | Default | |
| --- | --- | --- |
| `EV_PUBLIC_ORIGIN` | `https://evinvest.ltd` | the plane's origin; an element's `data-origin` overrides it |
| `EV_TURNSTILE_SITEKEY` | unset | unset, the forms stay disabled with "Captcha failed to load" |
| `EV_SA_PANEL_URL` | unset | the chip's Services entry |
| `EV_MFE_BASE_PATH` | `/api/auth/mfe/` | where hosts load `dist/` from (concierge's `/auth/mfe/*` behind the conductor's `/api/auth` rewrite); registry `scriptUrl`s are root-relative under it |

## Copy

English is written at the call site (`t("key", "English")`); `npm run i18n:extract`
regenerates `messages/en/common.json` and prunes the translations. Each bundle ships only
the keys its own modules render, resolved by the `@evinvest/i18n` policy at build time.
The locale is the nearest `[lang]` of the element.

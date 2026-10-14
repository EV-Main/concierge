// <mfe-concierge-sign-in> — the platform's sign-in dialog, over any host in a scope.
//
// The host owns `open` and only `open`: the element mounts once (on the first opening) and
// stays; it never removes the attribute itself. Attributes, all optional but `open`:
//   open                    present while the dialog shows
//   data-intent             `signup` opens on sign-up; `signin`/`login` (default) on the email code
//   data-return-to          where an OAuth round trip lands: a root-relative path or an absolute
//                           URL on the host (model/return-to.ts)
//   data-turnstile-sitekey  overrides the built-in Turnstile site key
//   data-origin             overrides the identity plane's origin (default https://evinvest.ltd)
// Events (bubbling, composed, no detail):
//   ev:signed-in            the platform session exists; the host starts its own RP login
//   ev:close                dismissed (Escape, backdrop, close button); the host drops `open`
import { dispatchSignedIn, HOST_ATTRS } from "@evinvest/mfe";
import css from "virtual:mfe/css";

import { SignInDialog } from "../features/sign-in";
import { BUILD } from "../shared/config/build";
import { defineElement } from "../shared/element/define-element";
import { dispatchClose } from "../shared/element/events";

const TAG = "mfe-concierge-sign-in";
const SITEKEY_ATTR = "data-turnstile-sitekey";

interface Openings {
  count: number;
  open: boolean;
  /** `?auth_error=` from the page this element connected on, shown until the first dismissal. */
  oauthError: string | null;
}
const openings = new WeakMap<HTMLElement, Openings>();

function openingsOf(host: HTMLElement): Openings {
  let state = openings.get(host);
  if (!state) {
    state = { count: 0, open: false, oauthError: null };
    openings.set(host, state);
  }
  return state;
}

defineElement({
  tag: TAG,
  css,
  observed: ["open", HOST_ATTRS.intent, HOST_ATTRS.returnTo, SITEKEY_ATTR],
  onConnect(host) {
    openingsOf(host).oauthError = new URL(location.href).searchParams.get("auth_error");
  },
  render(host) {
    const state = openingsOf(host);
    const open = host.hasAttribute("open");
    // A new opening gets a fresh dialog (its first screen, no stale error); a closing keeps
    // the same one so its exit animation plays.
    if (open && !state.open) state.count += 1;
    state.open = open;
    return (
      <SignInDialog
        key={state.count}
        open={open}
        intent={host.getAttribute(HOST_ATTRS.intent)}
        returnTo={host.getAttribute(HOST_ATTRS.returnTo)}
        sitekey={host.getAttribute(SITEKEY_ATTR) ?? BUILD.turnstileSiteKey}
        oauthError={state.oauthError}
        onDismiss={() => {
          state.oauthError = null;
          dispatchClose(host);
        }}
        onSignedIn={() => dispatchSignedIn(host)}
      />
    );
  },
});

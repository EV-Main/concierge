// <mfe-concierge-reauth> — "Confirm it is you" for a host on the platform origin whose
// backend refused an act as `reauth_required` (concierge#171: the admin console before it
// opens a payment). The proof goes to `/api/auth/reauth/*`, which moves the session's
// `auth_time` to now and re-sets `ev_access`; the host then retries its act ONCE.
//
// The host owns `open` and only `open`, as on the sign-in element: the element mounts once
// and stays; it never removes the attribute itself. Attributes:
//   open          present while the dialog shows
//   data-origin   overrides the identity plane's origin; dev and stand builds only
// There is no host mode: the proof is of the platform session itself, so the host has
// nothing to write in. Off the platform origin the dialog says to confirm on the platform
// and sends nothing — the reauth routes refuse any other `Origin`.
// Events (bubbling, composed, no detail):
//   ev:reauthenticated   the plane accepted the proof and the new `ev_access` is set;
//                        retry the refused act once, then drop `open`
//   ev:close             dismissed (Escape, backdrop, close or Cancel); drop `open`
// At most one of the two per opening.
import css from "virtual:mfe/css";

import { ReauthDialog } from "../features/sign-in-methods";
import { defineElement } from "../shared/element/define-element";
import { dispatchClose, dispatchReauthenticated } from "../shared/element/events";

const openings = new WeakMap<HTMLElement, { count: number; open: boolean }>();

defineElement({
  tag: "mfe-concierge-reauth",
  css,
  observed: ["open"],
  render(host) {
    let state = openings.get(host);
    if (!state) {
      state = { count: 0, open: false };
      openings.set(host, state);
    }
    const open = host.hasAttribute("open");
    // A new opening gets a fresh dialog (no stale code, error or "already reported"); a
    // closing keeps the same one so its exit animation plays.
    if (open && !state.open) state.count += 1;
    state.open = open;
    return <ReauthDialog key={state.count} open={open} onConfirmed={() => dispatchReauthenticated(host)} onDismiss={() => dispatchClose(host)} />;
  },
});

// <mfe-concierge-stepup> — "Confirm this operation" with a second factor, for a money-plane
// page on the platform origin or a listed scope host (docs/STEPUP-PROOF.md). The page hands
// over the operation's hash and the least assurance it needs; the element runs the ceremony
// at `<EV_PUBLIC_ORIGIN>/api/auth/stepup/*` and hands back an opaque proof the page forwards
// to its own backend. The page never learns which kinds of factor the account holds: the
// picker and every per-kind form live here.
//
// The host owns these attributes, as on the reauth element: the element mounts once and
// stays; it never removes `open` itself. Attributes:
//   open          present while the dialog shows
//   intent-hash   the operation's hash, 64 lowercase hex; required
//   min-aal       the least assurance level, an integer; required, no default — missing or
//                 malformed, the dialog says the page asked wrongly and sends nothing
//   data-origin   overrides the identity plane's origin; dev and stand builds only
// With no factor that gives `min-aal`, the platform origin enrols one in place and asks
// again; a scope host links to the platform's account page (enrolment answers the platform
// only) and offers to ask again.
// Events (bubbling, composed):
//   ev:stepup-proof   detail `{ proof, expiresAt }` (unix seconds): forward `proof` to the
//                     backend for this one operation, then drop `open`
//   ev:close          dismissed (Escape, backdrop, close or Cancel), no detail; drop `open`
// At most one of the two per opening.
import css from "virtual:mfe/css";

import { parseStepupRequest, StepupDialog } from "../features/second-factor";
import { ReauthPrompt } from "../features/sign-in-methods";
import { defineElement } from "../shared/element/define-element";
import { dispatchClose, dispatchStepupProof } from "../shared/element/events";

const INTENT_ATTR = "intent-hash";
const AAL_ATTR = "min-aal";

const openings = new WeakMap<HTMLElement, { count: number; open: boolean }>();

defineElement({
  tag: "mfe-concierge-stepup",
  css,
  observed: ["open", INTENT_ATTR, AAL_ATTR],
  render(host) {
    let state = openings.get(host);
    if (!state) {
      state = { count: 0, open: false };
      openings.set(host, state);
    }
    const open = host.hasAttribute("open");
    // A new opening gets a fresh dialog (a new ceremony, no stale code or "already
    // reported"); a closing keeps the same one so its exit animation plays.
    if (open && !state.open) state.count += 1;
    state.open = open;
    return (
      <StepupDialog
        key={state.count}
        open={open}
        request={parseStepupRequest(host.getAttribute(INTENT_ATTR), host.getAttribute(AAL_ATTR))}
        reauth={ReauthPrompt}
        onProof={(proof) => dispatchStepupProof(host, proof)}
        onDismiss={() => dispatchClose(host)}
      />
    );
  },
});

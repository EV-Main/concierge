// <mfe-concierge-account> — the account page (profile, security, notifications) a host
// mounts on its own `/account`. Moved from the banking cabinet's profile and settings.
//
// On the platform origin it reads and changes everything itself. On a scope host it shows
// who is signed in (the session is the one read allowed cross-origin) and links every
// action on the session to the platform's /account (ORG-RESTRUCTURE-PLAN §3.9 F).
// Attributes: `data-section` (`profile` | `security` | `notifications`; the element writes
// it back when the reader switches tabs), `data-origin` (dev and stand builds only).
// Events (bubbling, composed): `ev:section` (`{ section }`) when the reader switches tabs;
// `ev:navigate` (cancelable, `{ href }`) for a plain same-origin
// link click; `signout` when the reader signs out — on the platform after the platform
// session has ended, elsewhere for the host to end its own — after which the page goes to
// the platform's sign-out confirmation (shared/element/host-sign-out.ts).
import css from "virtual:mfe/css";

import { defineElement } from "../shared/element/define-element";
import { dispatchSection } from "../shared/element/events";
import { AccountView, sectionOf } from "../views/account";

const SECTION_ATTR = "data-section";

defineElement({
  tag: "mfe-concierge-account",
  css,
  observed: [SECTION_ATTR],
  render(host) {
    return (
      <AccountView
        section={sectionOf(host.getAttribute(SECTION_ATTR))}
        onSection={(next) => {
          host.setAttribute(SECTION_ATTR, next);
          dispatchSection(host, next);
        }}
      />
    );
  },
});

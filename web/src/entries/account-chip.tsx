// <mfe-concierge-account-chip> — the account chip, moved from the banking cabinet
// (<mfe-cabinet-account-chip>) with its apiVersion-2 contract unchanged; only the tag and
// the bundle's origin are new.
//
// Two modes, picked by `data-mode` (attribute names: HOST_ATTRS of @evinvest/mfe):
//   • default — reads the platform session itself; signed out, a CTA that opens the
//     platform's sign-in dialog (`data-intent`, `data-return-to` are passed on to it).
//   • host (`data-mode="host"`) — a host with its own session writes name, email, links and
//     service groups (`hostAttributes`); the chip fetches nothing and turns Sign out into a
//     `signout` event — then, off the platform origin, navigates to the platform's sign-out
//     confirmation (shared/element/host-sign-out.ts).
// Either mode: `data-profile-href` is the host's own account route for the profile row.
// Events (bubbling, composed): `signout` (host mode), `ev:navigate` (cancelable, `{ href }`,
// a plain same-origin menu-link click offered to the host's router). `[data-ready]` is set
// once the chip has painted; `data-layout="menu"` keeps the name below `sm`.
import { HOST_ATTRIBUTE_NAMES, HOST_ATTRS, isHostMode, readHostProps, safeHref } from "@evinvest/mfe";
import css from "virtual:mfe/css";

import { AccountChip, HostAccountChip } from "../features/account-chip";
import { apiOriginOf } from "../shared/config/origin";
import { defineElement } from "../shared/element/define-element";
import { signOutOnHost } from "../shared/element/host-sign-out";

defineElement({
  tag: "mfe-concierge-account-chip",
  css,
  observed: HOST_ATTRIBUTE_NAMES,
  render(host) {
    const read = (name: string) => host.getAttribute(name);
    return isHostMode(read) ? (
      <HostAccountChip {...readHostProps(read)} onSignOut={() => signOutOnHost(host, apiOriginOf(host))} />
    ) : (
      <AccountChip intent={read(HOST_ATTRS.intent)} returnTo={read(HOST_ATTRS.returnTo)} profileHref={safeHref(read(HOST_ATTRS.profileHref))} />
    );
  },
});

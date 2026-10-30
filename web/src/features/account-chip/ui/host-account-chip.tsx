import { useT } from "@evinvest/i18n/react";
import type { HostProps } from "@evinvest/mfe";

import { displayName, initialsOfName, truncateName } from "../../../shared/lib/identity";
import type { MenuIdentity } from "../lib/chip-parts";
import { AccountMenu } from "./account-menu";

/** Keeps the label from pushing the host's central nav off-centre. */
export const MAX_LABEL = 28;

export type HostAccountChipProps = HostProps & {
  /** The element turns this into its `signout` event; the host owns the session. */
  onSignOut: () => void;
};

/**
 * The chip on a host with its own session (`data-mode="host"`): who is signed in and the
 * host's own entries come from the element's attributes. No session read and no logout
 * request — the host holds both. Neither name nor email yet is the host still loading: the
 * skeleton, in the final box.
 */
export function HostAccountChip({ name, email, profileHref, switchHref, groups, onSignOut }: HostAccountChipProps) {
  const t = useT();
  const identity: MenuIdentity | null =
    name || email
      ? {
          email,
          initials: initialsOfName(name ?? "", email),
          label: truncateName(name ?? displayName(email, t), MAX_LABEL),
        }
      : null;
  return (
    <AccountMenu
      identity={identity}
      profileHref={profileHref}
      switchAccount={switchHref}
      groups={groups}
      onSignOut={onSignOut}
    />
  );
}

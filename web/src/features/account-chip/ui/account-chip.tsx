import { useT } from "@evinvest/i18n/react";
import type { MenuGroup } from "@evinvest/mfe";
import { useState } from "react";

import type { SessionUser } from "../../../shared/api/session";
import { BUILD } from "../../../shared/config/build";
import { platformAccountUrl } from "../../../shared/config/origin";
import { useElement } from "../../../shared/element/element-context";
import { displayName, initialsOfName, truncateName } from "../../../shared/lib/identity";
import { useSession } from "../../../shared/model/use-session";
import type { MenuIdentity } from "../lib/chip-parts";
import { signOut } from "../model/sign-out";
import { AccountMenu } from "./account-menu";
import { MAX_LABEL } from "./host-account-chip";
import { SignInCta } from "./sign-in-cta";

// The chip in default mode — on the platform's own pages, where it reads the platform
// session itself (`GET /api/auth/session`, allowed cross-origin too). States:
//   • session loading                 → AccountMenu skeleton (final box)
//   • signed out, or the plane down   → the sign-in CTA
//   • signed in                       → the chip; username, else a name from the email
// It never redirects on a dropped session: an anonymous visitor must not be bounced.
export function AccountChip({ intent, returnTo, profileHref }: { intent: string | null; returnTo: string | null; profileHref: string | null }) {
  const { api } = useElement();
  const { session, refresh } = useSession(api);
  if (session.kind === "loading") return <AccountMenu identity={null} profileHref={null} switchAccount={null} groups={[]} onSignOut={() => undefined} />;
  if (session.kind !== "signedIn") return <SignInCta intent={intent} returnTo={returnTo} onSignedIn={() => void refresh()} />;
  return <SignedInChip user={session.user} profileHref={profileHref} />;
}

function SignedInChip({ user, profileHref }: { user: SessionUser; profileHref: string | null }) {
  const t = useT();
  const { api, platform } = useElement();
  const [failed, setFailed] = useState(false);
  const identity: MenuIdentity = {
    email: user.email,
    initials: initialsOfName(user.username ?? "", user.email),
    label: truncateName(user.username ?? displayName(user.email, t), MAX_LABEL),
  };

  const onSignOut = async () => {
    setFailed(false);
    // Off the platform the session cannot be ended from here (§3.9 F): its account page can.
    if (!platform) return location.assign(platformAccountUrl(api.origin, "security"));
    if (await signOut(api)) location.reload();
    else setFailed(true);
  };

  return (
    <AccountMenu
      identity={identity}
      profileHref={profileHref}
      // Google's chooser is on every sign-in, and the new session closes this one. A platform
      // route; a scope host switches accounts through its own RP login instead.
      switchAccount={platform ? `${api.origin}/api/auth/login?returnTo=${encodeURIComponent(location.pathname + location.search)}` : null}
      groups={serviceGroups(t("ui.services", "Services"))}
      error={failed ? t("auth.err.signOut", "We couldn't sign you out. Please try again.") : null}
      onSignOut={() => void onSignOut()}
    />
  );
}

/** The Services group; Service-Arb is `current` when this page is the panel's own origin. */
function serviceGroups(label: string): MenuGroup[] {
  const url = BUILD.saPanelUrl;
  if (!url) return [];
  let current = false;
  try {
    current = location.origin === new URL(url).origin;
  } catch {
    // A malformed build-time URL only loses the highlight.
  }
  return [{ id: "services", label, items: [{ id: "service-arb", href: url, label: "Service-Arb", external: false, current }] }];
}

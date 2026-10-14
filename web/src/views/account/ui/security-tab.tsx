import { useT } from "@evinvest/i18n/react";
import { dispatchSignOut } from "@evinvest/mfe";
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, ListRows } from "@evinvest/uikit";
import { useState } from "react";

import { SessionsCard } from "../../../features/sessions";
import { SignInMethodRows } from "../../../features/sign-in-methods";
import { anyBody } from "../../../shared/api/auth-api";
import { useElement } from "../../../shared/element/element-context";
import { signOutOnHost } from "../../../shared/element/host-sign-out";
import { ManageOnPlatform } from "../../../shared/ui/manage-on-platform";

export function SecurityTab({ onChanged }: { onChanged: () => void }) {
  const t = useT();
  const { platform } = useElement();
  return (
    <div className="flex flex-col gap-4">
      {platform ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle>{t("ui.security", "Security")}</CardTitle>
              <CardDescription>{t("settings.securitySub", "How you sign in and where your account is active")}</CardDescription>
            </CardHeader>
            <CardContent>
              <ListRows>
                <SignInMethodRows onChanged={onChanged} />
              </ListRows>
            </CardContent>
          </Card>
          <SessionsCard />
        </>
      ) : (
        <ManageOnPlatform section="security" title={t("ui.security", "Security")} />
      )}
      <SignOutCard />
    </div>
  );
}

/**
 * Sign out. On the platform the element ends the platform session first (only it can),
 * then tells the host (`signout`). On a scope host it tells the host, which ends its own
 * session, and goes to the platform's sign-out confirmation for the platform session.
 */
function SignOutCard() {
  const t = useT();
  const { api, platform, host } = useElement();
  const [failed, setFailed] = useState(false);

  async function signOut() {
    setFailed(false);
    if (!platform) return signOutOnHost(host, api.origin);
    if (!(await api.send("POST", "/logout", {}, anyBody, true)).ok) return setFailed(true);
    dispatchSignOut(host);
  }

  return (
    <Card>
      <CardContent className="flex flex-wrap items-center justify-between gap-3">
        <span className="text-sm text-ink-soft">{t("account.signOutHere", "Sign out on this device.")}</span>
        <Button variant="outline" onClick={() => void signOut()}>
          {t("auth.signOut", "Sign out")}
        </Button>
        {failed && <p role="alert" className="m-0 w-full text-sm text-accent-error">{t("auth.err.signOut", "We couldn't sign you out. Please try again.")}</p>}
      </CardContent>
    </Card>
  );
}

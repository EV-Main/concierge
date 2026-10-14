import { useT } from "@evinvest/i18n/react";
import { Badge, Button, ListRow, Skeleton } from "@evinvest/uikit";
import { useEffect, useState } from "react";

import { useElement } from "../../../shared/element/element-context";
import { readMethods, setPassword, type SignInMethods } from "../api/methods-api";
import { CodeForm } from "./code-form";
import { EmailVerifyForm } from "./email-verify-form";
import { Passkeys } from "./passkeys";
import { UsernameForm } from "./username-form";

type Editing = null | "verify" | "password" | "username";

const PROVIDER_NAMES: Record<string, string> = { google: "Google", github: "GitHub" };

/**
 * How the signed-in account signs in — its address and whether it is proven, its username,
 * providers, password and passkeys — and the changes a reader makes here. Platform pages
 * only; `onChanged` lets the page re-read the session, which carries `emailVerified`.
 */
export function SignInMethodRows({ onChanged }: { onChanged: () => void }) {
  const t = useT();
  const { api } = useElement();
  const [methods, setMethods] = useState<SignInMethods | null | undefined>(undefined);
  const [editing, setEditing] = useState<Editing>(null);

  // Bumped after every change, which re-reads the methods.
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let live = true;
    void readMethods(api).then((answer) => {
      if (live) setMethods(answer.ok ? answer.body : null);
    });
    return () => {
      live = false;
    };
  }, [api, revision]);

  const done = () => {
    setEditing(null);
    setRevision((r) => r + 1);
    onChanged();
  };
  const toggle = (what: Exclude<Editing, null>) => setEditing(editing === what ? null : what);

  if (methods === undefined) return <Skeleton className="my-3 h-10 w-full" />;
  if (methods === null) return <p className="m-0 py-3 text-xs text-ink-soft">{t("account.unavailable", "This could not be loaded. Try again in a moment.")}</p>;

  const ways = [...methods.providers.map((p) => PROVIDER_NAMES[p] ?? p), ...(methods.password ? [t("auth.method.password", "Password")] : []), t("auth.method.code", "Email code")];
  return (
    <>
      <ListRow label={methods.email} description={methods.emailVerified ? t("auth.email.verified", "Verified") : t("auth.email.unverifiedSub", "Not verified — identity checks need a verified email")}>
        {methods.emailVerified ? (
          <Badge variant="outline">{t("auth.email.verified", "Verified")}</Badge>
        ) : (
          <Button variant="outline" size="sm" onClick={() => toggle("verify")}>
            {t("auth.email.verify", "Verify")}
          </Button>
        )}
      </ListRow>
      {editing === "verify" && <EmailVerifyForm email={methods.email} onDone={done} />}
      <ListRow label={t("auth.username.title", "Username")} description={methods.username ? `@${methods.username}` : t("auth.username.none", "None yet — once set, it signs you in like your email")}>
        <Button variant="outline" size="sm" onClick={() => toggle("username")}>
          {t("auth.username.change", "Change")}
        </Button>
      </ListRow>
      {editing === "username" && <UsernameForm current={methods.username ?? ""} onDone={done} />}
      <ListRow label={t("auth.methods.title", "Sign-in methods")} description={ways.join(" · ")}>
        <Button variant="outline" size="sm" onClick={() => toggle("password")}>
          {methods.password ? t("auth.password.change", "Change password") : t("auth.password.set", "Set password")}
        </Button>
      </ListRow>
      {editing === "password" && <CodeForm withPassword action={t("auth.password.save", "Save password")} submit={(code, password) => setPassword(api, password, code)} onDone={done} />}
      <Passkeys methods={methods} onChanged={done} />
    </>
  );
}

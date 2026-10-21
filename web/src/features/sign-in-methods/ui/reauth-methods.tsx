import { useT } from "@evinvest/i18n/react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@evinvest/uikit";
import { useState } from "react";

import { isReauthMethod, type ReauthMethod } from "../model/reauth";
import { ReauthCode } from "./reauth-code";
import { ReauthPasskey } from "./reauth-passkey";
import { ReauthPassword } from "./reauth-password";

/**
 * The ways to confirm, one tab each. Shared by the Security tab's inline step and the
 * `mfe-concierge-reauth` dialog, so both offer the same methods with the same refusals.
 */
export function ReauthMethods({ methods, onConfirmed }: { methods: ReauthMethod[]; onConfirmed: () => void }) {
  const t = useT();
  const [method, setMethod] = useState<ReauthMethod | undefined>(methods[0]);

  if (method === undefined) {
    return (
      <p role="alert" className="m-0 text-xs text-accent-error">
        {t("auth.reauth.none", "There is no way to confirm right now. Verify your email first, or sign in again.")}
      </p>
    );
  }
  const labels: Record<ReauthMethod, string> = {
    code: t("auth.reauth.method.code", "Email code"),
    password: t("auth.method.password", "Password"),
    passkey: t("auth.reauth.method.passkey", "Passkey"),
  };
  return (
    <Tabs value={method} onValueChange={(next) => isReauthMethod(next) && setMethod(next)}>
      <TabsList aria-label={t("auth.reauth.how", "How to confirm")}>
        {methods.map((m) => (
          <TabsTrigger key={m} value={m}>
            {labels[m]}
          </TabsTrigger>
        ))}
      </TabsList>
      <div className="pt-3">
        <TabsContent value="code">
          <ReauthCode onConfirmed={onConfirmed} />
        </TabsContent>
        <TabsContent value="password">
          <ReauthPassword onConfirmed={onConfirmed} />
        </TabsContent>
        <TabsContent value="passkey">
          <ReauthPasskey onConfirmed={onConfirmed} />
        </TabsContent>
      </div>
    </Tabs>
  );
}

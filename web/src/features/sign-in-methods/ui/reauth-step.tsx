import { useT } from "@evinvest/i18n/react";
import { Button, Tabs, TabsContent, TabsList, TabsTrigger } from "@evinvest/uikit";
import { useEffect, useId, useRef, useState } from "react";

import { isReauthMethod, type ReauthMethod } from "../model/reauth";
import { ReauthCode } from "./reauth-code";
import { ReauthPasskey } from "./reauth-passkey";
import { ReauthPassword } from "./reauth-password";

/**
 * The confirmation the plane asks for before a sensitive act on an old session. It takes
 * focus when it opens, so a keyboard reader lands on it rather than on the button that
 * opened it; `onCancel` hands focus back to whoever asked.
 */
export function ReauthStep({ methods, onConfirmed, onCancel }: { methods: ReauthMethod[]; onConfirmed: () => void; onCancel: () => void }) {
  const t = useT();
  const titleId = useId();
  const panel = useRef<HTMLElement>(null);
  const [method, setMethod] = useState<ReauthMethod | undefined>(methods[0]);

  useEffect(() => {
    panel.current?.focus();
  }, []);

  const labels: Record<ReauthMethod, string> = {
    code: t("auth.reauth.method.code", "Email code"),
    password: t("auth.method.password", "Password"),
    passkey: t("auth.reauth.method.passkey", "Passkey"),
  };
  return (
    <li className="list-none pb-3">
      <section ref={panel} tabIndex={-1} aria-labelledby={titleId} className="flex flex-col gap-3 rounded-md border border-ink/10 p-3">
        <div className="flex flex-col gap-1">
          <h3 id={titleId} className="m-0 text-sm font-semibold">
            {t("auth.reauth.title", "Confirm it is you")}
          </h3>
          <p className="m-0 text-xs text-ink-soft">{t("auth.reauth.sub", "You signed in a while ago. Confirm again to change your passkeys.")}</p>
        </div>
        {method === undefined ? (
          <p role="alert" className="m-0 text-xs text-accent-error">
            {t("auth.reauth.none", "There is no way to confirm right now. Verify your email first, or sign in again.")}
          </p>
        ) : (
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
        )}
        <Button variant="ghost" size="sm" className="self-start" onClick={onCancel}>
          {t("auth.reauth.cancel", "Cancel")}
        </Button>
      </section>
    </li>
  );
}

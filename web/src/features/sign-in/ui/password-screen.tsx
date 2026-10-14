import { useT } from "@evinvest/i18n/react";
import { Button, Input, Spinner } from "@evinvest/uikit";
import { useState, type ReactNode } from "react";

import { FIELD, Heading, PRIMARY, submitWith, TextAction } from "./parts";

export function PasswordScreen({ busy, human, challenge, onSubmit, onCode, onSignUp }: { busy: boolean; human: boolean; challenge: ReactNode; onSubmit: (identifier: string, password: string) => void; onCode: () => void; onSignUp: () => void }) {
  const t = useT();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  return (
    <>
      <Heading title={t("auth.dialog.heading", "Sign in or create an account")} />
      <form className="flex flex-col gap-6" onSubmit={submitWith(() => onSubmit(identifier.trim(), password))}>
        <div className="flex flex-col gap-5">
          <Input autoComplete="username" placeholder={t("auth.field.identifier", "Email or username")} aria-label={t("auth.field.identifier", "Email or username")} className={FIELD} value={identifier} onChange={(e) => setIdentifier(e.target.value)} />
          <div className="flex flex-col">
            <Input type="password" autoComplete="current-password" placeholder={t("auth.field.password", "Password")} aria-label={t("auth.field.password", "Password")} className={FIELD} value={password} onChange={(e) => setPassword(e.target.value)} />
            {challenge}
          </div>
        </div>
        <Button type="submit" className={PRIMARY} disabled={busy || !human || !identifier.trim() || !password}>
          {busy ? <Spinner /> : t("auth.signIn", "Sign in")}
        </Button>
      </form>
      <div className="-mt-3 flex items-center justify-between gap-3">
        <TextAction onClick={onCode}>{t("auth.useCodeInstead", "Sign in with a code instead")}</TextAction>
        <TextAction onClick={onSignUp}>{t("auth.createAccount", "Create an account")}</TextAction>
      </div>
    </>
  );
}

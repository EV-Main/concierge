import { useT } from "@evinvest/i18n/react";
import { Button, Input, Spinner } from "@evinvest/uikit";
import { useState, type ReactNode } from "react";

import { FIELD, Heading, looksLikeEmail, PRIMARY, submitWith, TextAction } from "./parts";

export function CodeScreen({ busy, human, challenge, onSubmit, onPassword, children }: { busy: boolean; human: boolean; challenge: ReactNode; onSubmit: (email: string) => void; onPassword: () => void; children: ReactNode }) {
  const t = useT();
  const [email, setEmail] = useState("");
  return (
    <>
      <Heading title={t("auth.dialog.heading", "Sign in or create an account")} />
      <form className="flex flex-col gap-6" onSubmit={submitWith(() => onSubmit(email.trim()))}>
        <div className="flex flex-col">
          <Input type="email" autoComplete="email" placeholder={t("auth.field.email", "Email")} aria-label={t("auth.field.email", "Email")} className={FIELD} value={email} onChange={(e) => setEmail(e.target.value)} />
          {challenge}
        </div>
        <Button type="submit" className={PRIMARY} disabled={busy || !human || !looksLikeEmail(email)}>
          {busy ? <Spinner /> : t("auth.useLoginCode", "Email me a code")}
        </Button>
      </form>
      <div className="-mt-3 flex justify-center">
        <TextAction onClick={onPassword}>{t("auth.usePasswordInstead", "Sign in with a password instead")}</TextAction>
      </div>
      {children}
    </>
  );
}

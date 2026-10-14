import { useT } from "@evinvest/i18n/react";
import { Button, Checkbox, Input, Spinner } from "@evinvest/uikit";
import { useId, useState, type ReactNode } from "react";

import { FIELD, Heading, looksLikeEmail, PRIMARY, submitWith, TextAction } from "./parts";

const MIN_PASSWORD = 8;

export function SignUpScreen({ busy, human, challenge, onSubmit, onSignIn }: { busy: boolean; human: boolean; challenge: ReactNode; onSubmit: (email: string, password: string, verify: boolean) => void; onSignIn: () => void }) {
  const t = useT();
  const verifyId = useId();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [verify, setVerify] = useState(true);
  return (
    <>
      <Heading title={t("auth.signup.heading", "Create an account")} description={t("auth.signup.desc", "Your account works right away. A KYC check later needs a verified email.")} />
      <form className="flex flex-col gap-6" onSubmit={submitWith(() => onSubmit(email.trim(), password, verify))}>
        <div className="flex flex-col gap-5">
          <Input type="email" autoComplete="email" placeholder={t("auth.field.email", "Email")} aria-label={t("auth.field.email", "Email")} className={FIELD} value={email} onChange={(e) => setEmail(e.target.value)} />
          <Input type="password" autoComplete="new-password" placeholder={t("auth.field.password", "Password")} aria-label={t("auth.field.password", "Password")} className={FIELD} value={password} onChange={(e) => setPassword(e.target.value)} />
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <Checkbox id={verifyId} checked={verify} onCheckedChange={setVerify} />
              <label htmlFor={verifyId} className="text-(length:--sign-in-text-body) text-ink-soft">
                {t("auth.signup.verifyNow", "Verify my email now")}
              </label>
            </div>
            {challenge}
          </div>
        </div>
        <Button type="submit" className={PRIMARY} disabled={busy || !human || !looksLikeEmail(email) || password.length < MIN_PASSWORD}>
          {busy ? <Spinner /> : t("auth.signup.create", "Create account")}
        </Button>
      </form>
      <div className="-mt-3 flex justify-center">
        <TextAction onClick={onSignIn}>{t("auth.signup.haveAccount", "Already have an account? Sign in")}</TextAction>
      </div>
    </>
  );
}

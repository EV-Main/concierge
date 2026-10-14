import { useT } from "@evinvest/i18n/react";
import { Button, Spinner } from "@evinvest/uikit";
import type { ReactNode } from "react";

import { Heading, PRIMARY, TextAction } from "./parts";

/** Right after sign-up: the account works already; proving the address is one mailed code away. */
export function VerifyStart({ email, busy, human, challenge, onSend, onLater }: { email: string; busy: boolean; human: boolean; challenge: ReactNode; onSend: () => void; onLater: () => void }) {
  const t = useT();
  return (
    <>
      <Heading title={t("auth.verify.title", "Confirm your email")} description={t("auth.verify.start", "Your account is ready. Send a 6 digit code to {email} to verify it, or skip and verify later.", { email })} />
      <div className="flex flex-col">{challenge}</div>
      <Button type="button" className={PRIMARY} disabled={busy || !human} onClick={onSend}>
        {busy ? <Spinner /> : t("auth.useLoginCode", "Email me a code")}
      </Button>
      <div className="-mt-3 flex justify-center">
        <TextAction onClick={onLater}>{t("auth.verify.later", "Verify later")}</TextAction>
      </div>
    </>
  );
}

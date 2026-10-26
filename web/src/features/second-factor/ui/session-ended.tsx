import { useT } from "@evinvest/i18n/react";
import { Button } from "@evinvest/uikit";
import { useEffect, useRef } from "react";

export function SessionEnded({ onContinue }: { onContinue: () => void }) {
  const t = useT();
  const proceed = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    proceed.current?.focus();
  }, []);
  return (
    <li className="flex list-none flex-col gap-2 py-3">
      <p role="status" className="m-0 text-sm text-ink">
        {t("auth.secondFactor.ended", "Your second factors were removed and every session of your account was signed out, this one included. Sign in again, then add a new authenticator.")}
      </p>
      <Button ref={proceed} size="sm" className="self-start" onClick={onContinue}>
        {t("auth.secondFactor.signInAgain", "Sign in again")}
      </Button>
    </li>
  );
}

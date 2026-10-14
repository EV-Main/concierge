import { useT } from "@evinvest/i18n/react";
import { Button } from "@evinvest/uikit";

import { platformAccountUrl } from "../../../shared/config/origin";
import { useElement } from "../../../shared/element/element-context";
import { Heading, PRIMARY, SECONDARY } from "./parts";

/** The account exists and is signed in, but this browser cannot confirm the address here. */
export function ConfirmOnPlatform({ onDone }: { onDone: () => void }) {
  const t = useT();
  const { api } = useElement();
  return (
    <>
      <Heading title={t("auth.verify.title", "Confirm your email")} description={t("auth.verify.onPlatform", "Your account is ready. Confirm your email from your account on evinvest.ltd.")} />
      <a className={SECONDARY} href={platformAccountUrl(api.origin, "security")} target="_blank" rel="noopener noreferrer">
        {t("account.openOnPlatform", "Open on evinvest.ltd")}
      </a>
      <Button type="button" className={PRIMARY} onClick={onDone}>
        {t("auth.verify.continue", "Continue")}
      </Button>
    </>
  );
}

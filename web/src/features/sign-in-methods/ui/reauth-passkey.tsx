import { useT } from "@evinvest/i18n/react";
import { Button } from "@evinvest/uikit";

import { useElement } from "../../../shared/element/element-context";
import { reauthWithPasskey } from "../api/reauth-api";
import { useAttempt } from "../model/use-attempt";
import { reauthRefusal } from "./refusal";

export function ReauthPasskey({ onConfirmed }: { onConfirmed: () => void }) {
  const t = useT();
  const { api } = useElement();
  const { busy, error, run } = useAttempt(onConfirmed);
  return (
    <div className="flex flex-col gap-2">
      <Button size="sm" className="self-start" disabled={busy} onClick={() => void run(() => reauthWithPasskey(api))}>
        {t("auth.reauth.usePasskey", "Use a passkey")}
      </Button>
      {error && (
        <p role="alert" className="m-0 text-xs text-accent-error">
          {reauthRefusal(t, error)}
        </p>
      )}
    </div>
  );
}

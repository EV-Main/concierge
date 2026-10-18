import { useT } from "@evinvest/i18n/react";
import { Button } from "@evinvest/uikit";
import { useEffect, useRef } from "react";

/** After a confirmation, an act the browser runs only from a click waits for that click. */
export function ReauthReady({ busy, onProceed, onCancel }: { busy: boolean; onProceed: () => void; onCancel: () => void }) {
  const t = useT();
  const proceed = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    proceed.current?.focus();
  }, []);
  return (
    <li className="flex list-none flex-col gap-2 pb-3">
      <p role="status" className="m-0 text-xs text-ink-soft">
        {t("auth.reauth.done", "Confirmed. Now add the passkey.")}
      </p>
      <div className="flex items-center gap-3">
        <Button ref={proceed} size="sm" disabled={busy} onClick={onProceed}>
          {t("auth.passkeys.add", "Add a passkey")}
        </Button>
        <Button variant="ghost" size="sm" disabled={busy} onClick={onCancel}>
          {t("auth.reauth.cancel", "Cancel")}
        </Button>
      </div>
    </li>
  );
}

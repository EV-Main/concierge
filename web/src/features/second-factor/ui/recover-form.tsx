import { useT } from "@evinvest/i18n/react";
import { Button, Input } from "@evinvest/uikit";
import { useState, type FormEvent } from "react";

/** Spending a code removes every factor and ends every session, so the form says so before it is sent. */
export function RecoverForm({ busy, onRecover, onCancel }: { busy: boolean; onRecover: (code: string) => void; onCancel: () => void }) {
  const t = useT();
  const [code, setCode] = useState("");

  function submit(event: FormEvent) {
    event.preventDefault();
    onRecover(code.trim());
  }

  return (
    <li className="list-none pb-3">
      <form className="flex flex-col gap-2" onSubmit={submit}>
        <p className="m-0 text-xs text-ink-soft">
          {t("auth.secondFactor.recover.sub", "A recovery code removes all your second factors and signs you out everywhere, this device included. Add a new authenticator after you sign in again.")}
        </p>
        <Input autoComplete="off" spellCheck={false} aria-label={t("auth.secondFactor.recover.field", "Recovery code")} placeholder="xxxx-xxxx-xxxx-xxxx" value={code} onChange={(e) => setCode(e.target.value)} />
        <div className="flex items-center gap-3">
          <Button type="submit" variant="destructive" size="sm" disabled={busy || code.trim() === ""}>
            {t("auth.secondFactor.recover.submit", "Use recovery code")}
          </Button>
          <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={onCancel}>
            {t("auth.reauth.cancel", "Cancel")}
          </Button>
        </div>
      </form>
    </li>
  );
}

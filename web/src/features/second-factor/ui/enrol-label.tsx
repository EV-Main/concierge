import { useT } from "@evinvest/i18n/react";
import { Button, Input } from "@evinvest/uikit";
import { useState, type FormEvent } from "react";

const MAX_LABEL = 64;

export function EnrolLabel({ busy, onStart, onCancel }: { busy: boolean; onStart: (label: string) => void; onCancel: () => void }) {
  const t = useT();
  const [label, setLabel] = useState(() => t("auth.secondFactor.kind.totp", "Authenticator app"));

  function submit(event: FormEvent) {
    event.preventDefault();
    onStart(label.trim());
  }

  return (
    <li className="list-none pb-3">
      <form className="flex flex-col gap-2" onSubmit={submit}>
        <Input aria-label={t("auth.secondFactor.labelField", "Name, to tell it apart later")} maxLength={MAX_LABEL} value={label} onChange={(e) => setLabel(e.target.value)} />
        <div className="flex items-center gap-3">
          <Button type="submit" size="sm" disabled={busy || label.trim() === ""}>
            {t("auth.secondFactor.continue", "Continue")}
          </Button>
          <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={onCancel}>
            {t("auth.reauth.cancel", "Cancel")}
          </Button>
        </div>
      </form>
    </li>
  );
}

import { useT } from "@evinvest/i18n/react";
import { Button } from "@evinvest/uikit";

/** What an act will cost, said before it runs; the act runs only on `action`. */
export function ConfirmAct({ message, action, busy, onConfirm, onCancel }: { message: string; action: string; busy: boolean; onConfirm: () => void; onCancel: () => void }) {
  const t = useT();
  return (
    <li className="flex list-none flex-col gap-2 pb-3">
      <p role="alert" className="m-0 text-xs text-accent-error">
        {message}
      </p>
      <div className="flex items-center gap-3">
        <Button variant="destructive" size="sm" disabled={busy} onClick={onConfirm}>
          {action}
        </Button>
        <Button variant="ghost" size="sm" disabled={busy} onClick={onCancel}>
          {t("auth.reauth.cancel", "Cancel")}
        </Button>
      </div>
    </li>
  );
}

import { useT } from "@evinvest/i18n/react";
import { Button } from "@evinvest/uikit";

export function RemoveLast({ busy, onRemove, onCancel }: { busy: boolean; onRemove: () => void; onCancel: () => void }) {
  const t = useT();
  return (
    <li className="flex list-none flex-col gap-2 pb-3">
      <p role="alert" className="m-0 text-xs text-accent-error">
        {t("auth.secondFactor.removeLast", "This is your only second factor. Without one, withdrawals are refused until you add a new one. Your recovery codes stop working too.")}
      </p>
      <div className="flex items-center gap-3">
        <Button variant="destructive" size="sm" disabled={busy} onClick={onRemove}>
          {t("auth.secondFactor.removeAnyway", "Remove anyway")}
        </Button>
        <Button variant="ghost" size="sm" disabled={busy} onClick={onCancel}>
          {t("auth.reauth.cancel", "Cancel")}
        </Button>
      </div>
    </li>
  );
}

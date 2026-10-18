import { useT } from "@evinvest/i18n/react";
import { Button, Input } from "@evinvest/uikit";
import { useId, useState, type FormEvent } from "react";

import { useElement } from "../../../shared/element/element-context";
import { reauthWithPassword } from "../api/reauth-api";
import { useAttempt } from "../model/use-attempt";
import { reauthRefusal } from "./refusal";

export function ReauthPassword({ onConfirmed }: { onConfirmed: () => void }) {
  const t = useT();
  const { api } = useElement();
  const [password, setPassword] = useState("");
  const { busy, error, run } = useAttempt(onConfirmed);
  const errorId = useId();

  function submit(event: FormEvent) {
    event.preventDefault();
    void run(() => reauthWithPassword(api, password));
  }

  return (
    <form className="flex flex-col gap-2" onSubmit={submit}>
      <Input
        type="password"
        autoComplete="current-password"
        aria-label={t("auth.field.password", "Password")}
        placeholder={t("auth.field.password", "Password")}
        aria-invalid={error === "invalid_credentials" || undefined}
        aria-describedby={error ? errorId : undefined}
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <Button type="submit" size="sm" className="self-start" disabled={busy || !password}>
        {t("auth.reauth.confirm", "Confirm")}
      </Button>
      {error && (
        <p id={errorId} role="alert" className="m-0 text-xs text-accent-error">
          {reauthRefusal(t, error)}
        </p>
      )}
    </form>
  );
}

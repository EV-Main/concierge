import { useT } from "@evinvest/i18n/react";
import { Button, Input } from "@evinvest/uikit";
import { useState, type FormEvent } from "react";

import type { AuthAnswer } from "../../../shared/api/auth-api";
import { useElement } from "../../../shared/element/element-context";
import { requestVerification } from "../api/methods-api";
import { refusal } from "./refusal";

const CODE_LENGTH = 6;
const MIN_PASSWORD = 8;

/** Mail a code to the account's address, then spend it on `submit` (with a new password when asked). */
export function CodeForm({ action, withPassword = false, submit, onDone }: { action: string; withPassword?: boolean; submit: (code: string, password: string) => Promise<AuthAnswer<true>>; onDone: () => void }) {
  const t = useT();
  const { api } = useElement();
  const [sent, setSent] = useState(false);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function send() {
    setBusy(true);
    const answer = await requestVerification(api);
    setBusy(false);
    if (answer.ok) setSent(true);
    else setError(refusal(t, answer.error));
  }

  async function confirm(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    const answer = await submit(code.trim(), password);
    setBusy(false);
    if (answer.ok) onDone();
    else setError(refusal(t, answer.error));
  }

  return (
    // A row of the surrounding ListRows: an `li`, so the list stays a list.
    <li className="flex list-none flex-col gap-2 pb-3">
      {!sent ? (
        <Button size="sm" className="self-start" disabled={busy} onClick={() => void send()}>
          {t("auth.code.mailMe", "Email me a code")}
        </Button>
      ) : (
        <form className="flex flex-col gap-2" onSubmit={(e) => void confirm(e)}>
          <Input inputMode="numeric" autoComplete="one-time-code" aria-label={t("auth.code.label", "Code")} placeholder={t("auth.code.label", "Code")} value={code} onChange={(e) => setCode(e.target.value)} />
          {withPassword && <Input type="password" autoComplete="new-password" aria-label={t("auth.field.newPassword", "New password")} placeholder={t("auth.field.newPassword", "New password")} value={password} onChange={(e) => setPassword(e.target.value)} />}
          <Button type="submit" size="sm" className="self-start" disabled={busy || code.trim().length !== CODE_LENGTH || (withPassword && password.length < MIN_PASSWORD)}>
            {action}
          </Button>
        </form>
      )}
      {error && <p role="alert" className="m-0 text-xs text-accent-error">{error}</p>}
    </li>
  );
}

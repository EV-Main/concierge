import { useT } from "@evinvest/i18n/react";
import { Button, Input } from "@evinvest/uikit";
import { useState, type FormEvent } from "react";

import { requestCode, verifyCode } from "../../../shared/api/code-api";
import { BUILD } from "../../../shared/config/build";
import { useElement } from "../../../shared/element/element-context";
import { Turnstile } from "../../../shared/ui/turnstile";
import { refusal } from "./refusal";

const CODE_LENGTH = 6;

/** Prove the account's address: a mailed code through /code/*, which marks it verified. */
export function EmailVerifyForm({ email, onDone }: { email: string; onDone: () => void }) {
  const t = useT();
  const { api } = useElement();
  const [token, setToken] = useState<string | null>(null);
  const [generation, setGeneration] = useState(0);
  const [sent, setSent] = useState(false);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function send() {
    setBusy(true);
    setError(null);
    const answer = await requestCode(api, email, token ?? "");
    // The token is single-use; the widget re-arms for a resend.
    setToken(null);
    setGeneration((g) => g + 1);
    setBusy(false);
    if (answer.ok) setSent(true);
    else setError(refusal(t, answer.error));
  }

  async function confirm(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    const answer = await verifyCode(api, email, code.trim());
    setBusy(false);
    if (answer.ok) onDone();
    else setError(refusal(t, answer.error));
  }

  return (
    <li className="flex list-none flex-col gap-2 pb-3">
      {!sent ? (
        <>
          <Turnstile sitekey={BUILD.turnstileSiteKey} generation={generation} onToken={setToken} onUnavailable={() => setError(t("auth.err.captchaLoad", "Captcha failed to load. Please refresh the page."))} />
          <Button size="sm" className="self-start" disabled={busy || token === null} onClick={() => void send()}>
            {t("auth.code.mailMe", "Email me a code")}
          </Button>
        </>
      ) : (
        <form className="flex flex-col gap-2" onSubmit={(e) => void confirm(e)}>
          <Input inputMode="numeric" autoComplete="one-time-code" aria-label={t("auth.code.label", "Code")} placeholder={t("auth.code.label", "Code")} value={code} onChange={(e) => setCode(e.target.value)} />
          <Button type="submit" size="sm" className="self-start" disabled={busy || code.trim().length !== CODE_LENGTH}>
            {t("auth.email.confirm", "Confirm")}
          </Button>
        </form>
      )}
      {error && <p role="alert" className="m-0 text-xs text-accent-error">{error}</p>}
    </li>
  );
}

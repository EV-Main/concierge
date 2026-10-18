import { useT } from "@evinvest/i18n/react";
import { Button, Input } from "@evinvest/uikit";
import { useId, useState, type FormEvent } from "react";

import { BUILD } from "../../../shared/config/build";
import { useElement } from "../../../shared/element/element-context";
import { Turnstile } from "../../../shared/ui/turnstile";
import { requestReauthCode, verifyReauthCode } from "../api/reauth-api";
import { useAttempt } from "../model/use-attempt";
import { reauthRefusal } from "./refusal";

const CODE_LENGTH = 6;

/** Mail a code to the account's verified address (behind a captcha, as every mail is), then spend it. */
export function ReauthCode({ onConfirmed }: { onConfirmed: () => void }) {
  const t = useT();
  const { api } = useElement();
  const [sent, setSent] = useState(false);
  const [code, setCode] = useState("");
  const [token, setToken] = useState<string | null>(null);
  // A Turnstile token is single-use: each request re-arms the widget.
  const [generation, setGeneration] = useState(0);
  const { busy, error, setError, run } = useAttempt(onConfirmed);
  const errorId = useId();

  async function send() {
    if (token === null) return;
    const spent = token;
    setError(null);
    setToken(null);
    setGeneration((g) => g + 1);
    // A request is not a confirmation: `run` would call onConfirmed, so the mail goes through its own call.
    const answer = await requestReauthCode(api, spent);
    if (answer.ok) {
      setSent(true);
      setCode("");
    } else setError(answer.error);
  }

  function verify(event: FormEvent) {
    event.preventDefault();
    void run(() => verifyReauthCode(api, code.trim()));
  }

  const failure = error && (
    <p id={errorId} role="alert" className="m-0 text-xs text-accent-error">
      {reauthRefusal(t, error)}
    </p>
  );

  if (sent) {
    return (
      <form className="flex flex-col gap-2" onSubmit={verify}>
        <Input
          inputMode="numeric"
          autoComplete="one-time-code"
          aria-label={t("auth.code.label", "Code")}
          placeholder={t("auth.code.label", "Code")}
          aria-invalid={error === "invalid_code" || undefined}
          aria-describedby={error ? errorId : undefined}
          value={code}
          onChange={(e) => setCode(e.target.value)}
        />
        <div className="flex items-center gap-3">
          <Button type="submit" size="sm" disabled={busy || code.trim().length !== CODE_LENGTH}>
            {t("auth.reauth.confirm", "Confirm")}
          </Button>
          <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => setSent(false)}>
            {t("auth.reauth.newCode", "Send a new code")}
          </Button>
        </div>
        {failure}
      </form>
    );
  }
  return (
    <div className="flex flex-col gap-2">
      <Turnstile sitekey={BUILD.turnstileSiteKey} generation={generation} onToken={setToken} onUnavailable={() => setError("captcha_unavailable")} />
      <Button size="sm" className="self-start" disabled={busy || token === null} onClick={() => void send()}>
        {t("auth.code.mailMe", "Email me a code")}
      </Button>
      {failure}
    </div>
  );
}

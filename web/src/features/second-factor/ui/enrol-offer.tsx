import { useT } from "@evinvest/i18n/react";
import { Button } from "@evinvest/uikit";
import { useId, useState } from "react";

import type { AuthError } from "../../../shared/api/auth-api";
import { useElement } from "../../../shared/element/element-context";
import { confirmEnrolment, type Offer } from "../api/second-factor-api";
import { AnswerForm } from "./answer-form";
import { CopyButton } from "./copy-button";
import { QrCode } from "./qr-code";
import { secondFactorRefusal } from "./refusal";

/** The new factor's secret, shown this once, and its first code, which proves the app holds it. */
export function EnrolOffer({ offer, onEnrolled, onRestart, onCancel }: { offer: Offer; onEnrolled: (codes: string[] | null) => void; onRestart: () => void; onCancel: () => void }) {
  const t = useT();
  const { api } = useElement();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<AuthError | null>(null);
  const [tries, setTries] = useState(0);
  const errorId = useId();

  async function confirm(response: unknown) {
    setBusy(true);
    setError(null);
    const answer = await confirmEnrolment(api, offer.enrolment, response);
    setBusy(false);
    if (answer.ok) return onEnrolled(answer.body.codes);
    setError(answer.error);
    setTries((n) => n + 1);
  }

  return (
    <li className="flex list-none flex-col gap-3 pb-3">
      <p className="m-0 text-xs text-ink-soft">{t("auth.secondFactor.scan", "Scan this code with your authenticator app, or type the key into it. Then enter the 6-digit code it shows.")}</p>
      <div className="flex flex-wrap items-center gap-4">
        <QrCode value={offer.uri} label={t("auth.secondFactor.qr", "QR code for your authenticator app")} />
        <div className="flex min-w-0 flex-col gap-2">
          <span className="text-xs text-ink-soft">{t("auth.secondFactor.key", "Setup key")}</span>
          <code className="break-all font-mono text-sm text-ink">{offer.secret.match(/.{1,4}/g)?.join(" ")}</code>
          <CopyButton text={offer.secret} label={t("auth.secondFactor.copyKey", "Copy key")} />
        </div>
      </div>
      {error === "enrolment_expired" ? (
        <Button size="sm" className="self-start" onClick={onRestart}>
          {t("auth.secondFactor.restart", "Start again")}
        </Button>
      ) : (
        <AnswerForm key={tries} kind={offer.kind} challenge={null} action={t("auth.secondFactor.confirm", "Turn on")} busy={busy} refusedBy={error ? errorId : undefined} onAnswer={(response) => void confirm(response)} />
      )}
      {error && (
        <p id={errorId} role="alert" className="m-0 text-xs text-accent-error">
          {secondFactorRefusal(t, error)}
        </p>
      )}
      <Button variant="ghost" size="sm" className="self-start" disabled={busy} onClick={onCancel}>
        {t("auth.reauth.cancel", "Cancel")}
      </Button>
    </li>
  );
}

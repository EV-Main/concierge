import { useT } from "@evinvest/i18n/react";
import { Button } from "@evinvest/uikit";
import { useId, useState, type ReactNode } from "react";

import type { AuthError } from "../../../shared/api/auth-api";
import { useElement } from "../../../shared/element/element-context";
import { confirmEnrolment, type Offer } from "../api/second-factor-api";
import { AnswerForm } from "./answer-form";
import { CopyButton } from "./copy-button";
import { QrCode } from "./qr-code";
import { secondFactorRefusal } from "./refusal";

function Step({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <section className="flex gap-3">
      <span aria-hidden className="flex size-6 shrink-0 items-center justify-center rounded-full bg-ink/10 text-xs font-semibold text-ink">
        {n}
      </span>
      <div className="flex min-w-0 flex-1 flex-col gap-3">
        <h3 className="m-0 pt-0.5 text-sm font-semibold text-ink">{title}</h3>
        {children}
      </div>
    </section>
  );
}

/** The new factor's secret, shown this once, and its first code, which proves the app holds it. */
export function EnrolOffer({ offer, onEnrolled, onRestart }: { offer: Offer; onEnrolled: (codes: string[] | null) => void; onRestart: () => void }) {
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
    <div className="flex flex-col gap-6">
      <Step n={1} title={t("auth.secondFactor.enrol.scanTitle", "Scan the QR code")}>
        <p className="m-0 text-xs text-ink-soft">
          {t("auth.secondFactor.enrol.scan", "Open an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Authy or any other) and scan this code.")}
        </p>
        <QrCode value={offer.uri} label={t("auth.secondFactor.qr", "QR code for your authenticator app")} />
        {/* A phone cannot scan its own screen; the otpauth link hands the key to the app installed on it. */}
        <Button asChild size="sm" className="self-start no-underline pointer-fine:hidden">
          <a href={offer.uri}>{t("auth.secondFactor.enrol.openApp", "Open in authenticator app")}</a>
        </Button>
        <details className="group text-xs text-ink-soft">
          <summary className="cursor-pointer select-none hover:text-ink">{t("auth.secondFactor.enrol.cantScan", "Can't scan it? Enter a setup key instead")}</summary>
          <div className="flex flex-col gap-2 pt-2">
            <span>{t("auth.secondFactor.enrol.keyHint", "In the app, choose to enter a key, and type or paste this one. It is time-based.")}</span>
            <code className="font-mono text-sm break-all text-ink">{offer.secret.match(/.{1,4}/g)?.join(" ")}</code>
            <CopyButton text={offer.secret} label={t("auth.secondFactor.copyKey", "Copy key")} />
          </div>
        </details>
      </Step>
      <Step n={2} title={t("auth.secondFactor.enrol.codeTitle", "Enter the code from the app")}>
        <p className="m-0 text-xs text-ink-soft">{t("auth.secondFactor.enrol.code", "The app now shows a 6-digit code for EV Investment. It changes every 30 seconds.")}</p>
        {error === "enrolment_expired" ? (
          <Button size="sm" className="self-start" onClick={onRestart}>
            {t("auth.secondFactor.restart", "Start again")}
          </Button>
        ) : (
          <AnswerForm key={tries} kind={offer.kind} challenge={null} busy={busy} refusedBy={error ? errorId : undefined} onAnswer={(response) => void confirm(response)} />
        )}
        {error && (
          <p id={errorId} role="alert" className="m-0 text-xs text-accent-error">
            {secondFactorRefusal(t, error)}
          </p>
        )}
      </Step>
    </div>
  );
}

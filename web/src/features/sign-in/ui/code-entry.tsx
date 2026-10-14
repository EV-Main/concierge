import { useT } from "@evinvest/i18n/react";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@evinvest/uikit";
import { useEffect, useState, type ReactNode } from "react";

import { Heading, TextAction } from "./parts";

const CODE_LENGTH = 6;
const RESEND_SECS = 60;

export interface CodeEntryProps {
  title: string;
  description: string;
  busy: boolean;
  human: boolean;
  challenge?: ReactNode;
  onCode: (code: string) => void;
  onResend?: () => void;
  onBack: () => void;
  backLabel?: string;
  /** Offer "Send a new code" at once — nothing went out to wait for. */
  resendNow?: boolean;
}

/** Six digits, submitted as the last one lands; a resend waits out RESEND_SECS. */
export function CodeEntry({ title, description, busy, human, challenge, onCode, onResend, onBack, backLabel, resendNow = false }: CodeEntryProps) {
  const t = useT();
  const [code, setCode] = useState("");
  const [wait, setWait] = useState(resendNow ? 0 : RESEND_SECS);

  useEffect(() => {
    if (wait <= 0) return;
    const timer = setTimeout(() => setWait((s) => s - 1), 1000);
    return () => clearTimeout(timer);
  }, [wait]);

  function change(raw: string) {
    const digits = raw.replace(/\D/g, "").slice(0, CODE_LENGTH);
    setCode(digits);
    if (digits.length === CODE_LENGTH && !busy) onCode(digits);
  }

  return (
    <>
      <Heading title={title} description={description} />
      <div className="flex flex-col items-center gap-3">
        <InputOTP maxLength={CODE_LENGTH} value={code} onChange={change} disabled={busy} aria-label={t("auth.code.label", "Code")} autoFocus>
          <InputOTPGroup>
            {Array.from({ length: CODE_LENGTH }, (_, i) => (
              <InputOTPSlot key={i} index={i} className="h-12 w-11 text-base" />
            ))}
          </InputOTPGroup>
        </InputOTP>
        <p className="m-0 text-center text-(length:--sign-in-text-fine) text-ink-soft">{t("auth.code.checkSpam", "It can take a minute. Check your spam folder too.")}</p>
      </div>
      {onResend && wait <= 0 && challenge}
      <div className="flex items-center justify-between gap-3">
        <TextAction onClick={onBack}>{backLabel ?? t("auth.code.back", "Use a different email")}</TextAction>
        {onResend &&
          (wait > 0 ? (
            <span className="text-xs font-medium text-ink-soft">{t("auth.code.resendIn", "Send a new code in {seconds}s", { seconds: wait })}</span>
          ) : (
            <TextAction
              onClick={() => {
                if (!human || busy) return;
                setCode("");
                setWait(RESEND_SECS);
                onResend();
              }}
            >
              {t("auth.code.resend", "Send a new code")}
            </TextAction>
          ))}
      </div>
    </>
  );
}

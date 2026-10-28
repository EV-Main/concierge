import type { Translate } from "@evinvest/i18n";
import { useT } from "@evinvest/i18n/react";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@evinvest/uikit";
import { useEffect, useRef, useState, type ReactNode } from "react";

/** What a kind's form gets: the challenge it was sent (if its kind has one) and where its answer goes. */
interface AnswerFormProps {
  challenge: unknown;
  busy: boolean;
  /** The id of the refusal shown under the form, when the last answer was refused. */
  refusedBy: string | undefined;
  onAnswer: (response: unknown) => void;
}

const TOTP_DIGITS = 6;

/** Six digits, submitted as the last one lands, as the sign-in code is. */
function TotpForm({ busy, refusedBy, onAnswer }: AnswerFormProps) {
  const t = useT();
  const [code, setCode] = useState("");
  const input = useRef<HTMLInputElement>(null);

  // Not `autoFocus`: a form remounted after a refusal mounts disabled while the next ceremony opens.
  useEffect(() => {
    if (!busy) input.current?.focus();
  }, [busy]);

  function change(raw: string) {
    const digits = raw.replace(/\D/g, "").slice(0, TOTP_DIGITS);
    setCode(digits);
    if (digits.length === TOTP_DIGITS && !busy) onAnswer({ code: digits });
  }

  return (
    <InputOTP
      maxLength={TOTP_DIGITS}
      value={code}
      onChange={change}
      ref={input}
      disabled={busy}
      aria-label={t("auth.secondFactor.totp.code", "6-digit code from your authenticator app")}
      aria-invalid={refusedBy ? true : undefined}
      aria-describedby={refusedBy}
    >
      <InputOTPGroup>
        {Array.from({ length: TOTP_DIGITS }, (_, i) => (
          <InputOTPSlot key={i} index={i} className="h-12 w-11 text-base" />
        ))}
      </InputOTPGroup>
    </InputOTP>
  );
}

const FORMS = new Map<string, (props: AnswerFormProps) => ReactNode>([["totp", (props) => <TotpForm {...props} />]]);

export function AnswerForm({ kind, ...props }: AnswerFormProps & { kind: string }) {
  const t = useT();
  const form = FORMS.get(kind);
  if (!form) {
    return (
      <p role="alert" className="m-0 text-xs text-accent-error">
        {t("auth.secondFactor.unsupported", "This kind of second factor ({kind}) is not supported in this version. Reload the page, or use another one.", { kind })}
      </p>
    );
  }
  return form(props);
}

export function kindName(t: Translate, kind: string): string {
  return kind === "totp" ? t("auth.secondFactor.kind.totp", "Authenticator app") : kind;
}

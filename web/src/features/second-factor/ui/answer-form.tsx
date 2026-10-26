import type { Translate } from "@evinvest/i18n";
import { useT } from "@evinvest/i18n/react";
import { Button, Input } from "@evinvest/uikit";
import { useState, type FormEvent, type ReactNode } from "react";

/** What a kind's form gets: the challenge it was sent (if its kind has one) and where its answer goes. */
interface AnswerFormProps {
  challenge: unknown;
  action: string;
  busy: boolean;
  /** The id of the refusal shown under the form, when the last answer was refused. */
  refusedBy: string | undefined;
  onAnswer: (response: unknown) => void;
}

const TOTP_CODE = /^\d{6}$/;

function TotpForm({ action, busy, refusedBy, onAnswer }: AnswerFormProps) {
  const t = useT();
  const [code, setCode] = useState("");

  function submit(event: FormEvent) {
    event.preventDefault();
    onAnswer({ code: code.trim() });
  }

  return (
    <form className="flex flex-col gap-2" onSubmit={submit}>
      <Input
        inputMode="numeric"
        autoComplete="one-time-code"
        maxLength={6}
        aria-label={t("auth.secondFactor.totp.code", "6-digit code from your authenticator app")}
        placeholder={t("auth.code.label", "Code")}
        aria-invalid={refusedBy ? true : undefined}
        aria-describedby={refusedBy}
        value={code}
        onChange={(e) => setCode(e.target.value)}
      />
      <Button type="submit" size="sm" className="self-start" disabled={busy || !TOTP_CODE.test(code.trim())}>
        {action}
      </Button>
    </form>
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

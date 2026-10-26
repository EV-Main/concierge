import { useT } from "@evinvest/i18n/react";
import { Button, Skeleton, Tabs, TabsContent, TabsList, TabsTrigger } from "@evinvest/uikit";
import { useEffect, useId, useRef, useState } from "react";

import type { AuthError } from "../../../shared/api/auth-api";
import { useElement } from "../../../shared/element/element-context";
import { verifyFactor, verifyOptions, type VerifyCeremony } from "../api/second-factor-api";
import { AnswerForm, kindName } from "./answer-form";
import { secondFactorRefusal } from "./refusal";

/**
 * Prove one of the account's factors, which leaves the session free to change them for five
 * minutes. A ceremony is spent by one answer, right or wrong, so every refusal opens a new one.
 */
export function FactorStep({ onPassed, onCancel }: { onPassed: () => void; onCancel: () => void }) {
  const t = useT();
  const { api } = useElement();
  const [ceremony, setCeremony] = useState<VerifyCeremony | null>(null);
  const [factor, setFactor] = useState<string | undefined>(undefined);
  const [round, setRound] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<AuthError | null>(null);
  const titleId = useId();
  const errorId = useId();
  const panel = useRef<HTMLElement>(null);

  useEffect(() => {
    panel.current?.focus();
  }, []);

  useEffect(() => {
    let live = true;
    void verifyOptions(api).then((answer) => {
      if (!live) return;
      if (!answer.ok) return setError(answer.error);
      setCeremony(answer.body);
      setFactor((chosen) => (answer.body.factors.some((f) => f.id === chosen) ? chosen : answer.body.factors[0]?.id));
    });
    return () => {
      live = false;
    };
  }, [api, round]);

  async function answer(id: string, response: unknown) {
    if (!ceremony) return;
    setBusy(true);
    setError(null);
    const verified = await verifyFactor(api, ceremony.ceremony, id, response);
    setBusy(false);
    if (verified.ok) return onPassed();
    setError(verified.error);
    setCeremony(null);
    setRound((r) => r + 1);
  }

  const factors = ceremony?.factors ?? [];
  return (
    <li className="list-none pb-3">
      <section ref={panel} tabIndex={-1} aria-labelledby={titleId} className="flex flex-col gap-3 rounded-md border border-ink/10 p-3">
        <div className="flex flex-col gap-1">
          <h3 id={titleId} className="m-0 text-sm font-semibold">
            {t("auth.secondFactor.step.title", "Confirm with your second factor")}
          </h3>
          <p className="m-0 text-xs text-ink-soft">{t("auth.secondFactor.step.sub", "Changing your second factor needs a code from one you already have.")}</p>
        </div>
        {ceremony === null && error === null && <Skeleton className="h-16 w-full" />}
        {ceremony !== null && factor !== undefined && (
          <Tabs value={factor} onValueChange={setFactor}>
            {factors.length > 1 && (
              <TabsList aria-label={t("auth.secondFactor.step.which", "Which second factor")}>
                {factors.map((f) => (
                  <TabsTrigger key={f.id} value={f.id}>
                    {f.label ?? kindName(t, f.kind)}
                  </TabsTrigger>
                ))}
              </TabsList>
            )}
            {factors.map((f) => (
              <TabsContent key={f.id} value={f.id} className={factors.length > 1 ? "pt-3" : undefined}>
                <AnswerForm kind={f.kind} challenge={f.challenge} action={t("auth.reauth.confirm", "Confirm")} busy={busy} refusedBy={error ? errorId : undefined} onAnswer={(response) => void answer(f.id, response)} />
              </TabsContent>
            ))}
          </Tabs>
        )}
        {error && (
          <p id={errorId} role="alert" className="m-0 text-xs text-accent-error">
            {secondFactorRefusal(t, error)}
          </p>
        )}
        <Button variant="ghost" size="sm" className="self-start" onClick={onCancel}>
          {t("auth.reauth.cancel", "Cancel")}
        </Button>
      </section>
    </li>
  );
}

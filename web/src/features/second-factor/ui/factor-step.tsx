import { useT } from "@evinvest/i18n/react";
import { Button, Skeleton } from "@evinvest/uikit";
import { useCallback, useEffect, useId, useRef } from "react";

import { useElement } from "../../../shared/element/element-context";
import { verifyFactor, verifyOptions } from "../api/second-factor-api";
import { useFactorCeremony } from "../model/use-factor-ceremony";
import { FactorPicker } from "./factor-picker";
import { secondFactorRefusal } from "./refusal";

/** Prove one of the account's factors, which leaves the session free to change them for five minutes. */
export function FactorStep({ onPassed, onCancel }: { onPassed: () => void; onCancel: () => void }) {
  const t = useT();
  const { api } = useElement();
  const open = useCallback(() => verifyOptions(api), [api]);
  const step = useFactorCeremony(open, (ceremony, factor, response) => verifyFactor(api, ceremony, factor, response), onPassed);
  const titleId = useId();
  const errorId = useId();
  const panel = useRef<HTMLElement>(null);
  const error = step.unopened ?? step.refused;

  useEffect(() => {
    panel.current?.focus();
  }, []);

  return (
    <li className="list-none pb-3">
      <section ref={panel} tabIndex={-1} aria-labelledby={titleId} className="flex flex-col gap-3 rounded-md border border-ink/10 p-3">
        <div className="flex flex-col gap-1">
          <h3 id={titleId} className="m-0 text-sm font-semibold">
            {t("auth.secondFactor.step.title", "Confirm with your second factor")}
          </h3>
          <p className="m-0 text-xs text-ink-soft">{t("auth.secondFactor.step.sub", "Changing your second factor needs a code from one you already have.")}</p>
        </div>
        {step.ceremony === null && step.opening && <Skeleton className="h-16 w-full" />}
        {step.ceremony !== null && (
          <FactorPicker factors={step.ceremony.factors} action={t("auth.reauth.confirm", "Confirm")} busy={step.busy} refusedBy={error ? errorId : undefined} generation={step.generation} onAnswer={(factor, response) => void step.answer(factor, response)} />
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

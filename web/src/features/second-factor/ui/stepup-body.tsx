import { useT } from "@evinvest/i18n/react";
import { Button, DialogDescription, DialogHeader, DialogTitle, Skeleton } from "@evinvest/uikit";
import { useCallback, useId, type ComponentType } from "react";

import type { StepupProofDetail } from "../../../shared/element/events";
import { useElement } from "../../../shared/element/element-context";
import { stepupOptions, stepupVerify } from "../api/stepup-api";
import { useFactorCeremony } from "../model/use-factor-ceremony";
import type { StepupRequest } from "../model/stepup-request";
import type { ReauthSlotProps } from "./enrolment";
import { FactorPicker } from "./factor-picker";
import { isRetryable, secondFactorRefusal, stepupRefusal } from "./refusal";
import { StepupNoFactor } from "./stepup-no-factor";

export function StepupHeader({ titleId, descriptionId, authenticator }: { titleId: string; descriptionId: string; authenticator: boolean }) {
  const t = useT();
  return (
    <DialogHeader>
      <DialogTitle id={titleId}>{t("auth.stepup.title", "Confirm this operation")}</DialogTitle>
      <DialogDescription id={descriptionId}>
        {authenticator ? t("auth.stepup.subTotp", "Confirm this operation with your authenticator app.") : t("auth.stepup.sub", "Confirm this operation with your second factor.")}
      </DialogDescription>
    </DialogHeader>
  );
}

/** The ceremony for one operation: its factors, the answer, and the proof it ends in. */
export function StepupBody({ request, titleId, descriptionId, reauth, onProof }: { request: StepupRequest; titleId: string; descriptionId: string; reauth: ComponentType<ReauthSlotProps>; onProof: (proof: StepupProofDetail) => void }) {
  const t = useT();
  const { api } = useElement();
  const { intentHash, minAal } = request;
  const open = useCallback(() => stepupOptions(api, intentHash, minAal), [api, intentHash, minAal]);
  const step = useFactorCeremony(open, (ceremony, factor, response) => stepupVerify(api, ceremony, factor, response), onProof);
  const errorId = useId();
  const factors = step.ceremony?.factors ?? [];
  const authenticator = factors.length > 0 && factors.every((f) => f.kind === "totp");

  return (
    <>
      <StepupHeader titleId={titleId} descriptionId={descriptionId} authenticator={authenticator} />
      {step.unopened === "no_second_factor" ? (
        <StepupNoFactor reauth={reauth} onReady={step.retry} />
      ) : step.unopened ? (
        <div className="flex flex-col gap-2">
          <p role="alert" className="m-0 text-xs text-accent-error">
            {stepupRefusal(t, step.unopened)}
          </p>
          {isRetryable(step.unopened) && (
            <Button size="sm" variant="outline" className="self-start" onClick={step.retry}>
              {t("auth.stepup.retry", "Try again")}
            </Button>
          )}
        </div>
      ) : step.ceremony === null ? (
        <Skeleton className="h-16 w-full" />
      ) : (
        <FactorPicker factors={factors} busy={step.busy} refusedBy={step.refused ? errorId : undefined} generation={step.generation} onAnswer={(factor, response) => void step.answer(factor, response)} />
      )}
      {step.refused && !step.unopened && (
        <p id={errorId} role="alert" className="m-0 text-xs text-accent-error">
          {secondFactorRefusal(t, step.refused)}
        </p>
      )}
    </>
  );
}

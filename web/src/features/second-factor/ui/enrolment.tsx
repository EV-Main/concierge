import { useT } from "@evinvest/i18n/react";
import { useState, type ComponentType } from "react";

import { useElement } from "../../../shared/element/element-context";
import { startEnrolment, type Offer } from "../api/second-factor-api";
import { useGuardedAct } from "../model/use-guarded-act";
import { EnrolLabel } from "./enrol-label";
import { EnrolOffer } from "./enrol-offer";
import { FactorStep } from "./factor-step";
import { RecoveryCodes } from "./recovery-codes";
import { secondFactorRefusal } from "./refusal";

/** The sign-in confirmation step, composed in by the page: one feature does not import another. */
export interface ReauthSlotProps {
  sub: string;
  onConfirmed: () => void;
  onCancel: () => void;
}

type Stage = { kind: "label" } | { kind: "offer"; offer: Offer } | { kind: "codes"; codes: string[] };

/** Adding an authenticator app: a name, its secret and first code, then (for the first factor) the recovery codes. Rows of a list. */
export function Enrolment({ reauth: Reauth, onEnrolled, onCancel }: { reauth: ComponentType<ReauthSlotProps>; onEnrolled: () => void; onCancel: () => void }) {
  const t = useT();
  const { api } = useElement();
  const [stage, setStage] = useState<Stage>({ kind: "label" });
  const gate = useGuardedAct();
  const locked = gate.busy || gate.stage !== "idle";

  const start = (label: string) =>
    gate.start(async () => {
      const answer = await startEnrolment(api, label);
      if (answer.ok) setStage({ kind: "offer", offer: answer.body });
      return answer;
    });

  return (
    <>
      {stage.kind === "label" && <EnrolLabel busy={locked} onStart={(label) => void start(label)} onCancel={onCancel} />}
      {stage.kind === "offer" && <EnrolOffer offer={stage.offer} onEnrolled={(codes) => (codes ? setStage({ kind: "codes", codes }) : onEnrolled())} onRestart={() => setStage({ kind: "label" })} onCancel={onCancel} />}
      {stage.kind === "codes" && <RecoveryCodes codes={stage.codes} onSaved={onEnrolled} />}
      {gate.stage === "reauth" && <Reauth sub={t("auth.secondFactor.reauthSub", "You signed in a while ago. Confirm it is you to continue.")} onConfirmed={gate.passed} onCancel={gate.cancel} />}
      {gate.stage === "factor" && <FactorStep onPassed={gate.passed} onCancel={gate.cancel} />}
      {gate.error && (
        <li role="alert" className="list-none py-3 text-xs text-accent-error">
          {secondFactorRefusal(t, gate.error)}
        </li>
      )}
    </>
  );
}

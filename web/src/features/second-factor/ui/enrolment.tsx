import { useT } from "@evinvest/i18n/react";
import { Button, Skeleton } from "@evinvest/uikit";
import { useEffect, useState, type ComponentType } from "react";

import { useElement } from "../../../shared/element/element-context";
import { startEnrolment, type Offer } from "../api/second-factor-api";
import { useGuardedAct } from "../model/use-guarded-act";
import { kindName } from "./answer-form";
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

type Stage = { kind: "starting" } | { kind: "offer"; offer: Offer } | { kind: "codes"; codes: string[] };

/** Adding an authenticator app: its QR code and first code, then (for the first factor) the recovery codes. */
export function Enrolment({ reauth: Reauth, onEnrolled, onCancel }: { reauth: ComponentType<ReauthSlotProps>; onEnrolled: () => void; onCancel: () => void }) {
  const t = useT();
  const { api } = useElement();
  const [stage, setStage] = useState<Stage>({ kind: "starting" });
  const gate = useGuardedAct();
  // The label tells factors apart in lists; nobody is asked to name an app they hold one of.
  const label = kindName(t, "totp");

  const start = () =>
    gate.start(async () => {
      setStage({ kind: "starting" });
      const answer = await startEnrolment(api, label);
      if (answer.ok) setStage({ kind: "offer", offer: answer.body });
      return answer;
    });

  // eslint-disable-next-line react-hooks/exhaustive-deps -- once per opening: each start mints a new secret
  useEffect(() => void start(), []);

  const leave = () => {
    gate.cancel();
    onCancel();
  };

  if (stage.kind === "codes") return <RecoveryCodes codes={stage.codes} onSaved={onEnrolled} />;
  return (
    <div className="flex flex-col gap-4">
      {gate.stage === "reauth" ? (
        <ul className="m-0 list-none p-0">
          <Reauth sub={t("auth.secondFactor.reauthSub", "You signed in a while ago. Confirm it is you to continue.")} onConfirmed={gate.passed} onCancel={leave} />
        </ul>
      ) : gate.stage === "factor" ? (
        <ul className="m-0 list-none p-0">
          <FactorStep onPassed={gate.passed} onCancel={leave} />
        </ul>
      ) : gate.error ? (
        <p role="alert" className="m-0 text-xs text-accent-error">
          {secondFactorRefusal(t, gate.error)}
        </p>
      ) : stage.kind === "offer" ? (
        <EnrolOffer offer={stage.offer} onEnrolled={(codes) => (codes ? setStage({ kind: "codes", codes }) : onEnrolled())} onRestart={() => void start()} />
      ) : (
        <Skeleton className="h-64 w-full" />
      )}
      {gate.stage === "idle" && (
        <Button variant="ghost" size="sm" className="self-end" onClick={onCancel}>
          {t("auth.reauth.cancel", "Cancel")}
        </Button>
      )}
    </div>
  );
}

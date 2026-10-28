import { useT } from "@evinvest/i18n/react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@evinvest/uikit";
import { useState } from "react";

import type { FactorChallenge } from "../api/second-factor-api";
import { AnswerForm, kindName } from "./answer-form";

/** One tab per offered factor when there are several, each with its kind's answer form. */
export function FactorPicker({
  factors,
  busy,
  refusedBy,
  generation,
  onAnswer,
}: {
  factors: FactorChallenge[];
  busy: boolean;
  refusedBy: string | undefined;
  /** Bumped with each new ceremony, which clears the forms for the next answer. */
  generation: number;
  onAnswer: (factor: string, response: unknown) => void;
}) {
  const t = useT();
  const [chosen, setChosen] = useState(factors[0]?.id);
  const factor = factors.some((f) => f.id === chosen) ? chosen : factors[0]?.id;
  if (factor === undefined) return null;
  return (
    <Tabs value={factor} onValueChange={setChosen}>
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
          <AnswerForm key={generation} kind={f.kind} challenge={f.challenge} busy={busy} refusedBy={refusedBy} onAnswer={(response) => onAnswer(f.id, response)} />
        </TabsContent>
      ))}
    </Tabs>
  );
}

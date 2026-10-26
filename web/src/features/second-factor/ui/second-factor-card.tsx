import { useT } from "@evinvest/i18n/react";
import { dispatchSignOut } from "@evinvest/mfe";
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, ListRow, ListRows } from "@evinvest/uikit";
import { useEffect, useState, type ComponentType } from "react";

import { useElement } from "../../../shared/element/element-context";
import { readSecondFactors, recover, removeFactor, replaceRecoveryCodes, type Factor, type SecondFactors } from "../api/second-factor-api";
import { useGuardedAct } from "../model/use-guarded-act";
import { kindName } from "./answer-form";
import { Enrolment, type ReauthSlotProps } from "./enrolment";
import { FactorStep } from "./factor-step";
import { RecoverForm } from "./recover-form";
import { RecoveryCodes } from "./recovery-codes";
import { secondFactorRefusal } from "./refusal";
import { RemoveLast } from "./remove-last";
import { SessionEnded } from "./session-ended";

type Loaded = { kind: "loading" } | { kind: "off" } | { kind: "failed" } | { kind: "ready"; held: SecondFactors };

type Panel = null | { kind: "enrol" } | { kind: "codes"; codes: string[] } | { kind: "removeLast"; factor: string } | { kind: "recover" } | { kind: "ended" };

const dateOf = (secs: number) => new Date(secs * 1000).toLocaleDateString();

/**
 * The account's second factor, which the money plane asks for before a withdrawal. Platform
 * pages only. `reauth` is the sign-in confirmation step, composed in by the page; a plane
 * without the feature renders nothing.
 */
export function SecondFactorCard({ reauth: Reauth, onSessionEnded }: { reauth: ComponentType<ReauthSlotProps>; onSessionEnded: () => void }) {
  const t = useT();
  const { api, host } = useElement();
  const [loaded, setLoaded] = useState<Loaded>({ kind: "loading" });
  const [revision, setRevision] = useState(0);
  const [panel, setPanel] = useState<Panel>(null);
  const gate = useGuardedAct();
  const locked = gate.busy || gate.stage !== "idle";

  useEffect(() => {
    let live = true;
    void readSecondFactors(api).then((answer) => {
      if (!live) return;
      if (!answer.ok) return setLoaded({ kind: "failed" });
      setLoaded(answer.body.secondFactor ? { kind: "ready", held: answer.body.secondFactor } : { kind: "off" });
    });
    return () => {
      live = false;
    };
  }, [api, revision]);

  const reload = () => setRevision((r) => r + 1);
  const open = (next: Panel) => {
    gate.clear();
    setPanel(next);
  };

  if (loaded.kind === "loading" || loaded.kind === "off") return null;

  const remove = (factor: string) =>
    gate.start(async () => {
      const answer = await removeFactor(api, factor);
      if (answer.ok) {
        setPanel(null);
        reload();
      }
      return answer;
    });
  const newCodes = () =>
    gate.start(async () => {
      const answer = await replaceRecoveryCodes(api);
      if (answer.ok) {
        setPanel({ kind: "codes", codes: answer.body });
        reload();
      }
      return answer;
    });
  const spendCode = (code: string) =>
    gate.start(async () => {
      const answer = await recover(api, code);
      if (answer.ok) setPanel({ kind: "ended" });
      return answer;
    });
  const askRemove = (factor: Factor, held: SecondFactors) => {
    if (held.factors.length === 1) open({ kind: "removeLast", factor: factor.id });
    else void remove(factor.id);
  };

  const addButton = (
    <Button variant="outline" size="sm" disabled={locked || panel !== null} onClick={() => open({ kind: "enrol" })}>
      {t("auth.secondFactor.add", "Add authenticator app")}
    </Button>
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("auth.secondFactor.title", "Two-step verification")}</CardTitle>
        <CardDescription>{t("auth.secondFactor.sub", "A code from an app on your phone, asked for before money leaves your account")}</CardDescription>
      </CardHeader>
      <CardContent>
        <ListRows>
          {panel?.kind === "ended" ? (
            <SessionEnded
              onContinue={() => {
                dispatchSignOut(host);
                onSessionEnded();
              }}
            />
          ) : loaded.kind === "failed" ? (
            // Outside the panels below: recovery codes shown once must survive a failed re-read.
            <li className="list-none py-3 text-xs text-ink-soft">{t("account.unavailable", "This could not be loaded. Try again in a moment.")}</li>
          ) : loaded.held.factors.length === 0 ? (
            <ListRow label={kindName(t, "totp")} description={t("auth.secondFactor.none", "Withdrawals need a second factor. Add one before your first withdrawal.")}>
              {addButton}
            </ListRow>
          ) : (
            <>
              {loaded.held.factors.map((factor) => (
                <ListRow
                  key={factor.id}
                  label={factor.label}
                  description={[
                    kindName(t, factor.kind),
                    t("auth.secondFactor.added", "added {date}", { date: dateOf(factor.createdAt) }),
                    factor.lastUsedAt === null ? t("auth.secondFactor.neverUsed", "never used") : t("auth.secondFactor.lastUsed", "last used {date}", { date: dateOf(factor.lastUsedAt) }),
                  ].join(" · ")}
                >
                  <Button variant="outline" size="sm" disabled={locked || panel !== null} onClick={() => askRemove(factor, loaded.held)}>
                    {t("auth.passkeys.remove", "Remove")}
                  </Button>
                </ListRow>
              ))}
              <ListRow label={t("auth.secondFactor.another", "Another authenticator")}>{addButton}</ListRow>
              <ListRow
                label={t("auth.secondFactor.codes.row", "Recovery codes")}
                description={t("auth.secondFactor.codes.left", "{n} left · a new set replaces the old one", { n: loaded.held.recoveryCodesLeft })}
              >
                <Button variant="outline" size="sm" disabled={locked || panel !== null} onClick={() => void newCodes()}>
                  {t("auth.secondFactor.codes.new", "New codes")}
                </Button>
              </ListRow>
              <ListRow label={t("auth.secondFactor.lost", "Lost your authenticator?")}>
                <Button variant="outline" size="sm" disabled={locked || panel !== null} onClick={() => open({ kind: "recover" })}>
                  {t("auth.secondFactor.recover.open", "Use a recovery code")}
                </Button>
              </ListRow>
            </>
          )}
          {panel?.kind === "enrol" && (
            <Enrolment
              reauth={Reauth}
              onEnrolled={() => {
                setPanel(null);
                reload();
              }}
              onCancel={() => setPanel(null)}
            />
          )}
          {panel?.kind === "codes" && <RecoveryCodes codes={panel.codes} onSaved={() => setPanel(null)} />}
          {panel?.kind === "removeLast" && <RemoveLast busy={locked} onRemove={() => void remove(panel.factor)} onCancel={() => setPanel(null)} />}
          {panel?.kind === "recover" && <RecoverForm busy={locked} onRecover={(code) => void spendCode(code)} onCancel={() => setPanel(null)} />}
          {gate.stage === "reauth" && <Reauth sub={t("auth.secondFactor.reauthSub", "You signed in a while ago. Confirm it is you to continue.")} onConfirmed={gate.passed} onCancel={gate.cancel} />}
          {gate.stage === "factor" && <FactorStep onPassed={gate.passed} onCancel={gate.cancel} />}
          {gate.error && (
            <li role="alert" className="list-none py-3 text-xs text-accent-error">
              {secondFactorRefusal(t, gate.error)}
            </li>
          )}
        </ListRows>
      </CardContent>
    </Card>
  );
}

import { useLocale, useT } from "@evinvest/i18n/react";
import { dispatchSignOut } from "@evinvest/mfe";
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Dialog, DialogContent, DialogHeader, DialogTitle, ListRow, ListRows } from "@evinvest/uikit";
import { useEffect, useId, useState, type ComponentType } from "react";

import { useElement } from "../../../shared/element/element-context";
import { SECOND_FACTORS_CHANGED } from "../../../shared/element/events";
import { readSecondFactors, recover, removeFactor, replaceRecoveryCodes, type Factor, type SecondFactors } from "../api/second-factor-api";
import { useGuardedAct } from "../model/use-guarded-act";
import { kindName } from "./answer-form";
import { ConfirmAct } from "./confirm-act";
import { Enrolment, type ReauthSlotProps } from "./enrolment";
import { FactorStep } from "./factor-step";
import { RecoverForm } from "./recover-form";
import { RecoveryCodes } from "./recovery-codes";
import { secondFactorRefusal } from "./refusal";
import { SessionEnded } from "./session-ended";

type Loaded = { kind: "loading" } | { kind: "off" } | { kind: "failed" } | { kind: "ready"; held: SecondFactors };

type Panel = null | { kind: "enrol" } | { kind: "codes"; codes: string[] } | { kind: "remove"; factor: Factor; last: boolean } | { kind: "newCodes" } | { kind: "recover" } | { kind: "ended" };

/**
 * The account's second factor, which the money plane asks for before a withdrawal. Platform
 * pages only. `reauth` is the sign-in confirmation step, composed in by the page; a plane
 * without the feature renders nothing.
 */
export function SecondFactorCard({ reauth: Reauth, onSessionEnded }: { reauth: ComponentType<ReauthSlotProps>; onSessionEnded: () => void }) {
  const t = useT();
  const locale = useLocale();
  const { api, host } = useElement();
  const [loaded, setLoaded] = useState<Loaded>({ kind: "loading" });
  const [revision, setRevision] = useState(0);
  const [panel, setPanel] = useState<Panel>(null);
  const gate = useGuardedAct();
  const enrolTitle = useId();
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
  useEffect(() => {
    const reread = () => setRevision((r) => r + 1);
    document.addEventListener(SECOND_FACTORS_CHANGED, reread);
    return () => document.removeEventListener(SECOND_FACTORS_CHANGED, reread);
  }, []);
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
  const dateOf = (secs: number) => new Date(secs * 1000).toLocaleDateString(locale);

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
                    ...(factor.label === kindName(t, factor.kind) ? [] : [kindName(t, factor.kind)]),
                    t("auth.secondFactor.added", "added {date}", { date: dateOf(factor.createdAt) }),
                    factor.lastUsedAt === null ? t("auth.secondFactor.neverUsed", "never used") : t("auth.secondFactor.lastUsed", "last used {date}", { date: dateOf(factor.lastUsedAt) }),
                  ].join(" · ")}
                >
                  <Button variant="outline" size="sm" disabled={locked || panel !== null} onClick={() => open({ kind: "remove", factor, last: loaded.held.factors.length === 1 })}>
                    {t("auth.passkeys.remove", "Remove")}
                  </Button>
                </ListRow>
              ))}
              <ListRow label={t("auth.secondFactor.another", "Another authenticator")}>{addButton}</ListRow>
              <ListRow
                label={t("auth.secondFactor.codes.row", "Recovery codes")}
                description={t("auth.secondFactor.codes.left", "{n} left · a new set replaces the old one", { n: loaded.held.recoveryCodesLeft })}
              >
                <Button variant="outline" size="sm" disabled={locked || panel !== null} onClick={() => open({ kind: "newCodes" })}>
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
          {panel?.kind === "codes" && (
            <li className="mb-3 list-none rounded-md border border-ink/10 p-3">
              <RecoveryCodes codes={panel.codes} onSaved={() => setPanel(null)} />
            </li>
          )}
          {panel?.kind === "remove" && (
            <ConfirmAct
              message={
                panel.last
                  ? t("auth.secondFactor.removeLast", "This is your only second factor. Without one, withdrawals are refused until you add a new one. Your recovery codes stop working too.")
                  : t("auth.secondFactor.removeOne", "Remove {label}? Its codes stop working at once.", { label: panel.factor.label })
              }
              action={panel.last ? t("auth.secondFactor.removeAnyway", "Remove anyway") : t("auth.passkeys.remove", "Remove")}
              busy={locked}
              onConfirm={() => void remove(panel.factor.id)}
              onCancel={() => setPanel(null)}
            />
          )}
          {panel?.kind === "newCodes" && (
            <ConfirmAct
              message={t("auth.secondFactor.codes.newConfirm", "Your current recovery codes stop working as soon as the new set is made.")}
              action={t("auth.secondFactor.codes.new", "New codes")}
              busy={locked}
              onConfirm={() => void newCodes()}
              onCancel={() => setPanel(null)}
            />
          )}
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
      {/* Closed by its own buttons only: a stray click outside must not throw away a scanned secret or unsaved recovery codes. */}
      <Dialog open={panel?.kind === "enrol"}>
        <DialogContent showCloseButton={false} aria-labelledby={enrolTitle} aria-describedby={undefined} className="max-w-[min(28rem,calc(100%-2rem))] gap-4 sm:max-w-md">
          <DialogHeader>
            <DialogTitle id={enrolTitle}>{t("auth.secondFactor.enrol.title", "Set up an authenticator app")}</DialogTitle>
          </DialogHeader>
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
        </DialogContent>
      </Dialog>
    </Card>
  );
}

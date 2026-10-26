import { useT } from "@evinvest/i18n/react";
import { Skeleton } from "@evinvest/uikit";

import { useElement } from "../../../shared/element/element-context";
import { useReauthMethods } from "../model/use-reauth-methods";
import { ReauthMethods } from "./reauth-methods";
import { reauthRefusal } from "./refusal";

/** The ways to confirm, for a caller that does not already hold the account's methods. */
export function ReauthBody({ onConfirmed }: { onConfirmed: () => void }) {
  const t = useT();
  const { api } = useElement();
  const choice = useReauthMethods(api);
  if (choice.kind === "loading") return <Skeleton className="h-24 w-full" />;
  if (choice.kind === "failed") {
    return (
      <p role="alert" className="m-0 text-xs text-accent-error">
        {reauthRefusal(t, choice.error)}
      </p>
    );
  }
  return <ReauthMethods methods={choice.methods} onConfirmed={onConfirmed} />;
}

import { useT } from "@evinvest/i18n/react";
import { Button, Dialog, DialogContent, DialogFooter } from "@evinvest/uikit";
import { useId, useRef, type ComponentType } from "react";

import type { StepupProofDetail } from "../../../shared/element/events";
import type { StepupRequest } from "../model/stepup-request";
import type { ReauthSlotProps } from "./enrolment";
import { stepupRefusal } from "./refusal";
import { StepupBody, StepupHeader } from "./stepup-body";

interface StepupDialogProps {
  open: boolean;
  /** Null when the page's attributes do not name an operation and a level: nothing is asked. */
  request: StepupRequest | null;
  reauth: ComponentType<ReauthSlotProps>;
  onProof: (proof: StepupProofDetail) => void;
  onDismiss: () => void;
}

/**
 * "Confirm this operation" over a host page. The element remounts it on every opening, so
 * each one opens its own ceremony; the host never learns which kinds of factor exist.
 */
export function StepupDialog({ open, request, reauth, onProof: proved, onDismiss: dismiss }: StepupDialogProps) {
  const t = useT();
  const titleId = useId();
  const descriptionId = useId();
  // One outcome per opening, as in ReauthDialog: the kit's Dialog reports one backdrop
  // click twice, and a dismissal racing a late proof must not tell the host both.
  const reported = useRef(false);
  const once =
    <A extends unknown[]>(report: (...args: A) => void) =>
    (...args: A) => {
      if (reported.current) return;
      reported.current = true;
      report(...args);
    };
  const onProof = once(proved);
  const onDismiss = once(dismiss);

  return (
    <Dialog open={open} onOpenChange={(next) => !next && onDismiss()}>
      <DialogContent aria-labelledby={titleId} aria-describedby={descriptionId} className="max-w-[min(25rem,calc(100%-2rem))] gap-4 sm:max-w-100">
        {request ? (
          <StepupBody request={request} titleId={titleId} descriptionId={descriptionId} reauth={reauth} onProof={onProof} />
        ) : (
          <>
            <StepupHeader titleId={titleId} descriptionId={descriptionId} authenticator={false} />
            <p role="alert" className="m-0 text-xs text-accent-error">
              {stepupRefusal(t, "invalid_request")}
            </p>
          </>
        )}
        <DialogFooter>
          <Button variant="ghost" size="sm" onClick={onDismiss}>
            {t("auth.reauth.cancel", "Cancel")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

import { useT } from "@evinvest/i18n/react";
import { Button, Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@evinvest/uikit";
import { useId, useRef } from "react";

import { useElement } from "../../../shared/element/element-context";
import { DialogCloseButton } from "../../../shared/ui/dialog-close";
import { ReauthBody } from "./reauth-body";
import { reauthRefusal } from "./refusal";

export interface ReauthDialogProps {
  open: boolean;
  /** The plane accepted the proof and has already re-set `ev_access` with a fresh `auth_time`. */
  onConfirmed: () => void;
  onDismiss: () => void;
}

/**
 * "Confirm it is you" over a host page, for an act the host's backend refused as
 * `reauth_required`. The element remounts it on every opening, so each one asks afresh.
 */
export function ReauthDialog({ open, onConfirmed: confirmed, onDismiss: dismiss }: ReauthDialogProps) {
  const t = useT();
  const { platform } = useElement();
  const titleId = useId();
  const descriptionId = useId();
  // One outcome per opening: the kit's Dialog reports one backdrop click twice, and a
  // dismissal racing a late success must not tell the host both.
  const reported = useRef(false);
  const once = (report: () => void) => () => {
    if (reported.current) return;
    reported.current = true;
    report();
  };
  const onConfirmed = once(confirmed);
  const onDismiss = once(dismiss);

  return (
    <Dialog open={open} onOpenChange={(next) => !next && onDismiss()}>
      <DialogContent showCloseButton={false} aria-labelledby={titleId} aria-describedby={descriptionId} className="max-w-[min(25rem,calc(100%-2rem))] gap-4 sm:max-w-100">
        <DialogHeader>
          <DialogTitle id={titleId}>{t("auth.reauth.title", "Confirm it is you")}</DialogTitle>
          <DialogDescription id={descriptionId}>{t("auth.reauth.dialogSub", "This action needs a fresh confirmation. Confirm again to continue.")}</DialogDescription>
        </DialogHeader>
        {/* The reauth routes answer the platform origin only; elsewhere a request would only come back `origin`. */}
        {platform ? (
          <ReauthBody onConfirmed={onConfirmed} />
        ) : (
          <p role="alert" className="m-0 text-xs text-accent-error">
            {reauthRefusal(t, "origin")}
          </p>
        )}
        <DialogFooter>
          <Button variant="ghost" size="sm" onClick={onDismiss}>
            {t("auth.reauth.cancel", "Cancel")}
          </Button>
        </DialogFooter>
        <DialogCloseButton />
      </DialogContent>
    </Dialog>
  );
}

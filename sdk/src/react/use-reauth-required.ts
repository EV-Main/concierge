import { useCallback, useEffect, useRef, useState } from 'react';

export interface ReauthRequired {
  open: boolean;
  /**
   * Open the reauth dialog. Resolves true once the user has confirmed (the
   * fresh `ev_access` is set), false when they dismiss it or the host unmounts.
   * Calls while the dialog is open share its one answer.
   */
  requireReauth: () => Promise<boolean>;
  /** Spread into `<ReauthDialog scriptUrl={…} {...dialogProps} />`. */
  dialogProps: {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onReauthenticated: () => void;
  };
}

interface Pending {
  answer: Promise<boolean>;
  settle: (confirmed: boolean) => void;
}

/**
 * "This act needs a fresh confirmation": a host whose backend answered
 * `reauth_required` awaits `requireReauth()` and, on true, retries the act
 * once. Whether an answer is `reauth_required` is the host's backend's
 * vocabulary, so the host decides that, not this hook.
 */
export function useReauthRequired(): ReauthRequired {
  const [open, setOpen] = useState(false);
  const pending = useRef<Pending | null>(null);

  const settle = useCallback((confirmed: boolean) => {
    const current = pending.current;
    pending.current = null;
    current?.settle(confirmed);
  }, []);

  // A caller awaiting a dialog that will never answer would hang its act for good.
  useEffect(() => () => settle(false), [settle]);

  const requireReauth = useCallback(() => {
    if (pending.current) return pending.current.answer;
    let resolve: (confirmed: boolean) => void = () => {};
    const answer = new Promise<boolean>((r) => {
      resolve = r;
    });
    pending.current = { answer, settle: resolve };
    setOpen(true);
    return answer;
  }, []);

  const onOpenChange = useCallback(
    (next: boolean) => {
      setOpen(next);
      // After a confirmation `settle(true)` has already run, so this is a no-op then.
      if (!next) settle(false);
    },
    [settle],
  );
  const onReauthenticated = useCallback(() => settle(true), [settle]);

  return { open, requireReauth, dialogProps: { open, onOpenChange, onReauthenticated } };
}

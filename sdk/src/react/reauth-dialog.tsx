import { API_VERSION } from '@evinvest/mfe';
import { RemoteElement } from '@evinvest/mfe/react';
import { useState, type ReactNode } from 'react';

import { CLOSE_EVENT, REAUTH_TAG, REAUTHENTICATED_EVENT } from '../index';

export interface ReauthDialogProps {
  /** Bundle URL from the concierge registry (`conciergeEntry(entries, 'reauth')`). */
  scriptUrl: string;
  open: boolean;
  /** Called with false when the user dismisses the dialog, or once they have confirmed. */
  onOpenChange: (open: boolean) => void;
  /**
   * The user confirmed and `ev_access` now carries a fresh `auth_time`. Retry
   * the refused act ONCE; a second `reauth_required` is an error, not a reason
   * to ask again. Runs before `onOpenChange(false)`.
   */
  onReauthenticated: () => void;
  minApiVersion?: number;
  /**
   * Shown while the dialog is open and the bundle loads, and for good if it
   * fails. Hidden while closed.
   */
  fallback?: ReactNode;
}

/**
 * The concierge re-authentication dialog, for a host on evinvest.ltd whose
 * backend answered `reauth_required`. The element draws its own backdrop and
 * traps focus; the host only says whether it is open. Mounted on the first open
 * and kept, as `SignInDialog` is.
 */
export function ReauthDialog({ scriptUrl, open, onOpenChange, onReauthenticated, minApiVersion = API_VERSION, fallback = null }: ReauthDialogProps) {
  const [armed, setArmed] = useState(open);
  // Latched during render, not in an effect: the first open mounts in the same commit.
  if (open && !armed) setArmed(true);
  if (!armed) return null;

  return (
    <RemoteElement
      tag={REAUTH_TAG}
      scriptUrl={scriptUrl}
      minApiVersion={minApiVersion}
      attributes={{ open }}
      events={{
        // Confirmed first, closed second: `useReauthRequired` reads a close with no
        // confirmation before it as a dismissal.
        [REAUTHENTICATED_EVENT]: () => {
          onReauthenticated();
          onOpenChange(false);
        },
        [CLOSE_EVENT]: () => onOpenChange(false),
      }}
      fallback={open ? fallback : null}
    />
  );
}

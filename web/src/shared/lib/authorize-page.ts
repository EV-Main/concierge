// What the two platform pages that authorize sends a browser to (`reauth.html`,
// `sign-in.html`; `runner/src/web/authorize.rs`) share: the one accepted `return_to`, the
// app's name from the registry, and a way out that is taken once. Each page then mounts
// its own element and decides only which address it leaves for.
import { fetchClientName } from "../api/client-name";
import { authorizeReturnTo } from "./authorize-return";

// Beside the pages' own directory (`/api/auth/mfe/` → `/api/auth/clients/`), so it also
// holds where concierge is reached without the conductor's `/api` prefix.
const CLIENTS_DIR = "../clients/";

export type AuthorizePage =
  /** `return_to` failed the check, or concierge would not serve its client at authorize. */
  | { kind: "refused" }
  /** `appName` is null when the registry has no name or could not be asked. */
  | { kind: "ready"; returnTo: string; appName: string | null };

export async function startAuthorizePage(): Promise<AuthorizePage> {
  const target = authorizeReturnTo(new URLSearchParams(location.search).get("return_to"), location.origin);
  if (!target) return { kind: "refused" };
  // The name comes from the registry by the client id inside the checked `return_to`,
  // never from the query, so a link cannot dress the page up as another app.
  const client = await fetchClientName(new URL(CLIENTS_DIR, location.href), target.clientId);
  if (client.kind === "unknown") return { kind: "refused" };
  return { kind: "ready", returnTo: target.href, appName: client.kind === "named" ? client.name : null };
}

/**
 * A `location.replace` that runs on the first call only. The elements report one outcome
 * per opening; the guard covers a late second one anyway, because a second `replace`
 * would cancel the first navigation for nothing.
 */
export function leaveOnce(): (href: string) => void {
  let leaving = false;
  return (href) => {
    if (leaving) return;
    leaving = true;
    location.replace(href);
  };
}

import { createContext, useContext, type ReactNode } from "react";

import type { AuthApi } from "../api/auth-api";

export interface ElementEnv {
  /** The custom element itself: events are dispatched from it, overlays portal into it. */
  host: HTMLElement;
  api: AuthApi;
  /** This page is the platform's own origin, the only one that may act on a session. */
  platform: boolean;
}

const ElementContext = createContext<ElementEnv | null>(null);

export function ElementProvider({ env, children }: { env: ElementEnv; children: ReactNode }) {
  return <ElementContext.Provider value={env}>{children}</ElementContext.Provider>;
}

export function useElement(): ElementEnv {
  const env = useContext(ElementContext);
  if (!env) throw new Error("useElement outside an element root");
  return env;
}

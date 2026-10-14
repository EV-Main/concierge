import { localeOfElement } from "@evinvest/i18n";
import { I18nProvider } from "@evinvest/i18n/react";
import { API_VERSION } from "@evinvest/mfe";
import { PortalProvider } from "@evinvest/uikit";
import { useLayoutEffect, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";

import { authApi, type AuthApi } from "../api/auth-api";
import { apiOriginOf, isPlatformPage, ORIGIN_ATTR } from "../config/origin";
import { messagesFor } from "./catalogue";
import { ElementProvider } from "./element-context";
import { attachStylesheet } from "./stylesheet";

export interface ElementSpec {
  tag: string;
  css: string;
  /** Attributes whose change re-renders the element (`data-origin` is always observed). */
  observed: readonly string[];
  render: (host: HTMLElement) => ReactNode;
  /** Before the first render of each connection. */
  onConnect?: (host: HTMLElement) => void;
}

/**
 * Sets `[data-ready]` in the commit that first paints the element — a layout effect, not
 * `flushSync` in `connectedCallback`, because a React host connects the element during its
 * own commit, where a nested synchronous render is refused.
 */
function ReadyMark({ host }: { host: HTMLElement }) {
  useLayoutEffect(() => {
    host.toggleAttribute("data-ready", true);
  }, [host]);
  return null;
}

const apis = new Map<string, AuthApi>();
function apiFor(origin: string): AuthApi {
  let api = apis.get(origin);
  if (!api) {
    api = authApi(origin);
    apis.set(origin, api);
  }
  return api;
}

/**
 * Registers `spec.tag` as a self-rendering element: React in its LIGHT DOM (host tokens and
 * fonts cascade in), overlays portaled into the element so the scoped sheet reaches them,
 * the locale read off the nearest `[lang]`, and `[data-ready]` set once the first render
 * has committed — the signal hosts wait on.
 */
export function defineElement(spec: ElementSpec): void {
  class RemoteElement extends HTMLElement {
    static apiVersion = API_VERSION;
    static observedAttributes = [ORIGIN_ATTR, ...spec.observed];
    #root: Root | undefined;

    connectedCallback() {
      // React renders into the light DOM, so a host's PostHog autocapture and session
      // replay would otherwise record the email, name and form input shown here.
      this.classList.add("ph-no-capture");
      attachStylesheet(spec.tag, spec.css);
      spec.onConnect?.(this);
      this.#root = createRoot(this);
      this.#render();
    }

    attributeChangedCallback() {
      // Fires before connect for attributes set on a detached element; the connect renders them.
      if (this.#root) this.#render();
    }

    disconnectedCallback() {
      this.#root?.unmount();
      this.#root = undefined;
      this.removeAttribute("data-ready");
    }

    #render() {
      const locale = localeOfElement(this);
      const api = apiFor(apiOriginOf(this));
      this.#root?.render(
        <I18nProvider locale={locale} messages={messagesFor(locale)}>
          <ElementProvider env={{ host: this, api, platform: isPlatformPage(api.origin) }}>
            <PortalProvider container={this}>
              {spec.render(this)}
              <ReadyMark host={this} />
            </PortalProvider>
          </ElementProvider>
        </I18nProvider>,
      );
    }
  }
  if (!customElements.get(spec.tag)) customElements.define(spec.tag, RemoteElement);
}

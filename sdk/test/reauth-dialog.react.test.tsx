// ReauthDialog mounts the concierge reauth element on the first open and keeps
// it. A confirmation reaches the host before the close, so the host can tell a
// confirmed close from a dismissal. The tag is defined up front, so the loader
// resolves without a network.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { ReauthDialog } from '../src/react/index';

const TAG = 'mfe-concierge-reauth';
const SCRIPT = '/auth/mfe/reauth.js';

let container: HTMLDivElement;
let root: Root;

beforeAll(() => {
  customElements.define(
    TAG,
    class extends HTMLElement {
      static apiVersion = 2;
    },
  );
});

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

async function render(node: ReactNode): Promise<void> {
  await act(async () => {
    root.render(node);
  });
}

function dialog(open: boolean, handlers: { onOpenChange?: (open: boolean) => void; onReauthenticated?: () => void } = {}) {
  return (
    <ReauthDialog
      scriptUrl={SCRIPT}
      open={open}
      onOpenChange={handlers.onOpenChange ?? (() => {})}
      onReauthenticated={handlers.onReauthenticated ?? (() => {})}
    />
  );
}

function element(): HTMLElement | null {
  return container.querySelector(TAG);
}

describe('ReauthDialog mounting', () => {
  it('should_render_nothing_while_open_has_never_been_true', async () => {
    await render(dialog(false));
    await render(dialog(false));

    expect(container.childElementCount).toBe(0);
    expect(document.querySelector(`script[data-mfe="${TAG}"]`)).toBeNull();
  });

  it('should_mount_the_element_with_the_open_attribute_on_the_first_open', async () => {
    await render(dialog(false));

    await render(dialog(true));

    expect(element()?.hasAttribute('open')).toBe(true);
  });

  it('should_keep_the_same_element_after_closing_and_drop_the_open_attribute', async () => {
    await render(dialog(true));
    const mounted = element();

    await render(dialog(false));

    expect(element()).toBe(mounted);
    expect(element()?.hasAttribute('open')).toBe(false);
  });
});

describe('ReauthDialog events', () => {
  it('should_report_the_confirmation_before_asking_to_close', async () => {
    const calls: string[] = [];
    await render(
      dialog(true, {
        onOpenChange: open => calls.push(`onOpenChange(${open})`),
        onReauthenticated: () => calls.push('onReauthenticated'),
      }),
    );

    element()?.dispatchEvent(new CustomEvent('ev:reauthenticated', { bubbles: true, composed: true, detail: null }));

    expect(calls).toEqual(['onReauthenticated', 'onOpenChange(false)']);
  });

  it('should_only_ask_to_close_on_ev_close', async () => {
    const onOpenChange = vi.fn<(open: boolean) => void>();
    const onReauthenticated = vi.fn<() => void>();
    await render(dialog(true, { onOpenChange, onReauthenticated }));

    element()?.dispatchEvent(new CustomEvent('ev:close', { bubbles: true, composed: true, detail: null }));

    expect(onOpenChange).toHaveBeenCalledTimes(1);
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(onReauthenticated).not.toHaveBeenCalled();
  });
});

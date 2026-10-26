// StepupDialog mounts the concierge step-up element on the first open and keeps it,
// with the operation in its attributes. A proof reaches the host before the close, so
// the host can tell a proved close from a dismissal. The tag is defined up front, so
// the loader resolves without a network.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import type { StepupProofDetail } from '../src/index';
import { StepupDialog, type StepupRequest } from '../src/react/index';

const TAG = 'mfe-concierge-stepup';
const SCRIPT = '/auth/mfe/stepup.js';
const REQUEST: StepupRequest = { intentHash: 'ab'.repeat(32), minAal: 2 };

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

function dialog(open: boolean, handlers: { onOpenChange?: (open: boolean) => void; onProof?: (detail: StepupProofDetail) => void } = {}, request: StepupRequest | null = REQUEST) {
  return <StepupDialog scriptUrl={SCRIPT} open={open} request={request} onOpenChange={handlers.onOpenChange ?? (() => {})} onProof={handlers.onProof ?? (() => {})} />;
}

function element(): HTMLElement | null {
  return container.querySelector(TAG);
}

function fire(type: string, detail: unknown): void {
  element()?.dispatchEvent(new CustomEvent(type, { bubbles: true, composed: true, detail }));
}

describe('StepupDialog mounting', () => {
  it('should_render_nothing_while_open_has_never_been_true', async () => {
    await render(dialog(false, {}, null));

    expect(container.childElementCount).toBe(0);
  });

  it('should_mount_the_element_with_the_operation_on_the_first_open', async () => {
    await render(dialog(true));

    expect(element()?.hasAttribute('open')).toBe(true);
    expect(element()?.getAttribute('intent-hash')).toBe(REQUEST.intentHash);
    expect(element()?.getAttribute('min-aal')).toBe('2');
  });

  it('should_keep_the_same_element_after_closing_and_drop_the_open_attribute', async () => {
    await render(dialog(true));
    const mounted = element();

    await render(dialog(false));

    expect(element()).toBe(mounted);
    expect(element()?.hasAttribute('open')).toBe(false);
  });
});

describe('StepupDialog events', () => {
  it('should_report_the_proof_before_asking_to_close', async () => {
    const calls: string[] = [];
    await render(
      dialog(true, {
        onOpenChange: open => calls.push(`onOpenChange(${open})`),
        onProof: detail => calls.push(`onProof(${detail.proof},${detail.expiresAt})`),
      }),
    );

    fire('ev:stepup-proof', { proof: 'jwt', expiresAt: 1700000000 });

    expect(calls).toEqual(['onProof(jwt,1700000000)', 'onOpenChange(false)']);
  });

  it('should_only_ask_to_close_on_ev_close', async () => {
    const onOpenChange = vi.fn<(open: boolean) => void>();
    const onProof = vi.fn<(detail: StepupProofDetail) => void>();
    await render(dialog(true, { onOpenChange, onProof }));

    fire('ev:close', null);

    expect(onOpenChange).toHaveBeenCalledTimes(1);
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(onProof).not.toHaveBeenCalled();
  });
});

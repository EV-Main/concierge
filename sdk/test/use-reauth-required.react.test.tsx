// useReauthRequired hands the host one promise per opening of the dialog: true
// after a confirmation, false after any other close or an unmount.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { useReauthRequired, type ReauthRequired } from '../src/react/index';

let container: HTMLDivElement;
let root: Root;
let latest: ReauthRequired | null = null;

function Probe() {
  latest = useReauthRequired();
  return null;
}

beforeEach(async () => {
  latest = null;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root.render(<Probe />);
  });
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

interface Answer {
  promise: Promise<boolean>;
}

function current(): ReauthRequired {
  if (latest === null) throw new Error('Probe has not rendered');
  return latest;
}

// Starts a request inside act so the open state is flushed. The promise is boxed:
// an async function would otherwise await it and hide the pending state.
async function request(): Promise<Answer> {
  let pending: Promise<boolean> | undefined;
  await act(async () => {
    pending = current().requireReauth();
  });
  if (pending === undefined) throw new Error('requireReauth did not run');
  return { promise: pending };
}

describe('useReauthRequired', () => {
  it('should_start_closed', () => {
    expect(current().open).toBe(false);
    expect(current().dialogProps.open).toBe(false);
  });

  it('should_open_on_requireReauth', async () => {
    await request();

    expect(current().open).toBe(true);
    expect(current().dialogProps.open).toBe(true);
  });

  it('should_resolve_true_when_the_user_confirms', async () => {
    const answer = await request();

    await act(async () => {
      current().dialogProps.onReauthenticated();
      current().dialogProps.onOpenChange(false);
    });

    await expect(answer.promise).resolves.toBe(true);
    expect(current().open).toBe(false);
  });

  it('should_resolve_false_when_the_user_closes_the_dialog', async () => {
    const answer = await request();

    await act(async () => current().dialogProps.onOpenChange(false));

    await expect(answer.promise).resolves.toBe(false);
    expect(current().open).toBe(false);
  });

  it('should_share_one_promise_between_calls_while_open', async () => {
    const first = await request();
    const second = await request();

    expect(second.promise).toBe(first.promise);

    await act(async () => {
      current().dialogProps.onReauthenticated();
      current().dialogProps.onOpenChange(false);
    });

    await expect(Promise.all([first.promise, second.promise])).resolves.toEqual([true, true]);
  });

  it('should_resolve_false_when_the_host_unmounts_while_open', async () => {
    const answer = await request();

    await act(async () => root.unmount());

    await expect(answer.promise).resolves.toBe(false);
    // afterEach unmounts again; give it a live root.
    root = createRoot(container);
  });

  it('should_open_a_new_dialog_for_a_call_after_an_answer', async () => {
    const first = await request();
    await act(async () => current().dialogProps.onOpenChange(false));
    await expect(first.promise).resolves.toBe(false);
    expect(current().open).toBe(false);

    const second = await request();

    expect(second.promise).not.toBe(first.promise);
    expect(current().open).toBe(true);

    await act(async () => {
      current().dialogProps.onReauthenticated();
      current().dialogProps.onOpenChange(false);
    });
    await expect(second.promise).resolves.toBe(true);
  });
});

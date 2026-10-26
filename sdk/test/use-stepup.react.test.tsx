// useStepup hands the host one promise per opening of the dialog: the proof after one
// is in, null after any other close or an unmount. A proof is for one operation, so a
// call for another operation while the dialog is open is refused.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { useStepup, type Stepup } from '../src/react/index';

const HASH = 'ab'.repeat(32);
const OTHER = 'cd'.repeat(32);

let container: HTMLDivElement;
let root: Root;
let latest: Stepup | null = null;

function Probe() {
  latest = useStepup();
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

function current(): Stepup {
  if (latest === null) throw new Error('Probe has not rendered');
  return latest;
}

// Boxed, as in the reauth hook's test: awaiting the promise would hide the pending state.
async function request(intentHash = HASH, minAal = 2): Promise<{ promise: Promise<string | null> }> {
  let pending: Promise<string | null> | undefined;
  await act(async () => {
    pending = current().requestProof(intentHash, minAal);
  });
  if (pending === undefined) throw new Error('requestProof did not run');
  return { promise: pending };
}

async function prove(proof: string): Promise<void> {
  await act(async () => {
    current().dialogProps.onProof({ proof, expiresAt: 1700000000 });
    current().dialogProps.onOpenChange(false);
  });
}

describe('useStepup', () => {
  it('should_start_closed_with_nothing_to_ask', () => {
    expect(current().open).toBe(false);
    expect(current().dialogProps.request).toBeNull();
  });

  it('should_open_for_the_operation_asked', async () => {
    await request(HASH, 3);

    expect(current().dialogProps.open).toBe(true);
    expect(current().dialogProps.request).toEqual({ intentHash: HASH, minAal: 3 });
  });

  it('should_resolve_with_the_proof', async () => {
    const answer = await request();

    await prove('jwt');

    await expect(answer.promise).resolves.toBe('jwt');
    expect(current().open).toBe(false);
  });

  it('should_resolve_null_when_the_user_closes_the_dialog', async () => {
    const answer = await request();

    await act(async () => current().dialogProps.onOpenChange(false));

    await expect(answer.promise).resolves.toBeNull();
  });

  it('should_share_one_promise_between_calls_for_the_same_operation', async () => {
    const first = await request();
    const second = await request();

    expect(second.promise).toBe(first.promise);
  });

  it('should_refuse_a_call_for_another_operation_while_open', async () => {
    const first = await request(HASH, 2);

    // Outside act: a refusal changes no state, and awaiting it later would leave it unhandled meanwhile.
    await expect(current().requestProof(OTHER, 2)).rejects.toThrow('another operation');
    await expect(current().requestProof(HASH, 3)).rejects.toThrow('another operation');
    expect(current().dialogProps.request).toEqual({ intentHash: HASH, minAal: 2 });

    await prove('jwt');
    await expect(first.promise).resolves.toBe('jwt');
  });

  it('should_resolve_null_when_the_host_unmounts_while_open', async () => {
    const answer = await request();

    await act(async () => root.unmount());

    await expect(answer.promise).resolves.toBeNull();
    // afterEach unmounts again; give it a live root.
    root = createRoot(container);
  });
});

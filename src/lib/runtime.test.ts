// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * Runtime-plumbing tests: the serial queue (storage mutex), the typed
 * message protocol, and the telemetry outbox's no-lost-events
 * guarantees under concurrency and backoff.
 *
 * chrome.* is stubbed with an in-memory storage double BEFORE the
 * modules under test are imported — config.ts registers a
 * storage.onChanged listener at module load, so import order matters.
 *
 * Run: `bun test` from bastio-extension/
 */

import { beforeEach, describe, expect, test } from 'bun:test';

// ------------------------------------------------------------------
// chrome stub (must precede dynamic imports of modules that touch it)
// ------------------------------------------------------------------

const localStore = new Map<string, unknown>();

function resolveKeys(keys: string | string[] | null | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (keys == null) {
    for (const [k, v] of localStore) out[k] = v;
    return out;
  }
  for (const k of Array.isArray(keys) ? keys : [keys]) {
    if (localStore.has(k)) out[k] = localStore.get(k);
  }
  return out;
}

const chromeStub = {
  storage: {
    local: {
      // Async with a microtask hop, like the real API — the hop is what
      // makes unserialized read-modify-writes actually interleave.
      get: async (keys: string | string[] | null) => {
        await Promise.resolve();
        return resolveKeys(keys);
      },
      set: async (items: Record<string, unknown>) => {
        await Promise.resolve();
        for (const [k, v] of Object.entries(items)) localStore.set(k, v);
      },
      remove: async (keys: string | string[]) => {
        await Promise.resolve();
        for (const k of Array.isArray(keys) ? keys : [keys]) localStore.delete(k);
      },
    },
    managed: {
      get: async () => ({}),
    },
    onChanged: {
      addListener: () => undefined,
    },
  },
  runtime: {
    id: 'test-extension-id',
    getManifest: () => ({ version: '0.0.0-test' }),
  },
};

(globalThis as Record<string, unknown>).chrome = chromeStub;

const { makeSerialQueue } = await import('./lock');
const { parseExtensionMessage } = await import('./messages');
const telemetry = await import('./telemetry');

const OUTBOX_KEY = 'bastio_event_outbox';
const LOCAL_CONFIG_KEY = 'bastio_local_config';

interface StoredEntry {
  event: { event_id: string };
  attempts: number;
  next_attempt_at: number;
}

function seedConfigured(): void {
  localStore.set(LOCAL_CONFIG_KEY, {
    backend_url: 'https://backend.test',
    telemetry_endpoint: '/v1/governance/events',
    org_id: 'org-test',
    installation_token: 'tok-test',
    installation_secret: 'secret-test',
  });
}

function fakeEvent(id: string): Record<string, unknown> {
  return { event_id: id, rule_ids: [], severity: 'low', action: 'logged' };
}

let fetchCalls = 0;
function stubFetch(ok: boolean): void {
  fetchCalls = 0;
  (globalThis as Record<string, unknown>).fetch = async () => {
    fetchCalls++;
    return new Response('{}', { status: ok ? 200 : 503 });
  };
}

beforeEach(async () => {
  localStore.clear();
  seedConfigured();
  // config.ts caches the merged config; force a re-read per test.
  const { invalidateConfigCache } = await import('./config');
  invalidateConfigCache();
});

// ------------------------------------------------------------------
// makeSerialQueue
// ------------------------------------------------------------------

describe('makeSerialQueue', () => {
  test('runs tasks strictly in order', async () => {
    const lock = makeSerialQueue();
    const order: number[] = [];
    await Promise.all(
      [1, 2, 3, 4, 5].map((n) =>
        lock(async () => {
          // The later the task, the shorter its sleep — without the
          // queue, completion order would invert.
          await new Promise((r) => setTimeout(r, 6 - n));
          order.push(n);
        }),
      ),
    );
    expect(order).toEqual([1, 2, 3, 4, 5]);
  });

  test('a throwing task releases the lock instead of poisoning the queue', async () => {
    const lock = makeSerialQueue();
    await expect(lock(async () => Promise.reject(new Error('boom')))).rejects.toThrow('boom');
    const result = await lock(async () => 'still alive');
    expect(result).toBe('still alive');
  });

  test('returns the task result', async () => {
    const lock = makeSerialQueue();
    expect(await lock(async () => 42)).toBe(42);
  });
});

// ------------------------------------------------------------------
// parseExtensionMessage
// ------------------------------------------------------------------

describe('parseExtensionMessage', () => {
  test('accepts every well-formed message type', () => {
    expect(parseExtensionMessage({ type: 'start-connect' })?.type).toBe('start-connect');
    expect(parseExtensionMessage({ type: 'cancel-connect' })?.type).toBe('cancel-connect');
    expect(parseExtensionMessage({ type: 'disconnect' })?.type).toBe('disconnect');
    expect(parseExtensionMessage({ type: 'drain-outbox' })?.type).toBe('drain-outbox');
    expect(
      parseExtensionMessage({ type: 'record-event', event: fakeEvent('e1') })?.type,
    ).toBe('record-event');
    expect(
      parseExtensionMessage({ type: 'bump-volume', source_domain: 'chatgpt.com' })?.type,
    ).toBe('bump-volume');
  });

  test('rejects malformed and unknown messages', () => {
    expect(parseExtensionMessage(null)).toBeNull();
    expect(parseExtensionMessage('record-event')).toBeNull();
    expect(parseExtensionMessage({})).toBeNull();
    expect(parseExtensionMessage({ type: 'evil-type' })).toBeNull();
    expect(parseExtensionMessage({ type: 'record-event' })).toBeNull(); // missing event
    expect(parseExtensionMessage({ type: 'record-event', event: 'not-an-object' })).toBeNull();
    expect(parseExtensionMessage({ type: 'bump-volume' })).toBeNull(); // missing domain
    expect(parseExtensionMessage({ type: 'bump-volume', source_domain: '' })).toBeNull();
  });
});

// ------------------------------------------------------------------
// telemetry outbox
// ------------------------------------------------------------------

describe('telemetry outbox', () => {
  test('concurrent enqueues lose no events (mutex)', async () => {
    stubFetch(false); // every post fails → every event must land in the outbox
    const N = 25;
    await Promise.all(
      Array.from({ length: N }, (_, i) =>
        telemetry.recordEvent(fakeEvent(`evt-${i}`) as never),
      ),
    );
    const outbox = (localStore.get(OUTBOX_KEY) as StoredEntry[]) ?? [];
    expect(outbox.length).toBe(N);
    const ids = new Set(outbox.map((e) => e.event.event_id));
    expect(ids.size).toBe(N);
  });

  test('drain posts due entries and clears them', async () => {
    localStore.set(OUTBOX_KEY, [
      { event: fakeEvent('due-1'), attempts: 0, next_attempt_at: Date.now() - 1 },
      { event: fakeEvent('due-2'), attempts: 0, next_attempt_at: Date.now() - 1 },
    ]);
    stubFetch(true);
    await telemetry.drainOutbox();
    expect(fetchCalls).toBe(2);
    const outbox = (localStore.get(OUTBOX_KEY) as StoredEntry[]) ?? [];
    expect(outbox.length).toBe(0);
  });

  test('drain leaves not-yet-due entries untouched and unposted', async () => {
    localStore.set(OUTBOX_KEY, [
      { event: fakeEvent('later'), attempts: 0, next_attempt_at: Date.now() + 60_000 },
    ]);
    stubFetch(true);
    await telemetry.drainOutbox();
    expect(fetchCalls).toBe(0);
    const outbox = (localStore.get(OUTBOX_KEY) as StoredEntry[]) ?? [];
    expect(outbox.length).toBe(1);
    expect(outbox[0].attempts).toBe(0);
  });

  test('failed drain re-queues with incremented attempts and future backoff', async () => {
    localStore.set(OUTBOX_KEY, [
      { event: fakeEvent('retry-me'), attempts: 1, next_attempt_at: Date.now() - 1 },
    ]);
    stubFetch(false);
    const before = Date.now();
    await telemetry.drainOutbox();
    const outbox = (localStore.get(OUTBOX_KEY) as StoredEntry[]) ?? [];
    expect(outbox.length).toBe(1);
    expect(outbox[0].attempts).toBe(2);
    expect(outbox[0].next_attempt_at).toBeGreaterThan(before);
  });

  test('entries at the attempt cap are dropped, not retried forever', async () => {
    localStore.set(OUTBOX_KEY, [
      { event: fakeEvent('give-up'), attempts: 5, next_attempt_at: Date.now() - 1 },
    ]);
    stubFetch(false);
    await telemetry.drainOutbox();
    const outbox = (localStore.get(OUTBOX_KEY) as StoredEntry[]) ?? [];
    expect(outbox.length).toBe(0);
  });

  test('events enqueued during a slow drain are not lost', async () => {
    localStore.set(OUTBOX_KEY, [
      { event: fakeEvent('slow-due'), attempts: 0, next_attempt_at: Date.now() - 1 },
    ]);
    // Slow failing fetch so the drain's post window is wide open while
    // a concurrent recordEvent enqueues.
    fetchCalls = 0;
    (globalThis as Record<string, unknown>).fetch = async () => {
      fetchCalls++;
      await new Promise((r) => setTimeout(r, 20));
      return new Response('{}', { status: 503 });
    };
    await Promise.all([
      telemetry.drainOutbox(),
      telemetry.recordEvent(fakeEvent('mid-drain') as never),
    ]);
    const outbox = (localStore.get(OUTBOX_KEY) as StoredEntry[]) ?? [];
    const ids = outbox.map((e) => e.event.event_id).sort();
    expect(ids).toEqual(['mid-drain', 'slow-due']);
  });
});

// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * makeSerialQueue returns an async mutex: callbacks passed to the
 * returned function run strictly one-at-a-time in submission order.
 *
 * chrome.storage.local has no transactions, so every read-modify-write
 * against a shared key races with concurrent writers IN THE SAME JS
 * CONTEXT (two awaits interleave between the read and the write). This
 * queue removes that class entirely. It does NOT serialize across
 * contexts (content script vs service worker) — cross-context safety
 * comes from routing all writes for a key through the service worker
 * (single writer), which then guards them with one of these queues.
 */
export function makeSerialQueue(): <T>(fn: () => Promise<T>) => Promise<T> {
  let tail: Promise<unknown> = Promise.resolve();
  return <T>(fn: () => Promise<T>): Promise<T> => {
    // Chain regardless of the previous task's outcome — a failed task
    // must release the lock, not poison the queue.
    const run = tail.then(fn, fn);
    tail = run.catch(() => undefined);
    return run;
  };
}

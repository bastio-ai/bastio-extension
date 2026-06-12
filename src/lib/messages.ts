// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * Typed message protocol between extension surfaces (content script,
 * popup, options) and the service worker.
 *
 * Two jobs:
 *  1. A discriminated union so every sender and the worker dispatch
 *     compile against the same shapes — no stringly-typed drift.
 *  2. Single-writer routing: chrome.storage.local has no transactions,
 *     so the event outbox and volume rollup are written ONLY by the
 *     service worker. Content scripts hand their payloads over via
 *     these messages instead of doing read-modify-write themselves
 *     from N tabs concurrently.
 */

import type { GovernanceEvent } from './types';

export type ExtensionMessage =
  | { type: 'start-connect' }
  | { type: 'cancel-connect' }
  | { type: 'disconnect' }
  | { type: 'drain-outbox' }
  | { type: 'record-event'; event: GovernanceEvent }
  | { type: 'bump-volume'; source_domain: string };

/**
 * parseExtensionMessage validates an untrusted runtime message into the
 * typed union, or null for anything malformed/unknown. onMessage hands
 * us `any`-shaped data; with no `externally_connectable` manifest key
 * only our own surfaces can send, but validating costs nothing and
 * keeps the worker dispatch total.
 */
export function parseExtensionMessage(raw: unknown): ExtensionMessage | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const m = raw as Record<string, unknown>;
  switch (m.type) {
    case 'start-connect':
    case 'cancel-connect':
    case 'disconnect':
    case 'drain-outbox':
      return { type: m.type };
    case 'record-event':
      if (typeof m.event === 'object' && m.event !== null) {
        return { type: 'record-event', event: m.event as GovernanceEvent };
      }
      return null;
    case 'bump-volume':
      if (typeof m.source_domain === 'string' && m.source_domain.length > 0) {
        return { type: 'bump-volume', source_domain: m.source_domain };
      }
      return null;
    default:
      return null;
  }
}

/**
 * submitEvent hands a governance event to the service worker, which
 * posts it (or queues it in the storage-backed outbox) under its
 * single-writer lock. Fire-and-forget from the page's perspective:
 * an unreachable worker or an orphaned content script (extension
 * updated under this tab) drops the event silently — it's metadata,
 * and the orphan can't sign requests anymore anyway.
 */
export async function submitEvent(event: GovernanceEvent): Promise<void> {
  try {
    await chrome.runtime.sendMessage({
      type: 'record-event',
      event,
    } satisfies ExtensionMessage);
  } catch {
    // Worker unreachable or context invalidated — drop.
  }
}

/** submitVolumeBump — same contract as submitEvent, for volume counts. */
export async function submitVolumeBump(sourceDomain: string): Promise<void> {
  try {
    await chrome.runtime.sendMessage({
      type: 'bump-volume',
      source_domain: sourceDomain,
    } satisfies ExtensionMessage);
  } catch {
    // Worker unreachable or context invalidated — drop.
  }
}

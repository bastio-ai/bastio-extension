// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * Telemetry + classifier API client. Posts events to {backend_url}/v1/governance/events
 * with per-install HMAC auth. Local outbox + retry: 100 events/min soft cap,
 * batch and aggregate locally, retry with exponential backoff.
 *
 * NO PROMPT CONTENT EVER LEAVES THE EXTENSION. Only metadata. This is a
 * core privacy guarantee — see the README's "Privacy" section.
 */

import { getConfig, isConfigured } from './config';
import { getOrCreateInstallState } from './install-state';
import { buildAuthHeader, deriveHmacKey, signRequest } from './hmac';
import { makeSerialQueue } from './lock';
import { warn } from './log';
import type {
  ClassifyRequest,
  ClassifyResponse,
  GovernanceEvent,
} from './types';

const OUTBOX_KEY = 'bastio_event_outbox';
// Exported for the popup's "last heartbeat" row — read-only there.
export const HEARTBEAT_KEY = 'bastio_last_heartbeat';
const MAX_OUTBOX_SIZE = 1000;
const HEARTBEAT_INTERVAL_MS = 5 * 60 * 1000; // 5 min

interface OutboxEntry {
  event: GovernanceEvent;
  attempts: number;
  next_attempt_at: number;
}

// Serializes every read-modify-write on OUTBOX_KEY. Content scripts
// never touch the outbox directly (they route events through the
// service worker via messages.ts), so this in-worker lock is the
// single global lock for the key.
const withOutboxLock = makeSerialQueue();

/**
 * recordEvent posts an event, falling back to the storage-backed
 * outbox on failure. SERVICE WORKER ONLY — content scripts must use
 * submitEvent() from messages.ts so the outbox keeps a single writer.
 */
export async function recordEvent(event: GovernanceEvent): Promise<void> {
  // Stamp browser metadata if missing
  const config = await getConfig();
  if (!isConfigured(config)) {
    // Pre-configure: drop the event silently. IT must push managed config first.
    return;
  }

  const ok = await tryPostEvent(event);
  if (!ok) await enqueue(event);
}

async function tryPostEvent(event: GovernanceEvent): Promise<boolean> {
  try {
    const config = await getConfig();
    const state = await getOrCreateInstallState();
    const key = await deriveHmacKey(config.installation_secret, state.install_id);
    const path = config.telemetry_endpoint;
    const url = `${config.backend_url}${path}`;
    const ts = Date.now();
    const body = JSON.stringify(event);
    const sig = await signRequest(key, 'POST', path, ts, state.install_id, body);
    const auth = buildAuthHeader(config.org_id, state.install_id, sig, ts);
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: auth },
      body,
    });
    if (res.status === 429) return false; // rate-limited; outbox + backoff
    return res.ok || res.status === 200;
  } catch (e) {
    warn('telemetry post failed', e);
    return false;
  }
}

async function enqueue(event: GovernanceEvent): Promise<void> {
  await withOutboxLock(async () => {
    const stored = await chrome.storage.local.get(OUTBOX_KEY);
    const outbox: OutboxEntry[] = stored[OUTBOX_KEY] ?? [];
    if (outbox.length >= MAX_OUTBOX_SIZE) {
      outbox.shift(); // drop oldest
    }
    outbox.push({ event, attempts: 0, next_attempt_at: Date.now() + 5_000 });
    await chrome.storage.local.set({ [OUTBOX_KEY]: outbox });
  });
}

/**
 * Drain the outbox. Called from the service-worker alarm.
 * Exponential backoff: 5s, 10s, 30s, 2m, 10m, 1h, then drop.
 *
 * Locking shape: two short critical sections — take ownership of the
 * due entries, then re-append the failures — with the (slow) network
 * posts in between OUTSIDE the lock, so concurrent enqueues never wait
 * on the network. Entries we own can't be lost: they're either posted,
 * re-appended with backoff, or dropped at the attempt cap.
 */
export async function drainOutbox(): Promise<void> {
  const now = Date.now();
  const due = await withOutboxLock(async () => {
    const stored = await chrome.storage.local.get(OUTBOX_KEY);
    const outbox: OutboxEntry[] = stored[OUTBOX_KEY] ?? [];
    if (outbox.length === 0) return [];
    const ready = outbox.filter((e) => e.next_attempt_at <= now);
    if (ready.length === 0) return [];
    const notDue = outbox.filter((e) => e.next_attempt_at > now);
    await chrome.storage.local.set({ [OUTBOX_KEY]: notDue });
    return ready;
  });
  if (due.length === 0) return;

  const failures: OutboxEntry[] = [];
  for (const entry of due) {
    const ok = await tryPostEvent(entry.event);
    if (ok) continue;
    const attempts = entry.attempts + 1;
    if (attempts >= 6) continue; // give up
    const backoff = Math.min(60 * 60_000, 5_000 * 2 ** attempts);
    failures.push({ ...entry, attempts, next_attempt_at: now + backoff });
  }
  if (failures.length === 0) return;

  await withOutboxLock(async () => {
    const stored = await chrome.storage.local.get(OUTBOX_KEY);
    const outbox: OutboxEntry[] = stored[OUTBOX_KEY] ?? [];
    const merged = outbox.concat(failures);
    // Respect the cap after the merge — drop oldest first, same
    // policy as enqueue.
    while (merged.length > MAX_OUTBOX_SIZE) merged.shift();
    await chrome.storage.local.set({ [OUTBOX_KEY]: merged });
  });
}

export async function sendHeartbeat(): Promise<void> {
  const config = await getConfig();
  if (!isConfigured(config)) return;
  const stored = await chrome.storage.local.get(HEARTBEAT_KEY);
  const last = (stored[HEARTBEAT_KEY] as number) ?? 0;
  if (Date.now() - last < HEARTBEAT_INTERVAL_MS) return;

  try {
    const state = await getOrCreateInstallState();
    const key = await deriveHmacKey(config.installation_secret, state.install_id);
    const path = '/v1/governance/heartbeat';
    const url = `${config.backend_url}${path}`;
    const ts = Date.now();
    const body = JSON.stringify({
      install_id: state.install_id,
      extension_version: chrome.runtime.getManifest().version,
      browser: detectBrowser(),
      browser_version: detectBrowserVersion(),
    });
    const sig = await signRequest(key, 'POST', path, ts, state.install_id, body);
    const auth = buildAuthHeader(config.org_id, state.install_id, sig, ts);
    await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: auth },
      body,
    });
    await chrome.storage.local.set({ [HEARTBEAT_KEY]: Date.now() });
  } catch (e) {
    warn('heartbeat failed', e);
  }
}

/**
 * Async server-side classifier call. Non-blocking — content script does NOT wait
 * on this for the block decision. Promotes severity if classifier returns higher
 * confidence than local detection.
 *
 * Latency SLO: p95 < 500ms. Drops the response if exceeded.
 */
export async function classify(req: ClassifyRequest): Promise<ClassifyResponse | null> {
  const config = await getConfig();
  if (!isConfigured(config)) return null;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 500);
  try {
    const state = await getOrCreateInstallState();
    const key = await deriveHmacKey(config.installation_secret, state.install_id);
    const path = '/v1/governance/classify';
    const url = `${config.backend_url}${path}`;
    const ts = Date.now();
    const body = JSON.stringify(req);
    const sig = await signRequest(key, 'POST', path, ts, state.install_id, body);
    const auth = buildAuthHeader(config.org_id, state.install_id, sig, ts);

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: auth },
      body,
      signal: controller.signal,
    });
    if (!res.ok) return null;
    return (await res.json()) as ClassifyResponse;
  } catch {
    return null;
  } finally {
    // Without the finally, any throw between setTimeout and the old
    // clearTimeout left a live timer aborting a dead controller.
    clearTimeout(timeoutId);
  }
}

function detectBrowser(): 'chrome' | 'edge' | 'unknown' {
  const ua = navigator.userAgent;
  if (/Edg\//.test(ua)) return 'edge';
  if (/Chrome\//.test(ua)) return 'chrome';
  return 'unknown';
}

function detectBrowserVersion(): string {
  const ua = navigator.userAgent;
  const match = /(Edg|Chrome)\/([0-9.]+)/.exec(ua);
  return match?.[2] ?? 'unknown';
}

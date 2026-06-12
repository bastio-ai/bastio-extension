// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * Per-domain volume aggregator. Used by tracking_mode='volume' and
 * tracking_mode='full' to surface "your team sent N prompts to ChatGPT
 * this month" without firing a telemetry event for every individual
 * keystroke or send.
 *
 * Counts live in chrome.storage.local so they survive service-worker
 * tear-down between sends. The window starts when a counter is first
 * incremented after a flush; closes when the SW alarm fires (every 5
 * minutes — the chrome.alarms minimum is 30 s, but the volume signal
 * doesn't need that resolution and a 5-minute roll-up keeps the
 * outbound payload small).
 */

import { getConfig, isConfigured } from './config';
import { buildAuthHeader, deriveHmacKey, signRequest } from './hmac';
import { getOrCreateInstallState } from './install-state';
import { makeSerialQueue } from './lock';
import { debug, warn } from './log';
import type { VolumeRollup } from './types';

const VOLUME_KEY = 'bastio_volume_rollup';
export const ALARM_VOLUME_FLUSH = 'bastio.volume-rollup';

interface StoredRollup {
  window_start: string;
  by_domain: Record<string, number>;
}

// Serializes read-modify-writes on VOLUME_KEY. Content scripts route
// bumps through the service worker (submitVolumeBump in messages.ts),
// so this in-worker lock is the single global lock for the key —
// concurrent bumps from N tabs can no longer drop increments.
const withVolumeLock = makeSerialQueue();

/**
 * Increment the count for a (source_domain, send) pair. SERVICE WORKER
 * ONLY — content scripts must use submitVolumeBump() from messages.ts.
 * Cheap relative to a network request, so calling it on every send
 * (even ones that produce a separate `observed` event in mode='full')
 * is fine.
 */
export async function bumpVolume(sourceDomain: string): Promise<void> {
  await withVolumeLock(async () => {
    const bag = await chrome.storage.local.get(VOLUME_KEY);
    const stored = (bag[VOLUME_KEY] as StoredRollup | undefined) ?? {
      window_start: new Date().toISOString(),
      by_domain: {},
    };
    stored.by_domain[sourceDomain] = (stored.by_domain[sourceDomain] ?? 0) + 1;
    await chrome.storage.local.set({ [VOLUME_KEY]: stored });
  });
}

/**
 * Flush the accumulated counts to /v1/governance/volume. Called from
 * the ALARM_VOLUME_FLUSH alarm in the service worker. Silent no-op
 * when the extension isn't configured or the rollup is empty.
 */
export async function flushVolume(): Promise<void> {
  const config = await getConfig();
  if (!isConfigured(config)) return;
  if (config.tracking_mode === 'policy') {
    // Mode was downgraded since the last bump — drop any in-flight
    // counts rather than ship them. Privacy posture wins.
    await chrome.storage.local.remove(VOLUME_KEY);
    return;
  }

  // Snapshot + clear inside the lock so a bump landing mid-flush can't
  // be deleted unseen — it either makes this window or starts the next.
  // Clearing up-front (vs after the POST) is deliberate: if the POST
  // fails we'd rather lose one window's counts than double-count on
  // the next flush. Volume is a soft signal — the trend matters, not
  // the exact integer.
  const rollup = await withVolumeLock(async (): Promise<VolumeRollup | null> => {
    const bag = await chrome.storage.local.get(VOLUME_KEY);
    const stored = bag[VOLUME_KEY] as StoredRollup | undefined;
    if (!stored || Object.keys(stored.by_domain).length === 0) return null;
    await chrome.storage.local.remove(VOLUME_KEY);
    return {
      window_start: stored.window_start,
      window_end: new Date().toISOString(),
      by_domain: stored.by_domain,
    };
  });
  if (!rollup) return;

  try {
    const state = await getOrCreateInstallState();
    const key = await deriveHmacKey(config.installation_secret, state.install_id);
    const path = '/v1/governance/volume';
    const url = `${config.backend_url}${path}`;
    const ts = Date.now();
    const body = JSON.stringify(rollup);
    const sig = await signRequest(key, 'POST', path, ts, state.install_id, body);
    const auth = buildAuthHeader(config.org_id, state.install_id, sig, ts);
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: auth },
      body,
    });
    if (!res.ok) {
      warn('volume flush rejected', res.status);
    } else {
      debug('volume flushed', Object.keys(rollup.by_domain).length, 'domains');
    }
  } catch (e) {
    warn('volume flush failed', e);
  }
}

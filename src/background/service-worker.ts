// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * MV3 service worker. Handles:
 *  - Per-install state initialization
 *  - Periodic outbox drain (telemetry retry)
 *  - Periodic heartbeat to backend
 *  - Domain-list refresh (every 6h)
 *  - Self-serve onboarding handshake (claim → poll)
 *  - Popup ↔ SW message passing for connect / disconnect
 */

import { initLogging } from '../lib/log';
import { parseExtensionMessage } from '../lib/messages';
import {
  ALARM_CONNECT_POLL,
  disconnect,
  getPendingClaim,
  pollConnect,
  startConnect,
} from '../lib/onboarding';
import { drainOutbox, recordEvent, sendHeartbeat } from '../lib/telemetry';
import { getOrCreateInstallState } from '../lib/install-state';
import { ALARM_POLICY_FETCH, fetchServerPolicy } from '../lib/policy-fetch';
import { ALARM_VOLUME_FLUSH, bumpVolume, flushVolume } from '../lib/volume';

// Service workers can be torn down and respawned between alarms, so
// re-hydrate the debug flag at module load. Each surface (SW, content
// script) keeps its own cached value.
void initLogging();

const ALARM_OUTBOX = 'bastio.outbox';
const ALARM_HEARTBEAT = 'bastio.heartbeat';
const ALARM_DOMAIN_LIST = 'bastio.domain-list';

// Shared by onInstalled + onStartup: alarms.create is idempotent
// (same-name create replaces), so double registration is harmless and
// keeping ONE list prevents the two paths drifting apart.
async function registerAlarms(): Promise<void> {
  await chrome.alarms.create(ALARM_OUTBOX, { periodInMinutes: 1 });
  await chrome.alarms.create(ALARM_HEARTBEAT, { periodInMinutes: 5 });
  await chrome.alarms.create(ALARM_DOMAIN_LIST, { periodInMinutes: 360 });
  await chrome.alarms.create(ALARM_VOLUME_FLUSH, { periodInMinutes: 5 });
  await chrome.alarms.create(ALARM_POLICY_FETCH, { periodInMinutes: 5 });
  // The connect poll is armed by startConnect(), not here — but if a
  // self-serve connect was mid-flight when the browser shut down,
  // re-arm it so the pending claim resolves instead of stranding the
  // user until they re-click Connect. (Alarms usually survive
  // restarts; this is cheap insurance for the cases where they don't.)
  if (await getPendingClaim()) {
    await chrome.alarms.create(ALARM_CONNECT_POLL, { periodInMinutes: 0.5 });
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  await getOrCreateInstallState();
  await registerAlarms();
  // Eager first fetch so a freshly reloaded extension picks up dashboard
  // policy changes (including tracking_mode) immediately instead of
  // waiting up to 5 min for the alarm tick.
  void fetchServerPolicy();
});

chrome.runtime.onStartup.addListener(async () => {
  await registerAlarms();
  void fetchServerPolicy();
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === ALARM_OUTBOX) {
    await drainOutbox();
  } else if (alarm.name === ALARM_HEARTBEAT) {
    await sendHeartbeat();
  } else if (alarm.name === ALARM_DOMAIN_LIST) {
    // Domain-list refresh: cached locally; future versions will pull from backend.
    // No-op for v0.1; allowlist is bundled in manifest content_scripts matches.
  } else if (alarm.name === ALARM_CONNECT_POLL) {
    await pollConnect();
  } else if (alarm.name === ALARM_VOLUME_FLUSH) {
    await flushVolume();
  } else if (alarm.name === ALARM_POLICY_FETCH) {
    await fetchServerPolicy();
  }
});

// Surface ↔ SW message handlers, validated through the typed protocol
// in lib/messages.ts. Two flavors:
//
//  - Popup connect/disconnect: the popup is short-lived and may close
//    the moment the user switches focus to the connect tab — keeping
//    the claim/poll state machine in the SW means the flow keeps
//    running regardless of popup lifecycle. These await their work and
//    respond with the outcome.
//  - Content-script record-event / bump-volume: single-writer routing
//    for chrome.storage read-modify-writes (see messages.ts). These
//    are fire-and-forget — respond immediately, do the work async, so
//    a tab never waits on telemetry network calls.
chrome.runtime.onMessage.addListener((raw: unknown, sender, sendResponse) => {
  // Without externally_connectable only our own surfaces can reach
  // onMessage, but the guard is free and makes the assumption explicit.
  if (sender.id !== chrome.runtime.id) return undefined;
  const msg = parseExtensionMessage(raw);
  if (!msg) {
    sendResponse({ ok: false, error: 'unknown message type' });
    return undefined;
  }

  if (msg.type === 'record-event') {
    void recordEvent(msg.event);
    sendResponse({ ok: true });
    return undefined;
  }
  if (msg.type === 'bump-volume') {
    void bumpVolume(msg.source_domain);
    sendResponse({ ok: true });
    return undefined;
  }

  (async () => {
    try {
      if (msg.type === 'start-connect') {
        const claim = await startConnect();
        sendResponse({ ok: true, claim });
      } else if (msg.type === 'drain-outbox') {
        // Popup's "send queued now": awaited so the popup can re-read
        // the queue depth after the drain actually ran.
        await drainOutbox();
        sendResponse({ ok: true });
      } else {
        // cancel-connect | disconnect
        await disconnect();
        sendResponse({ ok: true });
      }
    } catch (e) {
      sendResponse({ ok: false, error: e instanceof Error ? e.message : String(e) });
    }
  })();
  return true; // keep the channel open for async sendResponse
});

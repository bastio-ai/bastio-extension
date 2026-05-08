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
import {
  ALARM_CONNECT_POLL,
  disconnect,
  pollConnect,
  startConnect,
} from '../lib/onboarding';
import { drainOutbox, sendHeartbeat } from '../lib/telemetry';
import { getOrCreateInstallState } from '../lib/install-state';
import { ALARM_POLICY_FETCH, fetchServerPolicy } from '../lib/policy-fetch';
import { ALARM_VOLUME_FLUSH, flushVolume } from '../lib/volume';

// Service workers can be torn down and respawned between alarms, so
// re-hydrate the debug flag at module load. Each surface (SW, content
// script) keeps its own cached value.
void initLogging();

const ALARM_OUTBOX = 'bastio.outbox';
const ALARM_HEARTBEAT = 'bastio.heartbeat';
const ALARM_DOMAIN_LIST = 'bastio.domain-list';

chrome.runtime.onInstalled.addListener(async () => {
  await getOrCreateInstallState();
  await chrome.alarms.create(ALARM_OUTBOX, { periodInMinutes: 1 });
  await chrome.alarms.create(ALARM_HEARTBEAT, { periodInMinutes: 5 });
  await chrome.alarms.create(ALARM_DOMAIN_LIST, { periodInMinutes: 360 });
  await chrome.alarms.create(ALARM_VOLUME_FLUSH, { periodInMinutes: 5 });
  await chrome.alarms.create(ALARM_POLICY_FETCH, { periodInMinutes: 5 });
  // Eager first fetch so a freshly reloaded extension picks up dashboard
  // policy changes (including tracking_mode) immediately instead of
  // waiting up to 5 min for the alarm tick.
  void fetchServerPolicy();
});

chrome.runtime.onStartup.addListener(async () => {
  await chrome.alarms.create(ALARM_OUTBOX, { periodInMinutes: 1 });
  await chrome.alarms.create(ALARM_HEARTBEAT, { periodInMinutes: 5 });
  await chrome.alarms.create(ALARM_DOMAIN_LIST, { periodInMinutes: 360 });
  await chrome.alarms.create(ALARM_VOLUME_FLUSH, { periodInMinutes: 5 });
  await chrome.alarms.create(ALARM_POLICY_FETCH, { periodInMinutes: 5 });
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

// Popup ↔ SW message handlers. The popup is short-lived and may close
// the moment the user switches focus to the connect tab — keeping the
// claim/poll state machine in the SW means the flow keeps running
// regardless of popup lifecycle.
type PopupMessage =
  | { type: 'start-connect' }
  | { type: 'cancel-connect' }
  | { type: 'disconnect' };

chrome.runtime.onMessage.addListener((msg: PopupMessage, _sender, sendResponse) => {
  (async () => {
    try {
      if (msg.type === 'start-connect') {
        const claim = await startConnect();
        sendResponse({ ok: true, claim });
      } else if (msg.type === 'cancel-connect' || msg.type === 'disconnect') {
        await disconnect();
        sendResponse({ ok: true });
      } else {
        sendResponse({ ok: false, error: 'unknown message type' });
      }
    } catch (e) {
      sendResponse({ ok: false, error: e instanceof Error ? e.message : String(e) });
    }
  })();
  return true; // keep the channel open for async sendResponse
});

// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

import { getConfig, isConfigured, invalidateConfigCache } from '../lib/config';
import { getPendingClaim } from '../lib/onboarding';
import { SERVER_POLICY_AT_KEY } from '../lib/policy-fetch';
import { HEARTBEAT_KEY } from '../lib/telemetry';

type View = 'disconnected' | 'connecting' | 'connected';

// Compact relative timestamp for the connected view's status rows.
// "—" for never, "now" under a minute, then m/h/d buckets.
function relTime(ts: number | undefined): string {
  if (!ts || ts <= 0) return '—';
  const delta = Date.now() - ts;
  if (delta < 60_000) return 'now';
  if (delta < 60 * 60_000) return `${Math.floor(delta / 60_000)}m ago`;
  if (delta < 24 * 60 * 60_000) return `${Math.floor(delta / 3_600_000)}h ago`;
  return `${Math.floor(delta / 86_400_000)}d ago`;
}

async function init(): Promise<void> {
  const versionEl = document.getElementById('version')!;
  versionEl.textContent = `v${chrome.runtime.getManifest().version}`;

  document.getElementById('open-options')!.addEventListener('click', (e) => {
    e.preventDefault();
    void chrome.runtime.openOptionsPage();
  });

  // Wire button handlers up-front; they're idempotent.
  document.getElementById('btn-connect')!.addEventListener('click', () => {
    void onConnect();
  });
  document.getElementById('btn-cancel')!.addEventListener('click', () => {
    void onCancel();
  });
  document.getElementById('btn-drain')!.addEventListener('click', () => {
    void onDrain();
  });
  document.getElementById('open-connect-url')!.addEventListener('click', async (e) => {
    e.preventDefault();
    const claim = await getPendingClaim();
    if (claim) void chrome.tabs.create({ url: claim.connect_url });
  });

  // Listen for storage changes so the popup re-renders when the SW
  // finishes the poll handshake while the popup is still open.
  chrome.storage.onChanged.addListener((_changes, area) => {
    if (area === 'local' || area === 'managed') {
      void render();
    }
  });

  await render();
}

async function render(): Promise<void> {
  invalidateConfigCache();
  const config = await getConfig();
  const pending = await getPendingClaim();

  let view: View;
  if (isConfigured(config)) {
    view = 'connected';
  } else if (pending && new Date(pending.expires_at) > new Date()) {
    view = 'connecting';
  } else {
    view = 'disconnected';
  }

  const statusEl = document.getElementById('status')!;
  statusEl.classList.remove('ok', 'warn');

  showOnly(view);

  if (view === 'connected') {
    statusEl.textContent = 'Active';
    statusEl.classList.add('ok');
    document.getElementById('org-id')!.textContent = config.org_id.slice(0, 12) + '…';
    document.getElementById('backend-url')!.textContent = new URL(config.backend_url).host;
    const stored = await chrome.storage.local.get([
      'bastio_event_outbox',
      HEARTBEAT_KEY,
      SERVER_POLICY_AT_KEY,
    ]);
    const outbox = (stored['bastio_event_outbox'] as Array<unknown>) ?? [];
    document.getElementById('event-count')!.textContent =
      outbox.length === 0 ? 'all sent' : `${outbox.length} queued`;
    document.getElementById('heartbeat-at')!.textContent = relTime(
      stored[HEARTBEAT_KEY] as number | undefined,
    );
    document.getElementById('policy-at')!.textContent = relTime(
      stored[SERVER_POLICY_AT_KEY] as number | undefined,
    );
    // Manual drain only matters when something is actually queued.
    (document.getElementById('btn-drain') as HTMLButtonElement).hidden =
      outbox.length === 0;
  } else if (view === 'connecting') {
    statusEl.textContent = 'Connecting…';
    statusEl.classList.add('warn');
  } else {
    statusEl.textContent = 'Not connected';
    statusEl.classList.add('warn');
  }
}

function showOnly(view: View): void {
  const ids: Record<View, string> = {
    disconnected: 'view-disconnected',
    connecting: 'view-connecting',
    connected: 'view-connected',
  };
  for (const [k, id] of Object.entries(ids)) {
    const el = document.getElementById(id)!;
    el.hidden = k !== view;
  }
}

async function onConnect(): Promise<void> {
  const btn = document.getElementById('btn-connect') as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = 'Opening…';
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'start-connect' });
    if (!resp?.ok) {
      btn.textContent = 'Connect to Bastio';
      btn.disabled = false;
      const statusEl = document.getElementById('status')!;
      statusEl.textContent = `Error: ${resp?.error ?? 'unknown'}`;
      statusEl.classList.add('warn');
      return;
    }
    await render();
  } catch (e) {
    btn.textContent = 'Connect to Bastio';
    btn.disabled = false;
    const statusEl = document.getElementById('status')!;
    statusEl.textContent = `Error: ${e instanceof Error ? e.message : 'unknown'}`;
    statusEl.classList.add('warn');
  }
}

async function onCancel(): Promise<void> {
  await chrome.runtime.sendMessage({ type: 'cancel-connect' });
  await render();
}

async function onDrain(): Promise<void> {
  const btn = document.getElementById('btn-drain') as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = 'Sending…';
  try {
    await chrome.runtime.sendMessage({ type: 'drain-outbox' });
  } finally {
    btn.disabled = false;
    btn.textContent = 'Send queued events now';
    await render();
  }
}

void init();

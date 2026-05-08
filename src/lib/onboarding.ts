// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * Self-serve onboarding flow.
 *
 * The Web Store install path: when the user opens the popup and clicks
 * "Connect to Bastio", we mint a server-side claim, open the dashboard's
 * connect URL in a new tab, and poll for confirmation. On success we
 * write the credentials into chrome.storage.local under LOCAL_CONFIG_KEY
 * — the same key getConfig() reads as a self-serve / dev fallback above
 * chrome.storage.managed.
 *
 * Polling lives in the service worker (not the popup) so it survives the
 * popup closing while the user is in the connect tab. Polling cadence
 * is bounded by chrome.alarms' 30-second minimum periodInMinutes; that
 * means up to ~30s of latency between the user clicking Confirm and the
 * popup re-rendering as connected. Acceptable UX for a one-time bind.
 */

import { LOCAL_CONFIG_KEY, invalidateConfigCache } from './config';
import { debug, warn } from './log';
import type { ManagedConfig } from './types';

export const ALARM_CONNECT_POLL = 'bastio.connect-poll';
const PENDING_CLAIM_KEY = 'bastio_pending_claim';
const DEFAULT_BACKEND = 'https://api.bastio.com';

export interface PendingClaim {
  install_id: string;
  connect_url: string;
  expires_at: string;
  backend_url: string;
}

interface ClaimResponse {
  install_id: string;
  connect_url: string;
  expires_at: string;
}

interface PollResponse {
  org_id: string;
  installation_token: string;
  installation_secret: string;
  telemetry_endpoint?: string;
}

export async function getPendingClaim(): Promise<PendingClaim | null> {
  const bag = await chrome.storage.local.get(PENDING_CLAIM_KEY);
  const claim = bag[PENDING_CLAIM_KEY] as PendingClaim | undefined;
  return claim ?? null;
}

export async function clearPendingClaim(): Promise<void> {
  await chrome.storage.local.remove(PENDING_CLAIM_KEY);
  await chrome.alarms.clear(ALARM_CONNECT_POLL);
}

/**
 * Resolve which backend the connect request should go to. Defaults to
 * the production cloud endpoint; honours an explicit backend_url that
 * has already been seeded via build-time env vars or chrome.storage.managed
 * (rare in self-serve, common in self-hosted dev).
 */
async function resolveBackendURL(): Promise<string> {
  // Read the raw managed bag rather than the merged getConfig() — we
  // want to skip the dev-override path since starting a connect flow
  // implies we don't yet have a valid local config to reuse.
  const managed = await chrome.storage.managed.get(null).catch(() => ({}));
  const fromManaged = (managed as Partial<ManagedConfig>).backend_url;
  if (fromManaged && fromManaged.length > 0) return fromManaged;
  // Build-time env (handled at compile time via Vite, lands in DEFAULT_CONFIG).
  // We can't import DEFAULT_CONFIG from config.ts without re-introducing
  // the full merge; the literal string here matches the Vite default.
  return DEFAULT_BACKEND;
}

/**
 * Kick off the self-serve onboarding handshake. Fetches a fresh claim,
 * opens the connect URL in a new tab, and schedules the poll alarm.
 * Idempotent: if a non-expired pending claim already exists, returns it
 * without minting a new one (re-clicking Connect from the popup re-opens
 * the same tab).
 */
export async function startConnect(): Promise<PendingClaim> {
  const existing = await getPendingClaim();
  if (existing && new Date(existing.expires_at) > new Date()) {
    debug('reusing pending claim', existing.install_id);
    void chrome.tabs.create({ url: existing.connect_url });
    return existing;
  }

  const backend = await resolveBackendURL();
  const url = `${backend}/v1/governance/extension/claim`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  });
  if (!res.ok) {
    throw new Error(`claim failed: ${res.status} ${res.statusText}`);
  }
  const data = (await res.json()) as ClaimResponse;
  const pending: PendingClaim = {
    install_id: data.install_id,
    connect_url: data.connect_url,
    expires_at: data.expires_at,
    backend_url: backend,
  };
  await chrome.storage.local.set({ [PENDING_CLAIM_KEY]: pending });
  // chrome.alarms minimum periodInMinutes in production builds is 0.5
  // (30 seconds). The user typically takes 5-30s to confirm, so the
  // first or second tick will pick up the credentials.
  await chrome.alarms.create(ALARM_CONNECT_POLL, { periodInMinutes: 0.5 });
  void chrome.tabs.create({ url: pending.connect_url });
  return pending;
}

/**
 * Poll the cloud server for a confirmed claim. Called from the
 * ALARM_CONNECT_POLL alarm in the service worker.
 *
 *  - 404: still pending → keep polling
 *  - 410: expired or already consumed → clean up
 *  - 200: credentials returned → write to LOCAL_CONFIG_KEY, clean up
 */
export async function pollConnect(): Promise<'pending' | 'connected' | 'expired' | 'error'> {
  const pending = await getPendingClaim();
  if (!pending) {
    await chrome.alarms.clear(ALARM_CONNECT_POLL);
    return 'expired';
  }
  if (new Date(pending.expires_at) <= new Date()) {
    debug('pending claim expired locally, cleaning up');
    await clearPendingClaim();
    return 'expired';
  }

  const url = `${pending.backend_url}/v1/governance/extension/poll/${pending.install_id}`;
  let res: Response;
  try {
    res = await fetch(url);
  } catch (e) {
    warn('poll fetch failed', e);
    return 'error';
  }

  if (res.status === 404) return 'pending';
  if (res.status === 410) {
    await clearPendingClaim();
    return 'expired';
  }
  if (!res.ok) {
    warn('poll unexpected status', res.status);
    return 'error';
  }

  const data = (await res.json()) as PollResponse;
  const localConfig: Partial<ManagedConfig> = {
    backend_url: pending.backend_url,
    org_id: data.org_id,
    installation_token: data.installation_token,
    installation_secret: data.installation_secret,
    telemetry_endpoint: data.telemetry_endpoint ?? '/v1/governance/events',
  };
  await chrome.storage.local.set({ [LOCAL_CONFIG_KEY]: localConfig });
  await clearPendingClaim();
  invalidateConfigCache();
  debug('connect succeeded for org', data.org_id);
  return 'connected';
}

/**
 * Wipe the local config so the popup goes back to the disconnected
 * state. Does NOT touch chrome.storage.managed — managed installs are
 * controlled by IT and not user-disconnectable.
 */
export async function disconnect(): Promise<void> {
  await chrome.storage.local.remove(LOCAL_CONFIG_KEY);
  await clearPendingClaim();
  invalidateConfigCache();
}

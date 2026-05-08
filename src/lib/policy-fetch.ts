// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * Server-side policy fetcher. Polls /v1/governance/policy on a schedule
 * so admin changes in the cloud dashboard propagate to active extensions
 * without requiring an MDM re-push.
 *
 * The fetched policy lives in chrome.storage.local under
 * BASTIO_SERVER_POLICY_KEY. getConfig() merges it on top of the local /
 * managed config so server-side fields (right now: tracking_mode) take
 * precedence. Other fields (default_policy, custom_keywords, etc.) come
 * from the server response too — any non-empty value wins over the local
 * baseline.
 *
 * Cadence: chrome.alarms minimum is 30 s, but admin policy changes
 * aren't latency-critical, so we run on the same 5-minute cadence as
 * the heartbeat. Worst-case propagation: 5 min after dashboard save.
 */

import { getConfig, isConfigured, invalidateConfigCache } from './config';
import { buildAuthHeader, deriveHmacKey, signRequest } from './hmac';
import { getOrCreateInstallState } from './install-state';
import { debug, warn } from './log';
import type { ManagedConfig, PolicyConfig, TrackingMode } from './types';

export const ALARM_POLICY_FETCH = 'bastio.policy-fetch';
export const SERVER_POLICY_KEY = 'bastio_server_policy';

// Subset of the server-side policy fields the extension consumes. The
// dashboard's /policy endpoint returns more (e.g. custom_regex_packs)
// but the extension only needs the parts it acts on.
export interface ServerPolicy {
  default_policy?: PolicyConfig;
  custom_keywords?: string[];
  override_enabled?: boolean;
  tracking_mode?: TrackingMode;
}

/**
 * Hit /v1/governance/policy with the per-install HMAC, store the parsed
 * subset under SERVER_POLICY_KEY. Best-effort: failures (network, auth,
 * 5xx) just log and leave the previous cached value in place.
 */
export async function fetchServerPolicy(): Promise<void> {
  const config = await getConfig();
  if (!isConfigured(config)) return;

  try {
    const state = await getOrCreateInstallState();
    const key = await deriveHmacKey(config.installation_secret, state.install_id);
    const path = '/v1/governance/policy';
    const url = `${config.backend_url}${path}`;
    const ts = Date.now();
    const sig = await signRequest(key, 'GET', path, ts, state.install_id, '');
    const auth = buildAuthHeader(config.org_id, state.install_id, sig, ts);
    const res = await fetch(url, { method: 'GET', headers: { authorization: auth } });
    if (!res.ok) {
      warn('policy fetch rejected', res.status);
      return;
    }
    const raw = (await res.json()) as Record<string, unknown>;
    const subset: ServerPolicy = {};
    if (raw.default_policy && typeof raw.default_policy === 'object') {
      subset.default_policy = raw.default_policy as PolicyConfig;
    }
    if (Array.isArray(raw.custom_keywords)) {
      subset.custom_keywords = raw.custom_keywords as string[];
    }
    if (typeof raw.override_enabled === 'boolean') {
      subset.override_enabled = raw.override_enabled;
    }
    if (raw.tracking_mode === 'policy' || raw.tracking_mode === 'volume' || raw.tracking_mode === 'full') {
      subset.tracking_mode = raw.tracking_mode;
    }
    await chrome.storage.local.set({ [SERVER_POLICY_KEY]: subset });
    invalidateConfigCache();
    debug('server policy fetched', subset);
  } catch (e) {
    warn('policy fetch failed', e);
  }
}

/**
 * Read the cached server policy, if present. Returns null when the
 * extension has never successfully fetched (fresh install, network
 * down). Used by getConfig() in config.ts to merge server fields on
 * top of the local/managed baseline.
 */
export async function getCachedServerPolicy(): Promise<ServerPolicy | null> {
  const bag = await chrome.storage.local.get(SERVER_POLICY_KEY);
  const cached = bag[SERVER_POLICY_KEY] as ServerPolicy | undefined;
  return cached ?? null;
}

/**
 * Apply the cached server policy on top of a baseline managed config.
 * Server values win when present. Used inside config.ts only — exported
 * for testability.
 */
export function mergeServerPolicy(base: ManagedConfig, srv: ServerPolicy | null): ManagedConfig {
  if (!srv) return base;
  return {
    ...base,
    default_policy: srv.default_policy
      ? { ...base.default_policy, ...srv.default_policy }
      : base.default_policy,
    custom_keywords: srv.custom_keywords ?? base.custom_keywords,
    override_enabled:
      typeof srv.override_enabled === 'boolean' ? srv.override_enabled : base.override_enabled,
    tracking_mode: srv.tracking_mode ?? base.tracking_mode,
  };
}

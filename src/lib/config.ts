// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * Managed storage configuration loader.
 *
 * IT pushes the org config via Chrome Enterprise / Intune / Jamf into
 * chrome.storage.managed. This module reads it and provides typed access.
 * For self-serve installs (Chrome Web Store), the extension falls back to
 * defaults pointing at api.bastio.com.
 *
 * Self-serve path: chrome.storage.managed is read-only at runtime even
 * from the SW DevTools console, so we also accept the same shape under
 * chrome.storage.local['bastio_local_config']. When that key is set, it
 * wins over managed config. Two writers populate it:
 *   1. The popup's "Connect to Bastio" button — Web Store install path.
 *      The SW completes a /v1/governance/extension/claim+poll handshake
 *      and writes the credentials here.
 *   2. Manual seeding from the SW DevTools console — local development.
 *
 * Production enterprise installs push config via chrome.storage.managed
 * and never touch this key.
 */

import { warn } from './log';
import { getCachedServerPolicy, mergeServerPolicy } from './policy-fetch';
import type { ManagedConfig } from './types';

// Exported so the service-worker onboarding flow can write credentials
// here after the /extension/poll handshake succeeds, and so the popup
// can clear it on disconnect.
export const LOCAL_CONFIG_KEY = 'bastio_local_config';

// Build-time env vars (from Vite). When set, the extension boots
// pre-configured — useful for local dev / demo without going through
// the Chrome managed-policy plumbing. In production builds these are
// unset and `chrome.storage.managed` (pushed by IT via MDM) wins.
//
// Set in your shell before `npm run build`:
//   VITE_BASTIO_BACKEND_URL=https://api.bastio.com
//   VITE_BASTIO_ORG_ID=<from dashboard installation>
//   VITE_BASTIO_INSTALL_TOKEN=<from dashboard installation>
//   VITE_BASTIO_INSTALL_SECRET=<from dashboard installation>
//
// Never commit a build with secrets — env-driven means your source
// tree stays clean and the secrets live only in your shell history.
const ENV_BACKEND = import.meta.env.VITE_BASTIO_BACKEND_URL;
const ENV_ORG_ID = import.meta.env.VITE_BASTIO_ORG_ID;
const ENV_INSTALL_TOKEN = import.meta.env.VITE_BASTIO_INSTALL_TOKEN;
const ENV_INSTALL_SECRET = import.meta.env.VITE_BASTIO_INSTALL_SECRET;
const ENV_REDIRECT_URL = import.meta.env.VITE_BASTIO_REDIRECT_URL;
const ENV_REDIRECT_LABEL = import.meta.env.VITE_BASTIO_REDIRECT_LABEL;

const DEFAULT_CONFIG: ManagedConfig = {
  backend_url: ENV_BACKEND ?? 'https://api.bastio.com',
  org_id: ENV_ORG_ID ?? '',
  installation_token: ENV_INSTALL_TOKEN ?? '',
  installation_secret: ENV_INSTALL_SECRET ?? '',
  default_policy: {
    low: 'log',
    medium: 'warn',
    high: 'block_redirect',
  },
  custom_keywords: [],
  domain_overrides: [],
  override_enabled: false,
  telemetry_endpoint: '/v1/governance/events',
  tracking_mode: 'policy',
  // Redirect target rendered as the modal's primary CTA when policy
  // action is 'block_redirect'. Override at build time with
  // VITE_BASTIO_REDIRECT_URL / VITE_BASTIO_REDIRECT_LABEL, or in
  // production via chrome.storage.managed.
  redirect_target: {
    url: ENV_REDIRECT_URL ?? 'https://workspace.bastio.com',
    label: ENV_REDIRECT_LABEL ?? 'Continue safely in Bastio Workspace',
    open_in_new_tab: true,
  },
};

let cached: ManagedConfig | null = null;

export async function getConfig(): Promise<ManagedConfig> {
  if (cached) return cached;
  const managed = await chrome.storage.managed.get(null).catch(() => ({}));
  const localBag = await chrome.storage.local.get(LOCAL_CONFIG_KEY);
  const localConfig = localBag[LOCAL_CONFIG_KEY] as Partial<ManagedConfig> | undefined;
  let baseline: ManagedConfig;
  if (localConfig && Object.keys(localConfig).length > 0) {
    warn('using chrome.storage.local config (self-serve / dev path)');
    baseline = mergeConfig(DEFAULT_CONFIG, localConfig);
  } else {
    baseline = mergeConfig(DEFAULT_CONFIG, managed as Partial<ManagedConfig>);
  }
  // Apply the cached server-side policy on top. tracking_mode + dynamic
  // default_policy overrides flow from the dashboard via /v1/governance/policy
  // and are refreshed every ~5 min by the SW alarm.
  const srv = await getCachedServerPolicy();
  cached = mergeServerPolicy(baseline, srv);
  return cached;
}

export function isConfigured(config: ManagedConfig): boolean {
  return Boolean(config.org_id && config.installation_token && config.installation_secret);
}

function mergeConfig(base: ManagedConfig, override: Partial<ManagedConfig>): ManagedConfig {
  return {
    ...base,
    ...override,
    default_policy: {
      ...base.default_policy,
      ...(override.default_policy ?? {}),
    },
    custom_keywords: override.custom_keywords ?? base.custom_keywords,
    domain_overrides: override.domain_overrides ?? base.domain_overrides,
  };
}

export function invalidateConfigCache(): void {
  cached = null;
}

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'managed') {
    invalidateConfigCache();
  }
  if (areaName === 'local' && LOCAL_CONFIG_KEY in changes) {
    invalidateConfigCache();
  }
});

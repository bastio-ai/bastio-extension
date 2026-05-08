// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * Per-install state. Generates a stable install_id on first run and stores it
 * in chrome.storage.local. This drives per-install HMAC key derivation
 * (see hmac.ts).
 */

import type { InstallState } from './types';

const STORAGE_KEY = 'bastio_install_state';

export async function getOrCreateInstallState(): Promise<InstallState> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  const existing = stored[STORAGE_KEY] as InstallState | undefined;
  if (existing?.install_id) return existing;

  const fresh: InstallState = {
    install_id: crypto.randomUUID(),
    external_user_id: crypto.randomUUID(),
    first_run_at: new Date().toISOString(),
  };
  await chrome.storage.local.set({ [STORAGE_KEY]: fresh });
  return fresh;
}

export async function updateInstallState(patch: Partial<InstallState>): Promise<void> {
  const current = await getOrCreateInstallState();
  const next: InstallState = { ...current, ...patch };
  await chrome.storage.local.set({ [STORAGE_KEY]: next });
}

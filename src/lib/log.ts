// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * Debug-gated logger. OFF by default — public extensions should not spam
 * the console of every AI-tool tab the user visits. IT admins can enable
 * verbose logging when diagnosing a deployment by running:
 *
 *   chrome.storage.local.set({ bastio_debug: true })
 *
 * from the extension's service-worker DevTools or via a managed-storage
 * push. The flag is read once per surface (content script, service
 * worker) at module load and cached for the lifetime of that surface.
 */

let DEBUG = false;
let inited = false;

export function initLogging(): Promise<void> {
  if (inited) return Promise.resolve();
  inited = true;
  return chrome.storage.local
    .get('bastio_debug')
    .then((r) => {
      DEBUG = r.bastio_debug === true;
    })
    .catch(() => {
      // Storage unavailable — leave DEBUG off.
    });
}

export function debug(...args: unknown[]): void {
  if (DEBUG) console.info('[bastio]', ...args);
}

export function warn(...args: unknown[]): void {
  // Warnings are operational signals (network failures, HMAC errors).
  // Surface them only when debug is enabled so admins can opt in
  // without leaking noise into shared browsers.
  if (DEBUG) console.warn('[bastio]', ...args);
}

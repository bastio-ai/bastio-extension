// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * HMAC + HKDF using Web Crypto. Per-install key derivation is the security
 * backbone of telemetry auth.
 *
 * hmac_key = HKDF-SHA256(installation_secret, salt=install_id, info="bastio-governance-hmac-v1")
 */

const enc = new TextEncoder();

const HKDF_INFO = 'bastio-governance-hmac-v1';

function base64UrlToBytes(b64url: string): ArrayBuffer {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padding = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const bin = atob(b64 + padding);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function strBytes(s: string): ArrayBuffer {
  const u = enc.encode(s);
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength);
}

function bytesToHex(bytes: ArrayBuffer): string {
  const arr = new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < arr.length; i++) s += arr[i]!.toString(16).padStart(2, '0');
  return s;
}

export async function deriveHmacKey(
  installationSecretB64Url: string,
  installId: string,
): Promise<CryptoKey> {
  const ikm = base64UrlToBytes(installationSecretB64Url);
  const salt = strBytes(installId);
  const info = strBytes(HKDF_INFO);

  const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);

  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    baseKey,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign'],
  );
}

export async function sha256Hex(body: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', strBytes(body));
  return bytesToHex(digest);
}

/**
 * Canonical signed-string form per spec:
 *   {METHOD}\n{path}\n{ts_unix_ms}\n{install_id}\n{sha256_hex(body)}
 */
export async function signRequest(
  key: CryptoKey,
  method: string,
  path: string,
  timestampMs: number,
  installId: string,
  body: string,
): Promise<string> {
  const bodyHash = await sha256Hex(body);
  const canonical = `${method.toUpperCase()}\n${path}\n${timestampMs}\n${installId}\n${bodyHash}`;
  const sig = await crypto.subtle.sign('HMAC', key, strBytes(canonical));
  return bytesToHex(sig);
}

export function buildAuthHeader(
  orgId: string,
  installId: string,
  signatureHex: string,
  timestampMs: number,
): string {
  return `Bastio-HMAC org=${orgId}; install=${installId}; sig=${signatureHex}; ts=${timestampMs}`;
}

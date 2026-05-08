#!/usr/bin/env node
/**
 * Sign the built `dist/` extension into a CRX file using the production
 * private key. Same script used locally and in CI.
 *
 * Inputs:
 *   - `dist/`            : output of `npm run build` (CRX-flavored, with manifest.json + assets)
 *   - PRIVATE_KEY_PATH   : env var pointing at the PEM file (defaults to ./bastio-extension.pem)
 *     OR
 *     PRIVATE_KEY_BASE64 : env var holding the PEM contents base64-encoded (used in CI)
 *   - VERSION            : optional override; otherwise read from dist/manifest.json
 *
 * Outputs:
 *   - `release/bastio-governance-{version}.crx`
 *   - `release/extension-id.txt`           : the public-key-derived extension ID
 *   - prints the extension ID to stdout
 *
 * Run:
 *   PRIVATE_KEY_PATH=./bastio-extension.pem node scripts/sign-crx.cjs
 */

const fs = require('fs');
const path = require('path');
const ChromeExtension = require('crx');

async function main() {
  const distDir = path.resolve(__dirname, '..', 'dist');
  if (!fs.existsSync(path.join(distDir, 'manifest.json'))) {
    fail('dist/manifest.json not found — run `npm run build` first');
  }

  const pem = loadPrivateKey();
  const manifest = JSON.parse(fs.readFileSync(path.join(distDir, 'manifest.json'), 'utf8'));
  const version = process.env.VERSION || manifest.version;
  if (!version) fail('manifest.json has no "version" field');

  const releaseDir = path.resolve(__dirname, '..', 'release');
  fs.mkdirSync(releaseDir, { recursive: true });

  const crx = new ChromeExtension({
    privateKey: pem,
    codebase: process.env.CRX_UPDATE_URL || `https://github.com/bastio-ai/bastio-extension/releases/download/v${version}/bastio-governance-${version}.crx`,
  });

  await crx.load(distDir);
  const buffer = await crx.pack();

  const outPath = path.join(releaseDir, `bastio-governance-${version}.crx`);
  fs.writeFileSync(outPath, buffer);
  console.log(`wrote ${outPath} (${buffer.length} bytes)`);

  // Compute the extension ID from the public key. Chrome's algorithm:
  // SHA-256 of the DER-encoded public key, take first 16 bytes (32 hex chars),
  // map each hex digit 0-f to a-p.
  const pubKeyDer = crx.publicKey;
  const idHex = sha256Hex(pubKeyDer).slice(0, 32);
  const id = idHex
    .split('')
    .map((c) => String.fromCharCode('a'.charCodeAt(0) + parseInt(c, 16)))
    .join('');
  fs.writeFileSync(path.join(releaseDir, 'extension-id.txt'), id + '\n');
  console.log(`extension ID: ${id}`);

  // Emit GitHub Actions output for downstream steps.
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `extension_id=${id}\nversion=${version}\ncrx_path=${outPath}\n`);
  }
}

function loadPrivateKey() {
  if (process.env.PRIVATE_KEY_BASE64) {
    return Buffer.from(process.env.PRIVATE_KEY_BASE64, 'base64');
  }
  const keyPath = process.env.PRIVATE_KEY_PATH || path.resolve(__dirname, '..', 'bastio-extension.pem');
  if (!fs.existsSync(keyPath)) {
    fail(
      `Private key not found at ${keyPath}.\n` +
        `Either set PRIVATE_KEY_PATH=/path/to/key.pem or PRIVATE_KEY_BASE64=<base64-encoded-pem>.\n` +
        `Generate a new key with: openssl genrsa -out bastio-extension.pem 4096`,
    );
  }
  return fs.readFileSync(keyPath);
}

function sha256Hex(buf) {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function fail(msg) {
  console.error('error: ' + msg);
  process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

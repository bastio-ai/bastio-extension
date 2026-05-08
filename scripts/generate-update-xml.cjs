#!/usr/bin/env node
/**
 * Generate Chrome's update manifest. Customers' Chrome browsers fetch this
 * URL on the auto-update schedule (every ~5 hours) to discover new versions.
 *
 * Hosted at: https://cdn.bastio.com/governance/update.xml
 * (or for v1 we just use the GitHub Release asset URL directly).
 *
 * Format reference: https://developer.chrome.com/docs/apps/autoupdate/
 *
 * Inputs:
 *   - VERSION (env)                : the version this XML announces
 *   - EXTENSION_ID (env)           : the 32-char Chrome extension ID
 *   - CRX_URL (env, optional)      : public URL of the CRX. Defaults to the
 *                                    GitHub Release pattern; CI overrides
 *                                    once we have a real CDN.
 */

const fs = require('fs');
const path = require('path');

function main() {
  const version = required('VERSION');
  const extensionID = required('EXTENSION_ID');
  const crxURL =
    process.env.CRX_URL ||
    `https://github.com/bastio-ai/bastio-extension/releases/download/v${version}/bastio-governance-${version}.crx`;

  const xml = `<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='${extensionID}'>
    <updatecheck codebase='${crxURL}' version='${version}' />
  </app>
</gupdate>
`;

  const releaseDir = path.resolve(__dirname, '..', 'release');
  fs.mkdirSync(releaseDir, { recursive: true });
  const outPath = path.join(releaseDir, 'update.xml');
  fs.writeFileSync(outPath, xml);
  console.log(`wrote ${outPath}`);
}

function required(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`error: ${name} env var required`);
    process.exit(1);
  }
  return v;
}

main();

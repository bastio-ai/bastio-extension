# Release runbook — Bastio Governance browser extension

How to ship a new version. Two distribution paths run in parallel: **Chrome Web Store** (self-serve, Google signs) and **self-hosted CRX** (enterprise force-install, we sign).

## One-time setup

### 1. Generate the production signing key

**Do this once, on a secure operator machine — never on a CI runner.** This RSA key is the one thing you can't lose. Lose it and every customer's extension install breaks; you'd ship a "new" extension with a different ID.

```bash
openssl genrsa -out bastio-extension.pem 4096
```

The PEM file is roughly 3.3KB.

### 2. Compute and record the extension ID

Build the extension once, sign with the new key, and read off the ID:

```bash
cd bastio-extension
npm install
npm run build
PRIVATE_KEY_PATH=./bastio-extension.pem node scripts/sign-crx.cjs
cat release/extension-id.txt
```

Save the 32-character ID somewhere durable (1Password vault note, brand wiki, this runbook). Customers' MDM policies reference this ID by literal value.

### 3. Store the key in GitHub Actions

```bash
base64 -i bastio-extension.pem | pbcopy
```

In GitHub → repo Settings → Secrets and variables → Actions → New repository secret:
- Name: `CRX_PRIVATE_KEY_BASE64`
- Value: paste from clipboard

### 4. Move the local PEM to long-term storage

After GitHub has the base64'd copy:

```bash
# Move to 1Password vault as an encrypted attachment, or:
gpg -c bastio-extension.pem    # encrypt with a passphrase
mv bastio-extension.pem.gpg ~/secure-vault/
shred bastio-extension.pem     # securely delete the plaintext
```

The plaintext PEM should never live on a developer laptop unencrypted.

### 5. (Optional) Chrome Web Store credentials

Follow [Chrome Web Store API setup](https://developer.chrome.com/docs/webstore/using-api). Create OAuth client + refresh token. Add four GitHub secrets:

- `WEB_STORE_CLIENT_ID`
- `WEB_STORE_CLIENT_SECRET`
- `WEB_STORE_REFRESH_TOKEN`
- `WEB_STORE_EXTENSION_ID` (Web Store assigns its own ID — different from the self-hosted ID)

When all four are set, releases auto-publish to the Web Store. Self-hosted CRX always ships regardless.

## Cutting a release

1. Bump the version in `bastio-extension/manifest.json` (semver, e.g. `0.1.0` → `0.2.0`).
2. Commit + push to main.
3. Tag the commit:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

4. The `release.yml` workflow runs automatically. ~3 minutes.
5. Check the run output. The summary tab shows the extension ID, CRX filename, and the hosted-policy update.xml URL.
6. Find the new GitHub Release at [releases](https://github.com/bastio-ai/bastio-extension/releases) — `.crx`, web-store `.zip`, `update.xml`, and `extension-id.txt` attached.
7. If Web Store secrets are configured, the listing publishes automatically (Google reviews can still take 1-4 weeks before the listing appears live).

## Telling customers how to install

### Self-serve (Chrome Web Store)

Once the listing is live: send the Chrome Web Store URL.

### Enterprise (Chrome Enterprise hosted policy)

In Google Admin Console → Devices → Chrome → Apps & Extensions → Force-install:

```json
{
  "ExtensionInstallForcelist": [
    "<EXTENSION_ID>;https://github.com/bastio-ai/bastio-extension/releases/latest/download/update.xml"
  ]
}
```

Replace `<EXTENSION_ID>` with the value from `release/extension-id.txt`.

### Enterprise (Intune / Jamf)

The MDM bundle generated from the bastio dashboard (governance → installations → Generate MDM bundle) includes pre-filled Intune ADMX/ADML and Jamf `.mobileconfig` artifacts. The dashboard reads the current published extension ID from the OSS server's installation_secret store; until that's wired, edit the bundle's templates with the published ID before pushing.

## Rotating the signing key (only if compromised)

A key rotation is a **breaking change for every existing install** — Chrome refuses to update across keys. Plan this as an extension-rebuild + re-deployment.

1. Generate a new key (step 1 above).
2. Note the new extension ID (step 2).
3. Update `CRX_PRIVATE_KEY_BASE64` in GitHub.
4. Email every customer with the new ID + new MDM bundle. Communicate ~30 days ahead.
5. Cut a new release. The new `update.xml` lives at the new release tag.
6. Customers re-push their MDM policies with the new ID.
7. Old installs eventually wither. Document the deprecated ID so support recognizes calls about the old extension.

## Rolling back a bad release

CRX auto-update only goes forward. To "roll back":

1. Cut a new patch release with the previous code (e.g., 0.2.1 = 0.2.0 + version bump).
2. Push the tag. Workflow auto-publishes.
3. Browsers fetch the new (older-code) version on next update poll.

There is no "revert release" — Chrome won't downgrade.

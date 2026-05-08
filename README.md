# Bastio Governance — Browser Extension

> Audit Shadow AI usage and intercept sensitive data before it reaches public AI tools.

A Manifest V3 browser extension for Chrome and Edge that detects PII, credentials, and source code in the input fields of public AI tools — ChatGPT, Claude, Gemini, Copilot, Perplexity, and 13 others — blocks the send when policy says no, and reports each event with **metadata only** (never prompt content) to a backend you operate.

Built for IT-driven rollouts: pushed to managed Chrome / Edge fleets via Chrome Enterprise, Microsoft Intune, or Jamf, configured per-org through `chrome.storage.managed`, and signed with an enterprise CRX key for stable, force-installable updates.

> **Status:** `v0.1.0` — initial public release. The detection corpus and performance tests are stable, but the configuration surface and event schema may shift before `v1.0`. Pin to a tagged release rather than tracking `main`.

## Highlights

- **Local-first detection.** Three layers of client-side rules — PII regex with format validators, secret-prefix patterns plus Shannon entropy, code blocks plus customer keywords — run inline on every keystroke. The optional server-side classifier is an enrichment pass, not a gate.
- **Sub-30ms per send.** A perf test in the repo guards the detection budget; the corpus runs end-to-end under one millisecond on commodity hardware.
- **Block + redirect.** When policy fires, the user sees a localized modal (EN, DE, FR, ES, NL) and an optional one-click redirect to the company-approved AI tool — Bastio Workspace, an internal proxy, LibreChat, Open WebUI, or any URL you configure.
- **Per-install HMAC.** Each install derives its own HMAC signing key via HKDF-SHA256 from an IDP-pushed secret plus a per-install salt. Compromise of one install does not compromise the org.
- **MV3 native.** A single service worker plus `chrome.alarms` drive the outbox drain and heartbeat. No background page, no persistent processes, no JS in the host page's world.

## Privacy

**Prompt content never leaves the extension.**

The content script reads input text only to run local detection and decide whether to allow the send. Telemetry payloads carry:

- `rule_ids` (e.g. `pii.email`, `secret.aws_access_key`)
- `severity` (`low` / `medium` / `high`)
- `source_domain` (e.g. `chatgpt.com`)
- `char_count_intercepted`
- `action` (`logged`, `warned`, `blocked`, `redirected`, `overridden`)
- browser + extension version
- per-install HMAC signature

Never the text itself.

The optional Layer 4 server-side classifier is the one path that touches an excerpt: when the bastio backend has a Microsoft Presidio analyzer configured (`PRESIDIO_URL`), the content script forwards an excerpt of up to 8KB over TLS to the backend, which forwards it to Presidio in-network. Backends without Presidio fall back to a regex + entropy heuristic; in that mode no excerpt leaves the extension.

## Supported AI tools

ChatGPT, Claude.ai, Gemini, Copilot, Bing Chat, Perplexity, Character.ai, Poe, Mistral, You.com, Hugging Face, Meta AI, DeepSeek, Phind. The full list — 18 hosts — lives in [`manifest.json`](./manifest.json) under `content_scripts.matches`. Adding more is one entry there plus a matching `host_permissions` line.

## Install

### Self-hosted enterprise rollout (recommended for fleets)

1. Generate or import a CRX signing key. Full instructions in [RELEASE.md](./RELEASE.md).
2. Build and sign locally:
   ```bash
   npm install
   npm run release          # build + sign in one step
   ```
   This writes `dist/` and a signed `.crx` to `release/`.
3. Host the resulting `.crx` and `update.xml` on a private URL or attach them to a GitHub Release.
4. Force-install the extension via your MDM:
   - **Chrome Enterprise:** [`ExtensionInstallForcelist`](https://chromeenterprise.google/policies/) policy pointing at your `update.xml`.
   - **Microsoft Intune:** Force-install through the Edge or Chrome ADMX template.
   - **Jamf:** Distribute the bundled `.mobileconfig`.
5. Push the org config (backend URL, installation secret, redirect target) via `chrome.storage.managed`. Schema: [`public/managed-schema.json`](./public/managed-schema.json).

### Chrome Web Store (self-serve)

In submission. Track the [GitHub Releases](https://github.com/bastio-ai/bastio-extension/releases) page for the published Web Store link once it lands.

## Configure

In production, IT pushes the org config through MDM into `chrome.storage.managed`. The schema is canonical at [`public/managed-schema.json`](./public/managed-schema.json); a complete example:

```json
{
  "backend_url": "https://api.bastio.com",
  "org_id": "01J...",
  "installation_token": "<one-time token issued by your bastio backend>",
  "installation_secret": "<base64url 32-byte secret>",
  "default_policy": { "low": "log", "medium": "warn", "high": "block_redirect" },
  "custom_keywords": ["internal-only", "FY26-roadmap"],
  "domain_overrides": [],
  "override_enabled": true,
  "telemetry_endpoint": "/v1/governance/events",
  "redirect_target": {
    "url": "https://workspace.bastio.com",
    "label": "Bastio Workspace",
    "open_in_new_tab": true
  }
}
```

`custom_keywords` are case-insensitive substrings that fire `keyword.custom` at `low` severity — use them for project codenames, classification labels, or anything else specific to your org. `redirect_target` is the URL the modal's primary button sends the user to when policy fires; point it at whatever sanctioned AI tool your team actually uses.

In production, **enterprise installs** push config via `chrome.storage.managed` (read-only at runtime) — that path is unchanged.

For **self-serve installs** (Chrome Web Store) and **local development**, the extension also reads from `chrome.storage.local` under the key `bastio_local_config`. Two writers populate it:

- **Self-serve onboarding flow** — the popup's "Connect to Bastio" button hits `POST /v1/governance/extension/claim`, opens the dashboard's connect URL, and polls until the user confirms; on success the credentials are written here automatically.
- **Manual dev seed** — paste the same JSON shape directly from the SW DevTools console:

```js
chrome.storage.local.set({
  bastio_local_config: { /* the JSON above */ }
})
```

When `bastio_local_config` is present, it wins over managed config. The cache invalidates automatically when the key changes — reload the AI-tool tab to pick up edits. Enterprise deployments never touch this key, so behaviour in MDM-managed installs is unaffected.

If you run [Bastio Cloud](https://bastio.com), the dashboard generates this JSON for you as a downloadable MDM bundle. Self-hosted backends issue their own `installation_token` and `installation_secret` and push the JSON via existing MDM tooling.

### Debug logging

The extension is silent in production. Admins diagnosing a deployment can flip a flag from the extension's service-worker DevTools console:

```js
chrome.storage.local.set({ bastio_debug: true })
```

Reload the page to pick up the change. Set the key back to `false` (or remove it) to silence again.

## Detection — four layers

1. **Layer 1 — PII regex with format validators.** Email, phone (NANP and E.164), US SSN, Danish CPR, IBAN with mod-97 check, credit card with Luhn check (12-19 digits), US and UK passport.
2. **Layer 2 — secret-prefix patterns plus entropy fallback.** AWS access keys, GitHub PAT, Stripe, Slack, OpenAI, OpenAI project keys, Anthropic, Google API, JWT, SSH private key headers, Azure storage keys, MongoDB connection strings, Twilio, SendGrid, and a Shannon-entropy catch-all (≥ 4.5) for unknown high-entropy tokens.
3. **Layer 3 — code blocks plus customer rules.** Fenced code blocks, clustered code keywords (≥ 2 hits across `function` / `class` / `import` / SQL DML / etc.), customer-supplied keywords from the managed config.
4. **Layer 4 — server-side classifier (async).** When `PRESIDIO_URL` is set on the bastio backend, an excerpt (≤ 8KB) goes to Microsoft Presidio for trained-model PII detection. Otherwise a regex + entropy heuristic. The local block decision has already happened in under 30ms — Layer 4 only enriches the dashboard event with higher-quality severity and reasoning. p95 budget < 500ms; responses past the budget are dropped (no UX impact).

The detection corpus and false-positive baselines live in [`src/content/detector.test.ts`](./src/content/detector.test.ts) — 111 cases across known-bad, benign, and perf scenarios. Catch-rate target: 100% on known-bad. False-positive target: < 5% on the benign corpus.

## Develop

```bash
npm install
npm run dev           # rebuild on file changes
npm run build         # production build → ./dist
npm run typecheck     # tsc --noEmit
npm test              # 111 detection corpus tests, bun
```

Load `dist/` as an unpacked extension in `chrome://extensions` (Developer mode → Load unpacked).

For local QA, seed `chrome.storage.local['bastio_local_config']` from the service-worker DevTools console using the JSON shape under [Configure](#configure) above. The detector corpus (`npm test`) covers detection accuracy; for end-to-end policy modal + telemetry verification, run an OSS [Bastio backend](https://github.com/bastio-ai/bastio) locally and point `backend_url` at it.

### Architecture

```
src/
├── background/
│   └── service-worker.ts    # MV3 worker; alarms drive outbox + heartbeat
├── content/
│   ├── content.ts           # Entry: wires watcher → detector → modal → telemetry
│   ├── detector.ts          # Layers 1-3 (regex + secrets + code + keywords)
│   ├── detector.test.ts     # 111 corpus tests (known-bad + benign + perf)
│   ├── dom-watcher.ts       # Input observation + send-action interception
│   └── block-modal.ts       # Policy modal (closed shadow DOM, vanilla, localized)
├── lib/
│   ├── types.ts             # Shared types
│   ├── config.ts            # chrome.storage.managed loader
│   ├── install-state.ts     # Per-install identity (install_id, external_user_id)
│   ├── hmac.ts              # Web Crypto HMAC + HKDF (per-install key)
│   ├── i18n.ts              # Typed wrapper around chrome.i18n.getMessage
│   ├── log.ts               # Debug-gated logger (off by default)
│   └── telemetry.ts         # Event POST + outbox + classifier proxy + heartbeat
├── popup/                   # Toolbar popup (status + queue depth)
└── options/                 # Options page (read-only config view)

public/_locales/             # MV3 i18n: EN, DE, FR, ES, NL
public/managed-schema.json   # JSON Schema for chrome.storage.managed
```

## Localization

Chrome MV3 i18n. Five locales today (EN, DE, FR, ES, NL). Add more by dropping `messages.json` into `public/_locales/{locale}/`. Chrome resolves the user's browser language at install time. Typed lookup via [`src/lib/i18n.ts`](./src/lib/i18n.ts).

## Releasing

The release workflow is automated on tag push. Distribution lands in two channels:

- **Self-hosted CRX** — force-installable via Chrome Enterprise / Intune / Jamf, signed with the project's private RSA key, hosted on GitHub Releases with an `update.xml` manifest for auto-updates.
- **Chrome Web Store** — Google-signed, self-serve install. Pushed automatically when the four OAuth secrets are configured in the repo's GitHub Secrets.

```bash
# bump manifest.json version, commit, then:
git tag v0.2.0
git push origin v0.2.0
```

The `.github/workflows/release.yml` workflow handles build, sign, and publish. Full runbook covering signing-key generation, GitHub Secrets, rotation, and rollback is in [RELEASE.md](./RELEASE.md).

## License

[FSL-1.1-ALv2](./LICENSE) — Functional Source License, Apache 2.0 Future. Detection rules, default policy, managed-storage schema, and the entire extension client are public. Same license as the [Bastio OSS gateway](https://github.com/bastio-ai/bastio).

The Cloud-side trained classifier — Microsoft Presidio with proprietary thresholds — stays managed. Self-hosted deployments can run Presidio themselves, or rely on the regex + entropy heuristic, with no functional gap on the extension client.

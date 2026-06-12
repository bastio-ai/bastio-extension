# Chrome Web Store Listing — Bastio Governance

Everything the Web Store "Store listing" + "Privacy" tabs need, in one
place. Copy-paste from here when filling the dashboard. Screenshots are
tracked in `store/screenshots/` (see plan at the bottom).

## Basic info

| Field | Value |
|---|---|
| Name | Bastio Governance |
| Category | Productivity → Workflow & Planning (alt: Tools) |
| Language | English (US) — 4 more locales ship in-extension (DE, FR, ES, NL) |
| Summary (132 chars max) | Stop sensitive data from reaching ChatGPT, Claude & 16 other AI tools. Local detection, metadata-only reporting, IT-managed. |

## Description

> **See and govern Shadow AI usage across your team — without reading anyone's prompts.**
>
> Bastio Governance detects PII, credentials, and source code in the input fields of 18 public AI tools (ChatGPT, Claude, Gemini, Copilot, Perplexity, and more) and applies your organization's policy: log it, warn, block the send, or redirect to your approved AI tool.
>
> **Private by design**
> • Detection runs locally in your browser — prompt text never leaves the device
> • Reports metadata only: which rule fired, severity, domain, character count, action taken
> • Events go to YOUR organization's server (self-hosted Bastio OSS or Bastio Cloud) — never to third parties
>
> **Built for IT**
> • Deploy via Chrome Enterprise, Microsoft Intune, or Jamf with managed configuration
> • Per-install HMAC authentication — compromise of one install never compromises the fleet
> • SCIM 2.0 user sync, policy updates within 5 minutes, localized UI (EN, DE, FR, ES, NL)
>
> **Fast**
> • Sub-30ms detection budget, enforced by performance tests
> • Manifest V3 native: no background page, no persistent processes
>
> **Getting started**
> • IT-managed: push the extension + managed config from your MDM — zero user setup
> • Self-serve: install, click "Connect to Bastio," and link it to your Bastio server or free trial
>
> Start with a free 14-day Shadow AI Audit: deploy in log-only mode and get a report of which AI tools your team actually uses — before deciding what to block. Learn more at https://bastio.com.

## Single purpose statement (Privacy tab)

> The extension's single purpose is AI-usage governance: detecting sensitive content (PII, credentials, source code) typed into public AI tools and applying the organization's allow/warn/block/redirect policy, with metadata-only reporting to the organization's own server.

## Permission justifications (Privacy tab)

| Permission | Justification |
|---|---|
| `storage` | Stores org policy/config (managed storage), self-serve enrollment, and the undelivered-event queue. |
| `alarms` | Drives the periodic event-queue drain, heartbeat, and 5-minute policy refresh in the MV3 service worker. |
| Host permissions (18 named AI domains) | Detection only works on AI tool pages; each host is an AI assistant the org governs. The block/redirect modal is rendered by the statically declared content script (shadow DOM) — no `activeTab`/`scripting` needed or requested. No `<all_urls>`. |
| Host permission (api.bastio.com / org server) | Delivers metadata events, heartbeats, and policy fetches to the organization's reporting endpoint from the service worker. |

> History: the 2026-05-08 rejection ("Purple Potassium") was for requesting
> `scripting` without using it. `scripting` AND `activeTab` were both removed
> in v0.1.1 — neither is needed with statically declared content scripts.
> Keep this table in lockstep with manifest.json `permissions` on every
> submission.

## Data-use disclosures (Privacy tab checkboxes)

- Collects: "Website content" → **No** (text is read locally; only counts/rule IDs leave) — disclose "User activity: No", "Web history: No".
- Collects: "Personally identifiable information" → **No** (events are metadata; the per-install ID identifies the browser install, not the person — but if Legal prefers the conservative answer, declare the install identifier under "Authentication information: No / Unique identifiers: Yes").
- Certify: not sold to third parties; not used/transferred for purposes unrelated to the single purpose; not used for creditworthiness.
- Privacy policy URL: `https://bastio.com/legal/extension-privacy` (LIVE — deployed 2026-06-12, mirrors PRIVACY_POLICY.md; keep in sync).

## Screenshots plan (`store/screenshots/`, 1280×800 PNG)

1. **Block modal** on chatgpt.com — detector caught an AWS key mid-prompt; modal shows policy message + "Open approved tool" redirect button.
2. **Popup** — connected state: server URL, policy version, events queued/delivered, "Run audit" status.
3. **Options page** — read-only managed config view (org name, policy source, endpoint).
4. **Dashboard fleet view** (cloud.bastio.com Governance tab) — installs, events-by-domain chart, top rules. Shows the "where the data goes" story.

Promo tile (440×280) + marquee (1400×560): dark background per `.work/DESIGN.md`, cyan accent, headline "Govern Shadow AI" + the block-modal screenshot fragment.

## Submission checklist

- [x] Host PRIVACY_POLICY.md → live at https://bastio.com/legal/extension-privacy (2026-06-12)
- [ ] Verify publisher domain (bastio.com) in the Web Store dashboard
- [ ] Capture 4 screenshots + 2 promo images
- [ ] Web Store OAuth secrets in GitHub repo secrets (`WEB_STORE_CLIENT_ID`, `WEB_STORE_CLIENT_SECRET`, `WEB_STORE_REFRESH_TOKEN`, `WEB_STORE_EXTENSION_ID`) — RELEASE.md §4 step 5
- [ ] Self-serve onboarding e2e (popup "Connect to Bastio" → claim → poll → connected)
- [ ] Tag a release → `.github/workflows/release.yml` builds, signs, uploads

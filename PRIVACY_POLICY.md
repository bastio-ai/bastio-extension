# Privacy Policy — Bastio Governance Browser Extension

**Effective date:** 2026-06-11
**Applies to:** the "Bastio Governance" extension for Chrome and Edge (the "Extension"), published by Bastio ("we", "us").

The Extension helps organizations audit Shadow AI usage and prevent sensitive data (PII, credentials, source code) from being submitted to public AI tools. It is designed for deployment by an employer or IT administrator to managed browsers, and for self-serve use connected to a Bastio server.

## The short version

- **Prompt content never leaves your browser** in the Extension's default configuration. Detection runs locally.
- The Extension reports **metadata-only events** to the server your organization operates (or to Bastio Cloud, if that is what your organization connected it to). It does not send data to anyone else.
- We — Bastio the publisher — receive nothing from your install unless your organization's reporting endpoint is Bastio Cloud.

## What the Extension processes locally

On the AI tool websites listed in its manifest (e.g. chatgpt.com, claude.ai, gemini.google.com — 18 hosts total), the Extension reads the text of the input field as you type, **inside your browser only**, to run rule-based detection for PII, secrets, and source code. This text is not stored and not transmitted, with the single optional exception described under "Layer 4 classifier" below.

The Extension does not read pages outside those AI tool hosts, does not collect browsing history, and does not track you across sites.

## What the Extension transmits

When a detection or policy event occurs, the Extension sends an event to the reporting endpoint configured by your organization (a Bastio server they operate, or api.bastio.com for Bastio Cloud customers). Each event contains:

- the rule identifiers that fired (e.g. `pii.email`, `secret.aws_access_key`)
- severity (`low` / `medium` / `high`)
- the AI tool domain involved (e.g. `chatgpt.com`)
- the character count of the intercepted text (a number — not the text)
- the action taken (`logged`, `warned`, `blocked`, `redirected`, `overridden`)
- browser and Extension version
- a per-install identifier and HMAC signature (used to authenticate the event; derived locally via HKDF-SHA256)

The Extension also sends a periodic heartbeat (install identifier, version, configuration checksum) so administrators can see the deployment is healthy.

**Layer 4 classifier (optional, organization-controlled):** if your organization's server has a trained PII classifier configured (Microsoft Presidio), the Extension forwards an excerpt of the typed text (up to 8 KB) to **that server** over TLS for analysis. This is off unless your organization's server enables it. The excerpt goes only to the configured reporting endpoint, never to Bastio or any third party. Without this setting, no text ever leaves the browser.

## What we do NOT collect

- No prompt or conversation content (except the optional, organization-controlled classifier excerpt above — and then only to your organization's endpoint)
- No keystrokes or page content outside the supported AI tool input fields
- No browsing history, no cookies, no advertising identifiers
- No selling or sharing of data with third parties, ever

## Storage

Configuration (policy, endpoint, enrollment) is stored in `chrome.storage.managed` (pushed by your IT administrator) or `chrome.storage.local` (self-serve setup). Undelivered events are queued locally and deleted once delivered. Uninstalling the Extension removes all locally stored data.

## Who is responsible for the data

Event data is sent to and retained by the server your organization configured. For organization-managed deployments, your employer is the data controller for that telemetry, and their retention and access policies apply — contact your IT administrator for details. When the endpoint is Bastio Cloud, Bastio processes the metadata on your organization's behalf as a processor.

## Limited Use

Our use of information received from Google APIs and the Chrome platform adheres to the [Chrome Web Store User Data Policy](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq), including its Limited Use requirements. The Extension's single purpose is detecting and governing sensitive content submitted to AI tools; all data handling described above serves only that purpose.

## Changes and contact

We will update this policy as the Extension evolves; material changes are noted in the Extension's release notes. Questions: **privacy@bastio.com**, or Bastio, https://bastio.com.

// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * Content-script entrypoint. Wires the DOM watcher to the detector and modal.
 *
 * Runs on every public AI-tool domain listed in manifest.json. Reads the org
 * managed-storage config; if not configured (i.e. self-serve install before IT push),
 * the extension is silent.
 */

import { getConfig, isConfigured } from '../lib/config';
import { getOrCreateInstallState } from '../lib/install-state';
import { debug, initLogging } from '../lib/log';
import { classify, recordEvent } from '../lib/telemetry';
import type { GovernanceEvent, Severity } from '../lib/types';
import { bumpVolume } from '../lib/volume';
import { detect, ruleSummary } from './detector';
import { showBlockModal } from './block-modal';
import { startWatcher } from './dom-watcher';

const SOURCE_DOMAIN = location.hostname;

void main();

async function main(): Promise<void> {
  await initLogging();
  debug('content script loaded on', location.hostname);
  const config = await getConfig();
  if (!isConfigured(config)) {
    debug('not configured — extension idle');
    return;
  }
  debug('configured, backend=', config.backend_url);
  const state = await getOrCreateInstallState();

  startWatcher({
    isSensitive: (text) => {
      // Synchronous gate the doc-level pointer-intercept uses to
      // decide whether to engage. Only return true when the policy
      // action would actually surface a UI (block or warn). For
      // 'log' severity (silent record), we let the click flow
      // through naturally — preventing the click would force a
      // re-dispatch and risk recursion if multiple content-script
      // instances are alive.
      const r = detect(text, { customKeywords: config.custom_keywords });
      if (r.highest_severity === null) return false;
      const action = config.default_policy[r.highest_severity];
      return action === 'block_redirect' || action === 'warn';
    },
    onPreview: (text) => {
      // Fire-and-forget: warm classifier + cache results. Local detection is what
      // actually gates the block at send-time.
      const layer123 = detect(text, { customKeywords: config.custom_keywords });
      debug('preview text=', text.length, 'chars severity=', layer123.highest_severity, 'rules=', layer123.rule_ids);
      if (layer123.highest_severity === 'high' || layer123.highest_severity === 'medium') {
        void classify({
          text_excerpt: text.slice(0, 4000),
          layer_3_hits: layer123.rule_ids,
          source_domain: SOURCE_DOMAIN,
        });
      }
    },
    onSendComplete: async (text) => {
      // Fires when a tracked input transitions from non-empty → empty —
      // a strong signal the host page just submitted the user's prompt.
      // This is the path that records benign sends in tracking_mode
      // 'volume' / 'full' WITHOUT preventDefault'ing the host's handler.
      //
      // For sensitive content onSendIntercept already ran (volume bump +
      // policy-event record), so we re-detect here and no-op when the
      // text was sensitive — avoids double-counting on the override path.
      const cfg = await getConfig();
      const mode = cfg.tracking_mode ?? 'policy';
      debug('send-complete tracking_mode resolved as', mode);
      if (mode === 'policy') return;

      const r = detect(text, { customKeywords: cfg.custom_keywords });
      if (r.highest_severity !== null) return;

      void bumpVolume(SOURCE_DOMAIN);
      if (mode === 'full') {
        await recordEvent(
          buildEvent({
            severity: 'low',
            ruleIds: [],
            action: 'observed',
            charCount: text.length,
            installUserId: state.external_user_id,
          }),
        );
      }
    },
    onSendIntercept: async (text, _target) => {
      debug('send intercepted, text=', text.length, 'chars');
      // Re-resolve config so dashboard policy changes (tracking_mode,
      // default_policy) propagate without requiring an AI-tool tab
      // refresh. getConfig() is cached and invalidated by the policy
      // fetcher when the server response changes, so this is cheap on
      // the hot path.
      const config = await getConfig();
      // Volume rollup runs ahead of detection: the CISO chart counts
      // attempted Shadow AI usage, which includes blocks/warns/overrides
      // and not just benign sends. Skipped in 'policy' mode for privacy.
      const mode = config.tracking_mode ?? 'policy';
      debug('tracking_mode resolved as', mode);
      if (mode === 'volume' || mode === 'full') {
        void bumpVolume(SOURCE_DOMAIN);
      }

      const result = detect(text, { customKeywords: config.custom_keywords });
      const severity = result.highest_severity;
      if (severity === null) {
        // No detection hit. Mode 'full' also emits a per-send event
        // with action='observed' for forensic / IR fidelity. Modes
        // 'policy' and 'volume' stay silent on individual benign sends.
        if (mode === 'full') {
          await recordEvent(
            buildEvent({
              severity: 'low',
              ruleIds: [],
              action: 'observed',
              charCount: text.length,
              installUserId: state.external_user_id,
            }),
          );
        }
        return true;
      }

      const policyAction = config.default_policy[severity];

      if (policyAction === 'log') {
        await recordEvent(
          buildEvent({
            severity,
            ruleIds: result.rule_ids,
            action: 'logged',
            charCount: text.length,
            installUserId: state.external_user_id,
          }),
        );
        return true;
      }

      if (policyAction === 'warn') {
        const choice = await showBlockModal({
          rule_summary: ruleSummary(result.rule_ids),
          source_domain: SOURCE_DOMAIN,
          override_enabled: true,
        });
        const action =
          choice.action === 'cancel'
            ? 'warned'
            : choice.action === 'override'
              ? 'overridden'
              : 'warned';
        await recordEvent(
          buildEvent({
            severity,
            ruleIds: result.rule_ids,
            action,
            charCount: text.length,
            installUserId: state.external_user_id,
            overrideJustification: choice.override_justification,
          }),
        );
        return choice.action === 'override';
      }

      // policyAction === 'block_redirect'
      const choice = await showBlockModal({
        rule_summary: ruleSummary(result.rule_ids),
        source_domain: SOURCE_DOMAIN,
        redirect_target: config.redirect_target,
        override_enabled: config.override_enabled,
      });

      if (choice.action === 'redirect' && config.redirect_target) {
        const target = config.redirect_target;
        await recordEvent(
          buildEvent({
            severity,
            ruleIds: result.rule_ids,
            action: 'redirected',
            charCount: text.length,
            installUserId: state.external_user_id,
            redirectLabel: target.label,
          }),
        );
        if (target.open_in_new_tab) {
          window.open(target.url, '_blank', 'noopener,noreferrer');
        } else {
          location.href = target.url;
        }
        return false;
      }

      if (choice.action === 'override') {
        await recordEvent(
          buildEvent({
            severity,
            ruleIds: result.rule_ids,
            action: 'overridden',
            charCount: text.length,
            installUserId: state.external_user_id,
            overrideJustification: choice.override_justification,
          }),
        );
        return true;
      }

      // cancel
      await recordEvent(
        buildEvent({
          severity,
          ruleIds: result.rule_ids,
          action: 'blocked',
          charCount: text.length,
          installUserId: state.external_user_id,
        }),
      );
      return false;
    },
  });
}

interface BuildEventOpts {
  severity: Severity;
  ruleIds: string[];
  action: GovernanceEvent['action'];
  charCount: number;
  installUserId: string;
  redirectLabel?: string;
  overrideJustification?: string;
}

function buildEvent(opts: BuildEventOpts): GovernanceEvent {
  const ua = navigator.userAgent;
  const browser: GovernanceEvent['browser'] = /Edg\//.test(ua)
    ? 'edge'
    : /Chrome\//.test(ua)
      ? 'chrome'
      : 'unknown';
  const versionMatch = /(Edg|Chrome)\/([0-9.]+)/.exec(ua);
  const event: GovernanceEvent = {
    event_id: crypto.randomUUID(),
    user_id: opts.installUserId,
    occurred_at: new Date().toISOString(),
    source_domain: SOURCE_DOMAIN,
    rule_ids: opts.ruleIds,
    severity: opts.severity,
    action: opts.action,
    char_count_intercepted: opts.charCount,
    browser,
    browser_version: versionMatch?.[2] ?? 'unknown',
    extension_version: chrome.runtime.getManifest().version,
    // Origin only — never location.pathname (chat titles leak into
    // ChatGPT URLs like /c/<title>). Timezone and language come from
    // browser-resolved values; both are public per-tab info, no PII.
    url_origin: location.origin,
    client_timezone: tryResolveTimezone(),
    client_language: navigator.language || '',
  };
  if (opts.redirectLabel) event.redirect_target_label = opts.redirectLabel;
  if (opts.overrideJustification) event.override_justification = opts.overrideJustification;
  return event;
}

// Best-effort IANA timezone string. Wrapped in try/catch because some
// embedded browsers (rare) throw on Intl.DateTimeFormat construction.
function tryResolveTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || '';
  } catch {
    return '';
  }
}

// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * Shared types for the Bastio Governance extension.
 */

export type Severity = 'low' | 'medium' | 'high';

export type Action =
  | 'logged'
  | 'warned'
  | 'blocked'
  | 'redirected'
  | 'overridden'
  // 'observed' fires only in tracking_mode='full': a send to a public AI
  // tool that hit no detection rule. Same metadata-only payload as the
  // policy-relevant actions, never carries prompt content.
  | 'observed';

// Tracking mode controls which sends generate telemetry events:
//   - 'policy' (default): only policy-relevant sends (logged / warned /
//     blocked / redirected / overridden). Lowest privacy footprint and
//     ClickHouse volume; matches the v0.1 baseline.
//   - 'volume': adds aggregate counts of every send to public AI tools,
//     bucketed by source_domain and flushed every few minutes via the
//     /v1/governance/volume endpoint. Per-event detail stays gated to
//     policy-relevant actions. Powers the "12,000 prompts to ChatGPT
//     this month" CISO chart without 10× ClickHouse blowup.
//   - 'full': emits an `observed` event per benign send IN ADDITION to
//     the volume rollup. Highest fidelity, heaviest cost — for forensic
//     / IR deployments.
export type TrackingMode = 'policy' | 'volume' | 'full';

export type DetectorKind =
  | 'pii'
  | 'secret'
  | 'code'
  | 'keyword'
  | 'regex_pack'
  | 'classifier';

export interface DetectionRule {
  id: string;
  kind: DetectorKind;
  description: string;
  severity: Severity;
}

export interface DetectionHit {
  rule_id: string;
  kind: DetectorKind;
  severity: Severity;
  excerpt_offset: number;
  excerpt_length: number;
}

export interface DetectionResult {
  hits: DetectionHit[];
  highest_severity: Severity | null;
  rule_ids: string[];
}

export interface RedirectTarget {
  url: string;
  label: string;
  open_in_new_tab: boolean;
  carry_over_supported?: boolean;
}

export interface PolicyConfig {
  low: 'log' | 'warn' | 'block_redirect';
  medium: 'log' | 'warn' | 'block_redirect';
  high: 'log' | 'warn' | 'block_redirect';
}

export interface ManagedConfig {
  backend_url: string;
  org_id: string;
  installation_token: string;
  installation_secret: string;
  default_policy: PolicyConfig;
  custom_keywords: string[];
  domain_overrides: string[];
  override_enabled: boolean;
  telemetry_endpoint: string;
  // Defaults to 'policy' when absent (v0.1 baseline). Older managed
  // configs that predate this field stay on the lowest-footprint mode.
  tracking_mode?: TrackingMode;
  redirect_target?: RedirectTarget;
}

// Wire payload for the /v1/governance/volume endpoint. One row per
// (source_domain, window) pair; the window edges anchor the count to
// a real-time slice for the dashboard's volume charts.
export interface VolumeRollup {
  window_start: string; // ISO 8601
  window_end: string;   // ISO 8601
  by_domain: Record<string, number>;
}

export interface GovernanceEvent {
  event_id: string;
  user_id: string;
  occurred_at: string;
  source_domain: string;
  rule_ids: string[];
  severity: Severity;
  action: Action;
  char_count_intercepted: number;
  browser: 'chrome' | 'edge' | 'unknown';
  browser_version: string;
  extension_version: string;
  redirect_target_label?: string;
  override_justification?: string;
  // Request-metadata enrichment. URL origin only — never the path,
  // since chat conversation titles can leak into pathnames on tools
  // like ChatGPT (`/c/<conversation-name>`). Timezone + language come
  // from browser-resolved values, no PII.
  url_origin?: string;
  client_timezone?: string;
  client_language?: string;
}

export interface ClassifyRequest {
  text_excerpt: string;
  layer_3_hits: string[];
  source_domain: string;
}

export interface ClassifyResponse {
  severity: Severity;
  confidence: number;
  reasoning: string;
}

export interface InstallState {
  install_id: string;
  external_user_id: string;
  first_run_at: string;
  last_heartbeat_at?: string;
  policy_etag?: string;
  domain_list_etag?: string;
}

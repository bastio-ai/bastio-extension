// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * Detection engine. Three client-side layers:
 *
 * Layer 1: regex/format detectors (PII)
 * Layer 2: secrets detectors
 * Layer 3: code blocks + customer keywords + customer regex packs
 *
 * Layer 4 (server-side ML classifier) is fired async from the content script and
 * can promote severity post-hoc but never gates the block decision.
 *
 * NO PROMPT CONTENT IS SENT IN TELEMETRY. The detector returns rule_ids + severity
 * + char count. Excerpt offsets stay local and are dropped before transmission.
 */

import type {
  DetectionHit,
  DetectionResult,
  DetectionRule,
  Severity,
} from '../lib/types';

// ============================================================
// Layer 1: PII / format detectors
// ============================================================

const RX_EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const RX_US_PHONE = /\b(\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
// E.164 — `\b` before `+` doesn't fire because both are non-word; use a
// negative lookbehind for word/digit so we still anchor the start.
const RX_E164_PHONE = /(?<![\w+])\+[1-9]\d{6,14}\b/g;
const RX_US_SSN = /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
// Danish CPR (personnummer) — DDMMYY-XXXX. We validate format and
// date plausibility (day 01-31, month 01-12) but skip the mod-11
// checksum: Denmark retired the strict checksum in 2007 so newer
// numbers don't all comply, and false-negatives matter more than
// false-positives in a security gate.
// Danish CPR (personnummer). Three accepted shapes:
//   190987-2231       canonical (hyphen separator)
//   1909872231        hyphenless (common in form fields and pasted DBs)
//   19 09 87 2231     space-separated (frequently seen in scanned documents)
//
// Validation: DD anchored to a real day (01-31) — that's the constraint
// that keeps these from matching every 10-digit phone number / order ID.
// We deliberately DON'T enforce a valid month range (01-12), because
// real-world customer pastes regularly contain typo'd CPRs and an audit
// tool should flag anything that looks like one rather than miss the
// typos. False-positive risk is acceptable for a security-first posture.
const RX_DK_CPR = /\b(0[1-9]|[12]\d|3[01])\d{4}-\d{4}\b/g;
const RX_DK_CPR_NOHYPHEN = /\b(0[1-9]|[12]\d|3[01])\d{8}\b/g;
const RX_DK_CPR_SPACED = /\b(0[1-9]|[12]\d|3[01])\s+\d{2}\s+\d{2}\s+\d{4}\b/g;
const RX_IBAN = /\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b/g;
const RX_CREDIT_CARD = /\b(?:\d[ -]?){12,18}\d\b/g;
const RX_US_PASSPORT = /\b[A-Z]\d{8}\b/g;
const RX_UK_PASSPORT = /\b\d{9}\b/g;

// ============================================================
// Layer 2: secrets detectors
// ============================================================

const RX_AWS_ACCESS = /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g;
const RX_GH_PAT = /\b(ghp|ghs|gho|ghr|ghu)_[A-Za-z0-9]{36,}\b/g;
const RX_STRIPE = /\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{20,}\b/g;
const RX_SLACK = /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g;
const RX_GOOGLE_API = /\bAIza[0-9A-Za-z_\-]{35}\b/g;
const RX_OPENAI = /\bsk-[A-Za-z0-9]{48}\b/g;
const RX_OPENAI_PROJ = /\bsk-proj-[A-Za-z0-9_-]{40,}\b/g;
const RX_ANTHROPIC = /\bsk-ant-(api|admin)\d+-[A-Za-z0-9_-]{40,}\b/g;
const RX_JWT = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;
const RX_SSH_PRIVATE = /-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----/g;

// SaaS / cloud-vendor specific keys frequently pasted in dev questions.
// Each pattern is anchored on a vendor-distinctive prefix so the
// false-positive risk on benign prose is negligible.
const RX_AZURE_STORAGE = /\bAccountKey=[A-Za-z0-9+/]{86}==/g;
const RX_MONGODB_CONN = /\bmongodb(?:\+srv)?:\/\/[^\s'"<>]{15,}/g;
const RX_TWILIO_SID = /\bAC[a-f0-9]{32}\b/g;
const RX_SENDGRID = /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g;
const RX_MAILGUN = /\bkey-[a-f0-9]{32}\b/g;
const RX_DISCORD_WEBHOOK = /\bhttps?:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{60,}/g;
const RX_NPM_TOKEN = /\bnpm_[A-Za-z0-9]{36}\b/g;
const RX_TAILSCALE = /\btskey-(?:auth|api|client)-[A-Za-z0-9]{16,}-[A-Za-z0-9]{32,}\b/g;
const RX_PYPI_TOKEN = /\bpypi-AgEIcHlwaS5vcmcC[A-Za-z0-9_-]{40,}/g;
const RX_HEROKU_API = /\bheroku[_-]?api[_-]?key[\s:=]+[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/gi;

// ============================================================
// Layer 3: code detection
// ============================================================

const RX_CODE_FENCE = /```[\s\S]+?```/g;
// SQL DML by itself is sensitive (real schema/data leaks), so it gets its
// own rule that fires on a single hit instead of clustering.
//
// The SELECT branch caps the column-list repetition at {1,256} so the
// inner char class — which overlaps `\s` with the trailing `\s+FROM`
// boundary — can't backtrack catastrophically on hostile input that
// starts with SELECT but never closes with FROM. 256 covers any realistic
// SQL column list while keeping worst-case work constant per match attempt.
const RX_SQL_DML = /\b(SELECT\s+[\w*,.\s]{1,256}\s+FROM\s+\w+|INSERT\s+INTO\s+\w+|UPDATE\s+\w+\s+SET\s+\w+|DELETE\s+FROM\s+\w+|CREATE\s+TABLE\s+\w+|ALTER\s+TABLE\s+\w+|DROP\s+TABLE\s+\w+)\b/gi;
// General code keyword fingerprints — clustered (≥2) so isolated mentions
// of "function" or "class" in prose don't trigger. Patterns intentionally
// match common forms across JS/TS/Python/Java without `\b` at the end
// (some alternates end in `(` or `{` which aren't word chars).
const RX_CODE_KEYWORDS = /(\bfunction\s+\w*\s*\(|\bclass\s+\w+|\bimport\s+[{*"']|\bimport\s+\w+|\brequire\s*\(|\bdef\s+\w+|\bfunc\s+\w+\s*\(|\bpublic\s+(static\s+)?(void|class)\b|\bconsole\.log\b|\bfetch\s*\(|\bSystem\.out\.println\b|\bconst\s+\w+\s*=\s*(async\s+)?\(|\bexport\s+(default\s+)?(function|class|const)\b)/g;

// ============================================================
// Rule registry
// ============================================================

interface RuleSpec {
  rule: DetectionRule;
  pattern: RegExp;
  /** If true, count consecutive multi-hit clusters as a single hit. */
  cluster?: boolean;
  /** Optional post-validation (e.g., Luhn check for credit cards). */
  validate?: (match: string) => boolean;
}

const RULES: RuleSpec[] = [
  // PII
  { rule: { id: 'pii.email', kind: 'pii', description: 'Email address', severity: 'medium' }, pattern: RX_EMAIL },
  { rule: { id: 'pii.phone.us', kind: 'pii', description: 'US phone number', severity: 'medium' }, pattern: RX_US_PHONE },
  { rule: { id: 'pii.phone.e164', kind: 'pii', description: 'International phone (E.164)', severity: 'medium' }, pattern: RX_E164_PHONE },
  { rule: { id: 'pii.ssn', kind: 'pii', description: 'US Social Security Number', severity: 'high' }, pattern: RX_US_SSN },
  { rule: { id: 'pii.dk_cpr', kind: 'pii', description: 'Danish CPR (personnummer)', severity: 'high' }, pattern: RX_DK_CPR },
  { rule: { id: 'pii.dk_cpr', kind: 'pii', description: 'Danish CPR (no separator)', severity: 'high' }, pattern: RX_DK_CPR_NOHYPHEN },
  { rule: { id: 'pii.dk_cpr', kind: 'pii', description: 'Danish CPR (space-separated)', severity: 'high' }, pattern: RX_DK_CPR_SPACED },
  { rule: { id: 'pii.iban', kind: 'pii', description: 'IBAN bank account', severity: 'high' }, pattern: RX_IBAN, validate: validateIban },
  { rule: { id: 'pii.card', kind: 'pii', description: 'Credit card number', severity: 'high' }, pattern: RX_CREDIT_CARD, validate: (m) => luhn(m.replace(/\D/g, '')) },
  { rule: { id: 'pii.passport.us', kind: 'pii', description: 'US passport number', severity: 'high' }, pattern: RX_US_PASSPORT },
  { rule: { id: 'pii.passport.uk', kind: 'pii', description: 'UK passport number (likely)', severity: 'medium' }, pattern: RX_UK_PASSPORT },

  // Secrets
  { rule: { id: 'secret.aws_access_key', kind: 'secret', description: 'AWS access key', severity: 'high' }, pattern: RX_AWS_ACCESS },
  { rule: { id: 'secret.github_pat', kind: 'secret', description: 'GitHub personal access token', severity: 'high' }, pattern: RX_GH_PAT },
  { rule: { id: 'secret.stripe', kind: 'secret', description: 'Stripe API key', severity: 'high' }, pattern: RX_STRIPE },
  { rule: { id: 'secret.slack', kind: 'secret', description: 'Slack token', severity: 'high' }, pattern: RX_SLACK },
  { rule: { id: 'secret.google_api', kind: 'secret', description: 'Google API key', severity: 'high' }, pattern: RX_GOOGLE_API },
  { rule: { id: 'secret.openai', kind: 'secret', description: 'OpenAI API key', severity: 'high' }, pattern: RX_OPENAI },
  { rule: { id: 'secret.openai_project', kind: 'secret', description: 'OpenAI project key', severity: 'high' }, pattern: RX_OPENAI_PROJ },
  { rule: { id: 'secret.anthropic', kind: 'secret', description: 'Anthropic API key', severity: 'high' }, pattern: RX_ANTHROPIC },
  { rule: { id: 'secret.jwt', kind: 'secret', description: 'JSON Web Token', severity: 'medium' }, pattern: RX_JWT },
  { rule: { id: 'secret.private_key', kind: 'secret', description: 'Private key (PEM)', severity: 'high' }, pattern: RX_SSH_PRIVATE },

  // SaaS-specific keys
  { rule: { id: 'secret.azure_storage', kind: 'secret', description: 'Azure storage account key', severity: 'high' }, pattern: RX_AZURE_STORAGE },
  { rule: { id: 'secret.mongodb_conn', kind: 'secret', description: 'MongoDB connection string', severity: 'high' }, pattern: RX_MONGODB_CONN },
  { rule: { id: 'secret.twilio_sid', kind: 'secret', description: 'Twilio account SID', severity: 'high' }, pattern: RX_TWILIO_SID },
  { rule: { id: 'secret.sendgrid', kind: 'secret', description: 'SendGrid API key', severity: 'high' }, pattern: RX_SENDGRID },
  { rule: { id: 'secret.mailgun', kind: 'secret', description: 'Mailgun API key', severity: 'high' }, pattern: RX_MAILGUN },
  { rule: { id: 'secret.discord_webhook', kind: 'secret', description: 'Discord webhook URL', severity: 'high' }, pattern: RX_DISCORD_WEBHOOK },
  { rule: { id: 'secret.npm_token', kind: 'secret', description: 'npm access token', severity: 'high' }, pattern: RX_NPM_TOKEN },
  { rule: { id: 'secret.tailscale', kind: 'secret', description: 'Tailscale auth key', severity: 'high' }, pattern: RX_TAILSCALE },
  { rule: { id: 'secret.pypi', kind: 'secret', description: 'PyPI API token', severity: 'high' }, pattern: RX_PYPI_TOKEN },
  { rule: { id: 'secret.heroku', kind: 'secret', description: 'Heroku API key', severity: 'high' }, pattern: RX_HEROKU_API },

  // Code
  { rule: { id: 'code.fenced_block', kind: 'code', description: 'Fenced code block', severity: 'medium' }, pattern: RX_CODE_FENCE },
  { rule: { id: 'code.sql', kind: 'code', description: 'SQL DML statement', severity: 'medium' }, pattern: RX_SQL_DML },
  { rule: { id: 'code.keywords', kind: 'code', description: 'Code-language keywords clustered', severity: 'medium' }, pattern: RX_CODE_KEYWORDS, cluster: true },
];

// ============================================================
// Generic high-entropy fallback (Layer 2 catch-all)
// ============================================================

function shannonEntropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  const n = s.length;
  for (const c of counts.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

// Token shape for the high-entropy fallback. Module-scope so the engine
// compiles it once, not on every detect() call.
const RX_HIGH_ENTROPY_TOKEN = /\b[A-Za-z0-9+/=_-]{32,}\b/g;
const RX_PLAIN_UUID = /^[A-F0-9-]{36}$/i;

function detectHighEntropyTokens(text: string): DetectionHit[] {
  const hits: DetectionHit[] = [];
  RX_HIGH_ENTROPY_TOKEN.lastIndex = 0;
  let match;
  while ((match = RX_HIGH_ENTROPY_TOKEN.exec(text)) !== null) {
    const token = match[0];
    if (RX_PLAIN_UUID.test(token)) continue; // skip plain UUIDs
    // Compute entropy once and reuse — the previous version called
    // shannonEntropy twice for single-case tokens (one for the 4.6
    // gate, one for the 4.5 emit threshold).
    const entropy = shannonEntropy(token);
    const isSingleCase =
      token.toLowerCase() === token || token.toUpperCase() === token;
    if (isSingleCase && entropy < 4.6) continue;
    if (entropy >= 4.5) {
      hits.push({
        rule_id: 'secret.high_entropy',
        kind: 'secret',
        severity: 'medium',
        excerpt_offset: match.index,
        excerpt_length: token.length,
      });
    }
  }
  return hits;
}

// ============================================================
// Validators
// ============================================================

function luhn(digits: string): boolean {
  if (digits.length < 12 || digits.length > 19) return false;
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

function validateIban(s: string): boolean {
  const len = s.length;
  if (len < 15 || len > 34) return false;
  // Country-code length table (subset of major countries)
  const lengths: Record<string, number> = {
    DE: 22, FR: 27, GB: 22, IT: 27, ES: 24, NL: 18, BE: 16, CH: 21,
    SE: 24, NO: 15, DK: 18, FI: 18, IE: 22, AT: 20, PT: 25, LU: 20,
    PL: 28, CZ: 24, GR: 27, HU: 28, RO: 24, SK: 24, SI: 19, BG: 22,
    HR: 21, EE: 20, LV: 21, LT: 20, MT: 31, CY: 28, IS: 26,
  };
  const cc = s.slice(0, 2);
  const expected = lengths[cc];
  if (expected !== undefined && expected !== len) return false;
  // ISO 7064 mod-97 check
  const rearr = (s.slice(4) + s.slice(0, 4)).toUpperCase();
  let acc = 0;
  for (const ch of rearr) {
    const code = ch.charCodeAt(0);
    const v = code >= 65 && code <= 90 ? code - 55 : code - 48;
    if (v < 0 || v > 35) return false;
    acc = (acc * (v < 10 ? 10 : 100) + v) % 97;
  }
  return acc === 1;
}

// ============================================================
// Public API
// ============================================================

export interface DetectOptions {
  customKeywords: string[];
}

// Hard cap on input length the detector will scan. The dom-watcher
// debounces on input events, but a single paste at an AI-tool input box
// can be megabytes (whole files / log dumps). Without a cap, pathological
// inputs could spend seconds inside V8's regex engine on backtracking
// patterns. Real prompts are virtually never above 32KB; 100KB is a
// generous ceiling that still bounds worst-case CPU per detect() call.
const MAX_DETECT_BYTES = 100_000;

// Compiled-keyword cache. Custom keywords arrive via chrome.storage.managed
// and are stable for the lifetime of a tab — recompiling them on every
// keystroke is wasted work, especially for orgs that push hundreds of
// keywords. We key the cache on the keyword-array identity (cheap) plus
// a join (cheap) so a fresh array with the same contents reuses compiled
// patterns. Single-slot cache: one keyword list at a time per content
// script, which matches reality (managed config rarely changes mid-session).
let customKeywordCacheKey: string | null = null;
let customKeywordCacheRegexes: RegExp[] = [];

function compileCustomKeywords(keywords: string[]): RegExp[] {
  // Filter out empty strings so the cache key matches the regex list.
  const live = keywords.filter((k) => k.length > 0);
  const key = live.join('\x00');
  if (key === customKeywordCacheKey) return customKeywordCacheRegexes;
  customKeywordCacheKey = key;
  customKeywordCacheRegexes = live.map((kw) => new RegExp(escapeRegExp(kw), 'gi'));
  return customKeywordCacheRegexes;
}

export function detect(text: string, opts: DetectOptions): DetectionResult {
  if (!text || text.length === 0) {
    return { hits: [], highest_severity: null, rule_ids: [] };
  }
  if (text.length > MAX_DETECT_BYTES) {
    text = text.slice(0, MAX_DETECT_BYTES);
  }

  const hits: DetectionHit[] = [];

  for (const spec of RULES) {
    spec.pattern.lastIndex = 0;
    const matches = collectMatches(text, spec);
    hits.push(...matches);
  }

  hits.push(...detectHighEntropyTokens(text));

  for (const re of compileCustomKeywords(opts.customKeywords)) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      hits.push({
        rule_id: 'keyword.custom',
        kind: 'keyword',
        severity: 'low',
        excerpt_offset: m.index,
        excerpt_length: m[0].length,
      });
    }
  }

  return summarize(hits);
}

function collectMatches(text: string, spec: RuleSpec): DetectionHit[] {
  const out: DetectionHit[] = [];
  let match: RegExpExecArray | null;
  while ((match = spec.pattern.exec(text)) !== null) {
    if (spec.validate && !spec.validate(match[0])) continue;
    out.push({
      rule_id: spec.rule.id,
      kind: spec.rule.kind,
      severity: spec.rule.severity,
      excerpt_offset: match.index,
      excerpt_length: match[0].length,
    });
  }
  if (spec.cluster && out.length >= 2) {
    // cluster of code keywords gets promoted to medium
    return [{ ...out[0]!, severity: 'medium' }];
  }
  if (spec.cluster && out.length < 2) {
    return [];
  }
  return out;
}

function summarize(hits: DetectionHit[]): DetectionResult {
  const ranks: Record<Severity, number> = { low: 1, medium: 2, high: 3 };
  let highest: Severity | null = null;
  const ruleIds = new Set<string>();

  for (const h of hits) {
    ruleIds.add(h.rule_id);
    if (highest === null || ranks[h.severity] > ranks[highest]) {
      highest = h.severity;
    }
  }

  // Multi-PII cluster → promote to high
  const piiCount = hits.filter((h) => h.kind === 'pii').length;
  if (piiCount >= 3 && highest !== 'high') highest = 'high';

  // SQL DML + any PII = exfil shape; promote to high. A SELECT statement
  // that mentions an email or SSN is leaking schema AND data together —
  // worse than either signal alone.
  const hasSQL = hits.some((h) => h.rule_id === 'code.sql');
  if (hasSQL && piiCount >= 1) highest = 'high';

  return {
    hits,
    highest_severity: highest,
    rule_ids: Array.from(ruleIds),
  };
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

import { t, type MessageKey } from '../lib/i18n';

const RULE_KEY_MAP: Record<string, MessageKey> = {
  'pii.email': 'ruleEmailAddress',
  'pii.phone.us': 'rulePhoneNumber',
  'pii.phone.e164': 'rulePhoneNumber',
  'pii.ssn': 'ruleSSN',
  'pii.dk_cpr': 'ruleDanishCPR',
  'pii.iban': 'ruleBankAccount',
  'pii.card': 'ruleCreditCard',
  'pii.passport.us': 'rulePassport',
  'pii.passport.uk': 'rulePassport',
  'secret.aws_access_key': 'ruleAWSKey',
  'secret.github_pat': 'ruleGitHubPAT',
  'secret.stripe': 'ruleStripeKey',
  'secret.slack': 'ruleSlackToken',
  'secret.google_api': 'ruleGoogleAPIKey',
  'secret.openai': 'ruleOpenAIKey',
  'secret.openai_project': 'ruleOpenAIProjectKey',
  'secret.anthropic': 'ruleAnthropicKey',
  'secret.jwt': 'ruleJWT',
  'secret.private_key': 'rulePrivateKey',
  'secret.high_entropy': 'ruleHighEntropy',
  'code.fenced_block': 'ruleSourceCode',
  'code.keywords': 'ruleSourceCode',
  'code.sql': 'ruleSQL',
  'keyword.custom': 'ruleCustomKeyword',
  // SaaS-specific keys all summarize as "an API key" — no separate
  // localization keys needed; the rule_id itself shows in the audit log.
  'secret.azure_storage': 'ruleHighEntropy',
  'secret.mongodb_conn': 'ruleHighEntropy',
  'secret.twilio_sid': 'ruleHighEntropy',
  'secret.sendgrid': 'ruleHighEntropy',
  'secret.mailgun': 'ruleHighEntropy',
  'secret.discord_webhook': 'ruleHighEntropy',
  'secret.npm_token': 'ruleHighEntropy',
  'secret.tailscale': 'ruleHighEntropy',
  'secret.pypi': 'ruleHighEntropy',
  'secret.heroku': 'ruleHighEntropy',
};

// EN fallbacks for environments without chrome.i18n (tests, dev preview).
const EN_FALLBACKS: Record<MessageKey, string> = {
  ruleEmailAddress: 'an email address',
  rulePhoneNumber: 'a phone number',
  ruleSSN: 'a social security number',
  ruleDanishCPR: 'a Danish CPR (personnummer)',
  ruleBankAccount: 'a bank account number',
  ruleCreditCard: 'a credit card number',
  rulePassport: 'a passport number',
  ruleAWSKey: 'an AWS access key',
  ruleGitHubPAT: 'a GitHub access token',
  ruleStripeKey: 'a Stripe API key',
  ruleSlackToken: 'a Slack token',
  ruleGoogleAPIKey: 'a Google API key',
  ruleOpenAIKey: 'an OpenAI API key',
  ruleOpenAIProjectKey: 'an OpenAI project key',
  ruleAnthropicKey: 'an Anthropic API key',
  ruleJWT: 'a JSON Web Token',
  rulePrivateKey: 'a private key',
  ruleHighEntropy: 'a likely secret token',
  ruleSourceCode: 'source code',
  ruleSQL: 'a SQL statement',
  ruleCustomKeyword: 'a company-confidential keyword',
  ruleSensitiveContent: 'sensitive content',
  connectorAnd: 'and',
  // Modal copy fallbacks
  extName: 'Bastio Governance',
  extDescription: '',
  modalTitle: 'Bastio Governance',
  modalSubtitle: 'Company AI policy',
  modalBodySensitive: '',
  modalBodyDomain: '',
  modalCtaPrimary: '',
  modalCtaCancel: 'Cancel',
  modalOverrideToggle: 'Send anyway (logged)',
  modalJustifyLabel: 'Justification (required, audit-logged)',
  modalJustifyPlaceholder: 'Why does this need to bypass policy?',
  modalOverrideConfirm: 'Confirm override',
  modalFooter: '',
};

function localized(key: MessageKey, ...subs: string[]): string {
  const got = t(key, ...subs);
  if (got) return got;
  // chrome.i18n missing → use EN fallback. Substitutions are baked at the
  // caller, so fallbacks generally don't need them; modal-specific
  // formatted strings handle their own fallback at the call site.
  return EN_FALLBACKS[key] ?? '';
}

export function ruleSummary(ruleIds: string[]): string {
  if (ruleIds.length === 0) return localized('ruleSensitiveContent');

  const labels = Array.from(
    new Set(
      ruleIds.map((r) => {
        const key = RULE_KEY_MAP[r];
        return key ? localized(key) : r;
      }),
    ),
  );

  const and = localized('connectorAnd');
  if (labels.length === 1) return labels[0]!;
  if (labels.length === 2) return `${labels[0]} ${and} ${labels[1]}`;
  return `${labels.slice(0, -1).join(', ')}, ${and} ${labels[labels.length - 1]}`;
}

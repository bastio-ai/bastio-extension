// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * i18n helper. Wraps `chrome.i18n.getMessage` so callers don't have to deal
 * with the chrome-specific shape, and provides typed translation keys.
 *
 * Translations live in `public/_locales/{lang}/messages.json`. Chrome resolves
 * the user's locale from the browser at install time and serves the matching
 * file. For unsupported locales, Chrome falls back to `default_locale: en`
 * (set in manifest.json).
 */

export type MessageKey =
  | "extName"
  | "extDescription"
  | "modalTitle"
  | "modalSubtitle"
  | "modalBodySensitive"
  | "modalBodyDomain"
  | "modalCtaPrimary"
  | "modalCtaCancel"
  | "modalOverrideToggle"
  | "modalJustifyLabel"
  | "modalJustifyPlaceholder"
  | "modalOverrideConfirm"
  | "modalFooter"
  | "ruleEmailAddress"
  | "rulePhoneNumber"
  | "ruleSSN"
  | "ruleDanishCPR"
  | "ruleBankAccount"
  | "ruleCreditCard"
  | "rulePassport"
  | "ruleAWSKey"
  | "ruleGitHubPAT"
  | "ruleStripeKey"
  | "ruleSlackToken"
  | "ruleGoogleAPIKey"
  | "ruleOpenAIKey"
  | "ruleOpenAIProjectKey"
  | "ruleAnthropicKey"
  | "ruleJWT"
  | "rulePrivateKey"
  | "ruleHighEntropy"
  | "ruleSourceCode"
  | "ruleSQL"
  | "ruleCustomKeyword"
  | "ruleSensitiveContent"
  | "connectorAnd";

/**
 * Look up a translated message by key. Substitutions are positional ($1, $2...)
 * and applied to the resolved string in declaration order.
 *
 * If chrome.i18n is unavailable (e.g. tests, content-script-mock context),
 * returns an empty string per Chrome's contract.
 */
export function t(key: MessageKey, ...substitutions: string[]): string {
  if (typeof chrome === "undefined" || !chrome.i18n?.getMessage) {
    return "";
  }
  return chrome.i18n.getMessage(key, substitutions);
}

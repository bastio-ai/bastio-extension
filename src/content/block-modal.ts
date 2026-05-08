// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * Block + Configurable Redirect modal.
 *
 * Injected on top of the page when the detector fires `high` severity. Freezes the
 * captured input element and shows the policy modal. Vanilla DOM (no React in content
 * script) to keep bundle small and avoid host-page conflicts.
 */

import type { RedirectTarget } from '../lib/types';
import { t } from '../lib/i18n';

export interface ModalChoice {
  action: 'redirect' | 'cancel' | 'override';
  override_justification?: string;
}

interface ShowModalOpts {
  rule_summary: string;
  source_domain: string;
  redirect_target?: RedirectTarget;
  override_enabled: boolean;
}

const STYLES = `
  .bastio-overlay {
    position: fixed;
    inset: 0;
    background: rgba(8, 12, 20, 0.78);
    backdrop-filter: blur(6px);
    z-index: 2147483646;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", sans-serif;
    animation: bastio-fade 160ms ease-out;
  }
  @keyframes bastio-fade {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  .bastio-modal {
    background: #0d1117;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 12px;
    box-shadow: 0 24px 60px -12px rgba(0,0,0,0.6), 0 0 0 1px rgba(110, 220, 255, 0.08);
    width: 100%;
    max-width: 480px;
    margin: 0 24px;
    overflow: hidden;
    animation: bastio-pop 180ms cubic-bezier(0.16, 1, 0.3, 1);
  }
  @keyframes bastio-pop {
    from { transform: translateY(8px) scale(0.98); opacity: 0; }
    to { transform: translateY(0) scale(1); opacity: 1; }
  }
  .bastio-header {
    padding: 24px 28px 20px;
    border-bottom: 1px solid #21262d;
    display: flex;
    align-items: flex-start;
    gap: 16px;
  }
  .bastio-shield {
    flex-shrink: 0;
    width: 32px;
    height: 32px;
    border-radius: 8px;
    background: rgba(248, 81, 73, 0.12);
    color: #ff7b72;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
  }
  .bastio-title-row { flex: 1; }
  .bastio-title {
    font-size: 15px;
    font-weight: 600;
    margin: 0;
    color: #e6edf3;
    letter-spacing: -0.01em;
  }
  .bastio-subtitle {
    font-size: 12px;
    color: #8b949e;
    margin: 2px 0 0;
    font-family: ui-monospace, "JetBrains Mono", "SF Mono", monospace;
  }
  .bastio-body { padding: 20px 28px 24px; }
  .bastio-rule {
    font-size: 14px;
    color: #e6edf3;
    line-height: 22px;
    margin: 0 0 8px;
  }
  .bastio-rule strong {
    color: #ff7b72;
    font-weight: 600;
  }
  .bastio-detail {
    font-size: 13px;
    color: #8b949e;
    line-height: 20px;
    margin: 0;
  }
  .bastio-domain {
    font-family: ui-monospace, "JetBrains Mono", "SF Mono", monospace;
    background: #161b22;
    color: #e6edf3;
    padding: 1px 6px;
    border-radius: 4px;
    border: 1px solid #21262d;
  }
  .bastio-actions {
    padding: 16px 28px 20px;
    background: #010409;
    display: flex;
    gap: 10px;
    align-items: center;
    flex-wrap: wrap;
    border-top: 1px solid #21262d;
  }
  .bastio-btn {
    font: inherit;
    font-size: 13px;
    font-weight: 500;
    padding: 9px 14px;
    border-radius: 6px;
    border: 1px solid transparent;
    cursor: pointer;
    line-height: 1;
    transition: all 120ms ease;
  }
  .bastio-btn-primary {
    background: linear-gradient(180deg, #2ee5d8, #1ec9bd);
    color: #062a26;
    border-color: rgba(46, 229, 216, 0.4);
  }
  .bastio-btn-primary:hover { filter: brightness(1.08); }
  .bastio-btn-ghost {
    background: transparent;
    color: #c9d1d9;
    border-color: #30363d;
  }
  .bastio-btn-ghost:hover { background: #161b22; }
  .bastio-btn-link {
    background: transparent;
    color: #8b949e;
    border-color: transparent;
    text-decoration: underline;
    text-underline-offset: 3px;
    padding: 9px 4px;
    margin-left: auto;
  }
  .bastio-btn-link:hover { color: #c9d1d9; }
  .bastio-justify-row {
    width: 100%;
    margin-top: 8px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .bastio-justify-label {
    font-size: 11px;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .bastio-justify-input {
    width: 100%;
    background: #0d1117;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px 10px;
    font: inherit;
    font-size: 13px;
    box-sizing: border-box;
  }
  .bastio-justify-input:focus {
    outline: none;
    border-color: #2ee5d8;
    box-shadow: 0 0 0 3px rgba(46, 229, 216, 0.15);
  }
  .bastio-footer {
    padding: 12px 28px;
    background: #010409;
    font-size: 11px;
    color: #6e7681;
    font-family: ui-monospace, "JetBrains Mono", "SF Mono", monospace;
    text-align: center;
    border-top: 1px solid #21262d;
    letter-spacing: 0.02em;
  }
`;

let activeOverlay: HTMLElement | null = null;

export function showBlockModal(opts: ShowModalOpts): Promise<ModalChoice> {
  return new Promise((resolve) => {
    closeActive();

    const root = document.createElement('div');
    root.className = 'bastio-overlay';
    // Closed shadow mode: the host page can't reach into the modal via
    // root.shadowRoot (returns null), so it can't introspect or mutate
    // the dialog's DOM. Content-script JS runs in an isolated world
    // anyway, but closing the shadow adds a defense-in-depth layer for
    // any host page that tries to read the rule summary or justification
    // input out of the modal at render time.
    const shadow = root.attachShadow({ mode: 'closed' });

    const styleEl = document.createElement('style');
    styleEl.textContent = STYLES;
    shadow.appendChild(styleEl);

    const overlay = document.createElement('div');
    overlay.className = 'bastio-overlay';
    overlay.innerHTML = renderModal(opts);
    shadow.appendChild(overlay);

    const finish = (choice: ModalChoice): void => {
      cleanup();
      resolve(choice);
    };

    const cleanup = (): void => {
      root.remove();
      activeOverlay = null;
      document.removeEventListener('keydown', onKey, true);
    };

    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        finish({ action: 'cancel' });
      }
    };

    document.addEventListener('keydown', onKey, true);

    overlay.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;
      const action = target.dataset['bastioAction'];
      if (action === 'redirect' && opts.redirect_target) {
        finish({ action: 'redirect' });
      } else if (action === 'cancel') {
        finish({ action: 'cancel' });
      } else if (action === 'override-toggle') {
        const justifyRow = overlay.querySelector('.bastio-justify-row') as HTMLElement;
        if (justifyRow) {
          justifyRow.style.display = justifyRow.style.display === 'none' ? 'flex' : 'none';
          if (justifyRow.style.display === 'flex') {
            (justifyRow.querySelector('input') as HTMLInputElement)?.focus();
          }
        }
      } else if (action === 'override-confirm') {
        const justification = (
          overlay.querySelector('.bastio-justify-input') as HTMLInputElement
        )?.value.trim();
        if (!justification || justification.length < 8) {
          (overlay.querySelector('.bastio-justify-input') as HTMLInputElement)?.focus();
          return;
        }
        finish({ action: 'override', override_justification: justification });
      }
    });

    document.documentElement.appendChild(root);
    activeOverlay = root;
  });
}

function closeActive(): void {
  if (activeOverlay) {
    activeOverlay.remove();
    activeOverlay = null;
  }
}

function renderModal(opts: ShowModalOpts): string {
  const target = opts.redirect_target;
  const targetLabel = target?.label ?? 'a secure tool';
  const safeRule = escapeHtml(opts.rule_summary);
  const safeDomain = escapeHtml(opts.source_domain);
  const safeTarget = escapeHtml(targetLabel);
  const version = chrome.runtime.getManifest().version;

  // Strings come from chrome.i18n (resolved by the user's browser locale at
  // install time). EN literals serve as fallbacks if the locale lookup fails
  // for any reason (e.g. corrupted MV3 install).
  const title = t('modalTitle') || 'Bastio Governance';
  const subtitle = t('modalSubtitle') || 'Company AI policy';
  const sensitiveLine = t('modalBodySensitive', safeRule).replace(
    safeRule,
    `<strong>${safeRule}</strong>`,
  ) || `Sensitive data detected: <strong>${safeRule}</strong>`;
  const domainLine = t('modalBodyDomain', safeDomain).replace(
    safeDomain,
    `<span class="bastio-domain">${safeDomain}</span>`,
  ) || `Sending this to <span class="bastio-domain">${safeDomain}</span> would violate your company's AI policy.`;
  const ctaPrimary = t('modalCtaPrimary', safeTarget) || `Use ${safeTarget} →`;
  const ctaCancel = t('modalCtaCancel') || 'Cancel';
  const overrideToggle = t('modalOverrideToggle') || 'Send anyway (logged)';
  const justifyLabel = t('modalJustifyLabel') || 'Justification (required, audit-logged)';
  const justifyPlaceholder = t('modalJustifyPlaceholder') || 'Why does this need to bypass policy?';
  const overrideConfirm = t('modalOverrideConfirm') || 'Confirm override';
  const footer = t('modalFooter', version) || `protected by bastio.com · governance v${version}`;

  return `
    <div class="bastio-modal" role="dialog" aria-modal="true" aria-labelledby="bastio-title">
      <div class="bastio-header">
        <div class="bastio-shield">🛑</div>
        <div class="bastio-title-row">
          <h2 class="bastio-title" id="bastio-title">${escapeHtml(title)}</h2>
          <p class="bastio-subtitle">${escapeHtml(subtitle)}</p>
        </div>
      </div>
      <div class="bastio-body">
        <p class="bastio-rule">${sensitiveLine}</p>
        <p class="bastio-detail">${domainLine}</p>
      </div>
      <div class="bastio-actions">
        ${
          target
            ? `<button class="bastio-btn bastio-btn-primary" data-bastio-action="redirect">${escapeHtml(ctaPrimary)}</button>`
            : ''
        }
        <button class="bastio-btn bastio-btn-ghost" data-bastio-action="cancel">${escapeHtml(ctaCancel)}</button>
        ${
          opts.override_enabled
            ? `<button class="bastio-btn bastio-btn-link" data-bastio-action="override-toggle">${escapeHtml(overrideToggle)}</button>
               <div class="bastio-justify-row" style="display:none;">
                 <label class="bastio-justify-label">${escapeHtml(justifyLabel)}</label>
                 <input type="text" class="bastio-justify-input" placeholder="${escapeHtml(justifyPlaceholder)}" />
                 <button class="bastio-btn bastio-btn-ghost" data-bastio-action="override-confirm" style="align-self:flex-start;">${escapeHtml(overrideConfirm)}</button>
               </div>`
            : ''
        }
      </div>
      <div class="bastio-footer">${escapeHtml(footer)}</div>
    </div>
  `;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

import { getConfig } from '../lib/config';
import { getOrCreateInstallState } from '../lib/install-state';

function row(grid: HTMLElement, label: string, value: string): void {
  const dt = document.createElement('dt');
  dt.textContent = label;
  const dd = document.createElement('dd');
  dd.textContent = value || '—';
  grid.appendChild(dt);
  grid.appendChild(dd);
}

async function init(): Promise<void> {
  const config = await getConfig();
  const state = await getOrCreateInstallState();

  const orgGrid = document.getElementById('org-grid')!;
  row(orgGrid, 'Org ID', config.org_id || 'Not configured');
  row(orgGrid, 'Install ID', state.install_id);
  row(orgGrid, 'Extension version', chrome.runtime.getManifest().version);
  row(orgGrid, 'First run', new Date(state.first_run_at).toLocaleString());

  const policyGrid = document.getElementById('policy-grid')!;
  row(policyGrid, 'Low severity', config.default_policy.low);
  row(policyGrid, 'Medium severity', config.default_policy.medium);
  row(policyGrid, 'High severity', config.default_policy.high);
  row(policyGrid, 'Override allowed', String(config.override_enabled));

  const redirectBlock = document.getElementById('redirect-block')!;
  if (config.redirect_target?.url) {
    const grid = document.createElement('dl');
    grid.className = 'grid';
    row(grid, 'Label', config.redirect_target.label);
    row(grid, 'URL', config.redirect_target.url);
    row(grid, 'Open in new tab', String(config.redirect_target.open_in_new_tab));
    redirectBlock.appendChild(grid);
  } else {
    redirectBlock.innerHTML = '<p class="empty">No redirect target configured. Block actions will only deny — no destination button shown.</p>';
  }

  const keywordsBlock = document.getElementById('keywords-block')!;
  if (config.custom_keywords.length > 0) {
    const pre = document.createElement('pre');
    pre.textContent = config.custom_keywords.join('\n');
    keywordsBlock.appendChild(pre);
  } else {
    keywordsBlock.innerHTML = '<p class="empty">No custom keywords configured.</p>';
  }

  const backendGrid = document.getElementById('backend-grid')!;
  row(backendGrid, 'URL', config.backend_url);
  row(backendGrid, 'Telemetry endpoint', config.telemetry_endpoint);
}

void init();

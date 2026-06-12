// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright (c) 2026 Bastio, Inc.

/**
 * DOM input watcher. Locates AI-tool input elements (textareas, contenteditable
 * divs), debounces detection on input/keypress, and intercepts the send action
 * (button click + Enter keypress).
 *
 * Authoritative gate is the send-action interception. Input-event detection is
 * a local-only preview to warm up state and run async classifier hint calls.
 */

import { debug } from '../lib/log';

export type SendInterceptHandler = (text: string, target: HTMLElement) => Promise<boolean>;

const INPUT_SELECTORS = [
  'textarea',
  '[contenteditable="true"]',
  '[contenteditable=""]',
  '[role="textbox"]',
];

interface WatcherOptions {
  onPreview: (text: string) => void;
  onSendIntercept: SendInterceptHandler;
  // Synchronous quick-check: returns true if `text` is sensitive
  // enough that the doc-level pointer intercept should engage.
  // Without this, safe sends would still be preventDefault'd and we'd
  // re-dispatch — re-dispatch + reentry can recurse and crash the tab.
  isSensitive?: (text: string) => boolean;
  // Fire-and-forget signal that the user just completed a send: the
  // input transitioned from non-empty to empty. Used to record `observed`
  // events and bump volume rollups in tracking_mode='volume' / 'full'
  // WITHOUT preventDefault'ing benign sends — leaves the existing
  // input-binding contract untouched.
  onSendComplete?: (text: string) => void;
}

export function startWatcher(opts: WatcherOptions): () => void {
  const tracked = new WeakSet<HTMLElement>();
  let boundCount = 0;
  let previewTimer: ReturnType<typeof setTimeout> | null = null;
  let lastPreviewText = '';

  const handlePreview = (el: HTMLElement): void => {
    if (previewTimer) clearTimeout(previewTimer);
    previewTimer = setTimeout(() => {
      // Orphaned content script (extension updated/reloaded while this
      // tab stayed open): preview callbacks reach chrome.* APIs and
      // would throw "Extension context invalidated". Stop quietly.
      if (!chrome.runtime?.id) return;
      const text = readInput(el);
      if (text === lastPreviewText) return;
      // Detect a completed send: input transitioned from a real prompt
      // (≥4 chars, filters out single-char typo deletes) to empty.
      // ChatGPT, Claude, etc. all clear the textarea after a successful
      // submit. Fires fire-and-forget — does not delay or block the send.
      if (text.length === 0 && lastPreviewText.length >= 4 && opts.onSendComplete) {
        try {
          opts.onSendComplete(lastPreviewText);
        } catch {
          // Never let a callback failure break the input bindings.
        }
      }
      lastPreviewText = text;
      if (text.length >= 12) opts.onPreview(text);
    }, 250);
  };

  const handleKeyDown = async (e: KeyboardEvent, el: HTMLElement): Promise<void> => {
    // Intercept Cmd/Ctrl + Enter and plain Enter (without Shift) on a single-line send.
    const isSendKey =
      e.key === 'Enter' && !e.shiftKey && !e.altKey && !e.isComposing;
    if (!isSendKey) return;

    // Suppress re-entry when we're already re-dispatching. Without
    // this, our own dispatched Enter event re-triggers handleKeyDown,
    // which awaits onSendIntercept (returns true on null severity),
    // re-dispatches again — an infinite loop that crashes the tab
    // on any safe send. The flag is on documentElement so it stays
    // shared with the doc-level pointer interceptor.
    if (document.documentElement.hasAttribute('data-bastio-redispatching')) return;

    // Orphaned content script: chrome.runtime is gone after an extension
    // update, and the updated extension only injects into NEW navigations
    // — this instance can never evaluate policy again. preventDefault'ing
    // and then failing on the first chrome.* call would strand the user's
    // chat until a manual reload, so detach everything and let the host
    // page work natively instead. Checked BEFORE preventDefault on
    // purpose: this very keystroke must go through.
    if (!chrome.runtime?.id) {
      teardown();
      return;
    }

    const text = readInput(el);
    if (text.trim().length === 0) return;

    // Quick synchronous gate: only intercept when the content is
    // actually sensitive enough to warrant blocking the send. For
    // benign content, let Enter flow through to the host page.
    if (opts.isSensitive && !opts.isSensitive(text)) return;

    // Synchronous block: pause propagation, run check, decide.
    e.stopPropagation();
    e.stopImmediatePropagation();
    e.preventDefault();

    // On callback failure the send stays swallowed for THIS attempt
    // (fail-closed; a retry re-evaluates) — re-dispatching on error
    // would turn any induced exception into a policy bypass.
    let allowed = false;
    try {
      allowed = await opts.onSendIntercept(text, el);
    } catch {
      debug('send intercept failed; keeping send blocked for this attempt');
    }
    if (allowed) {
      document.documentElement.setAttribute('data-bastio-redispatching', '1');
      try {
        // Re-dispatch the same key to let the host page send the message.
        el.dispatchEvent(
          new KeyboardEvent('keydown', {
            key: 'Enter',
            code: 'Enter',
            bubbles: true,
            cancelable: true,
            composed: true,
          }),
        );
      } finally {
        document.documentElement.removeAttribute('data-bastio-redispatching');
      }
    }
  };

  const attachToInput = (el: HTMLElement): void => {
    if (tracked.has(el)) return;
    tracked.add(el);
    boundCount++;
    // `input` is the standard event but rich-text editors like
    // ProseMirror (used by ChatGPT) intercept and rewrite at the
    // beforeinput stage and may not fire native `input` reliably.
    // Listen for both, plus poll the element's text content as a
    // last-resort fallback so the preview stays accurate regardless
    // of how the host page mutates the DOM.
    const fireFromEvent = () => handlePreview(el);
    el.addEventListener('input', fireFromEvent);
    el.addEventListener('beforeinput', fireFromEvent);
    el.addEventListener('keyup', fireFromEvent);
    el.addEventListener('paste', fireFromEvent);
    el.addEventListener('keydown', (e) => void handleKeyDown(e as KeyboardEvent, el), true);
  };

  const scan = (root: ParentNode): void => {
    // Check the root itself first — querySelectorAll only walks
    // descendants, so a contenteditable div added directly via
    // MutationObserver as `addedNodes[0]` would be missed otherwise.
    if (root instanceof HTMLElement) {
      for (const sel of INPUT_SELECTORS) {
        if (root.matches(sel)) {
          attachToInput(root);
          break;
        }
      }
    }
    for (const sel of INPUT_SELECTORS) {
      for (const el of root.querySelectorAll<HTMLElement>(sel)) {
        attachToInput(el);
      }
    }
  };

  scan(document);

  const observer = new MutationObserver((records) => {
    for (const r of records) {
      for (const node of r.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          scan(node as ParentNode);
        }
      }
    }
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });

  // Defensive periodic re-scan: SPA frameworks (React/Vue/Angular)
  // sometimes mount inputs in ways that don't trigger MutationObserver
  // childList events on documentElement. Re-running scan a few times
  // after page load catches late mounts cheaply.
  //
  // Auto-stop conditions, whichever fires first:
  //   1. We've bound at least one input AND seen 3 consecutive ticks
  //      with no new bindings (page is stable, MutationObserver covers
  //      anything that mounts from here on).
  //   2. Hard 10s ceiling — never poll forever even on a page where
  //      the host never settles.
  let lastBoundCount = 0;
  let stableTicks = 0;
  const periodicScan = setInterval(() => {
    // Orphaned context: stop polling immediately instead of riding out
    // the 10s ceiling in a zombie instance.
    if (!chrome.runtime?.id) {
      teardown();
      return;
    }
    scan(document);
    if (boundCount > 0 && boundCount === lastBoundCount) {
      stableTicks++;
      if (stableTicks >= 3) clearInterval(periodicScan);
    } else {
      stableTicks = 0;
      lastBoundCount = boundCount;
    }
  }, 1000);
  setTimeout(() => clearInterval(periodicScan), 10000);

  // Document-level pointer capture: ChatGPT's send arrow uses a deeply
  // nested SVG inside a div with no button role; click events never
  // reach our listener (React stops propagation at the host root).
  // Pointerdown fires earlier in the event sequence and is harder
  // for the host page to suppress. We listen at capture phase so we
  // run before any React handler.
  //
  // Heuristic for "is this a send action?":
  //   - any pointer-target element OR ancestor up to <body>
  //   - that has a recently-tracked input with non-empty text content
  //   - and the text triggers high/medium severity
  // If yes, we block. If no, we let the click through.
  let lastInterceptAt = 0;
  // Cross-closure re-dispatch flag stored on documentElement.
  // Multiple content-script instances (e.g., after extension reload
  // without a page refresh) each register their own document-level
  // listeners with separate JS closures. A closure-only flag would
  // not be visible to sibling instances; their handlers would still
  // fire on our re-dispatched events and re-dispatch in turn —
  // recursion that crashes the tab. The DOM attribute is shared
  // across all instances since they all observe the same document.
  const REDISPATCH_ATTR = 'data-bastio-redispatching';
  const isReDispatching = (): boolean =>
    document.documentElement.hasAttribute(REDISPATCH_ATTR);
  const setReDispatching = (v: boolean): void => {
    if (v) document.documentElement.setAttribute(REDISPATCH_ATTR, '1');
    else document.documentElement.removeAttribute(REDISPATCH_ATTR);
  };

  const interceptDocPointer = async (e: Event): Promise<void> => {
    if (isReDispatching()) return;
    const now = performance.now();
    if (now - lastInterceptAt < 500) return; // debounce: avoid running for both pointerdown + click on same gesture
    // Skip clicks targeting our own block modal — its shadow root
    // re-targets event.target to the .bastio-overlay host, so a
    // closest() match catches both the host and any internal click
    // that bubbled out of the shadow DOM. Check this FIRST so we
    // don't waste time on findRecentInput() when the user is just
    // dismissing our modal.
    const target = e.target as HTMLElement | null;
    if (!target) return;
    if (target.closest('.bastio-overlay')) return;
    // For doc-level intercepts (button clicks, send arrows), the
    // active element is usually NOT the input (focus moved to the
    // button/modal). Prefer the input that has actual text content
    // — findRecentInput walks contenteditable first and only returns
    // a textarea last-resort. Falling back to findActiveInput last
    // covers edge cases where the user's keystroke fires before
    // focus moves.
    const input = findRecentInput(tracked) ?? findActiveInput();
    if (!input) return;
    const text = readInput(input);
    if (text.trim().length === 0) return;
    if (target === input || input.contains(target)) return;
    // Quick synchronous gate: if the input doesn't look sensitive,
    // do NOT preventDefault. Letting the host handle its own click
    // means we never re-dispatch, which means we can't recurse.
    if (opts.isSensitive && !opts.isSensitive(text)) {
      // No need to log every benign click — would spam the console.
      return;
    }
    // Reject clicks that clearly aren't a send action even though the
    // input has sensitive content. Without this the modal pops up on
    // every navigation click — profile menu, sidebar, share button,
    // any link in the page chrome. Two filters in order of cost:
    //   1. Semantic: target/ancestor is a link, nav, header, aside,
    //      or has a label that screams "this isn't send".
    //   2. Geometric: send buttons sit adjacent to the input. Anything
    //      more than ~300px away is almost certainly chrome.
    // Both filters are conservative — they reject only obvious
    // non-send chrome, leaving the existing send-button detection
    // path untouched.
    if (looksLikeNonSendClick(target)) return;
    if (!isAdjacentToInput(target, input, 300)) return;
    debug('doc-level', e.type, 'with non-empty input, len=', text.length, 'target=', target.tagName);
    lastInterceptAt = now;
    e.stopPropagation();
    e.stopImmediatePropagation();
    e.preventDefault();
    const allowed = await opts.onSendIntercept(text, input);
    if (allowed) {
      // Re-emit the original gesture so the host page can complete
      // the send. We use mousedown+mouseup+click to cover most
      // React handlers; redispatching a single event won't always
      // satisfy a button bound to onMouseDown vs onClick. The
      // documentElement attribute suppresses re-entry from our own
      // dispatched events across all content-script closures.
      setReDispatching(true);
      try {
        target.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));
        target.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true }));
        (target as HTMLElement).click();
      } finally {
        setReDispatching(false);
      }
    }
  };
  // Single named handler (not inline arrows) so teardown can actually
  // detach all three registrations. Capture-phase doc listeners must
  // never throw — an exception here aborts the gesture for the whole
  // page — so rejections from the async interceptor are swallowed
  // after the orphan check has had its chance to self-detach.
  const docPointerHandler = (e: Event): void => {
    if (!chrome.runtime?.id) {
      teardown();
      return;
    }
    interceptDocPointer(e).catch(() => {
      // Interceptor failures must not propagate out of a capture-phase
      // listener; the gesture either went through (pre-preventDefault
      // failure) or stays blocked for this attempt (post-preventDefault).
    });
  };
  document.addEventListener('pointerdown', docPointerHandler, true);
  document.addEventListener('mousedown', docPointerHandler, true);
  document.addEventListener('click', docPointerHandler, true);

  // teardown is idempotent and reachable from every periodic/handler
  // path so an orphaned instance (extension updated under this tab)
  // fully unhooks itself: doc listeners, observer, timers. Per-element
  // listeners stay attached — their handlers are no-ops once the
  // orphan checks above short-circuit — and the tab reclaims them on
  // navigation.
  let torndown = false;
  const teardown = (): void => {
    if (torndown) return;
    torndown = true;
    document.removeEventListener('pointerdown', docPointerHandler, true);
    document.removeEventListener('mousedown', docPointerHandler, true);
    document.removeEventListener('click', docPointerHandler, true);
    observer.disconnect();
    clearInterval(periodicScan);
    if (previewTimer) clearTimeout(previewTimer);
  };

  return teardown;
}

// looksLikeNonSendClick returns true when the click target is clearly
// not a send action — navigation links, header chrome, sidebar items,
// profile/menu/account buttons. The doc-level interceptor uses this to
// avoid popping the policy modal on benign navigation clicks while the
// input happens to hold sensitive text.
//
// Conservative on purpose: only matches clear non-send patterns. When
// in doubt, returns false and lets the existing send-button detection
// path decide.
const NON_SEND_LABEL_PATTERN =
  /\b(profile|account|settings?|menu|history|new chat|share|export|sign\s*out|log\s*out|login|sidebar|library|workspace|help|feedback|navigation)\b/i;

function looksLikeNonSendClick(target: HTMLElement): boolean {
  // Anchor tags are virtually never send buttons.
  if (target.closest('a[href]')) return true;
  // Top-level navigation regions never contain send buttons.
  if (
    target.closest('nav, header, aside, [role="navigation"], [role="menu"], [role="menuitem"], [role="tab"], [role="tablist"]')
  ) {
    return true;
  }
  // Walk a few ancestors looking at aria-label / text content for
  // navigation-shaped wording. Limit the walk depth so we don't read
  // the whole document innerText on a deeply nested click.
  let node: HTMLElement | null = target;
  for (let depth = 0; depth < 4 && node; depth++, node = node.parentElement) {
    const aria = node.getAttribute('aria-label') ?? '';
    if (aria && NON_SEND_LABEL_PATTERN.test(aria)) return true;
    const title = node.getAttribute('title') ?? '';
    if (title && NON_SEND_LABEL_PATTERN.test(title)) return true;
    // Only check textContent on small, leaf-ish elements (avoids
    // reading paragraph-sized strings).
    const text = node.textContent ?? '';
    if (text.length > 0 && text.length < 40 && NON_SEND_LABEL_PATTERN.test(text)) {
      return true;
    }
  }
  return false;
}

// isAdjacentToInput returns true when target's bounding rect is within
// `slack` pixels of any edge of input's bounding rect. Send buttons
// (whether inline icons inside the input or a primary button just
// below) sit adjacent to the input. Anything farther away is page
// chrome and should not be intercepted as a potential send action.
function isAdjacentToInput(
  target: HTMLElement,
  input: HTMLElement,
  slack: number,
): boolean {
  const ti = input.getBoundingClientRect();
  const tt = target.getBoundingClientRect();
  // Distance from target's center to the input's bounding rect:
  // 0 if overlapping, otherwise the shortest perpendicular distance.
  const cx = (tt.left + tt.right) / 2;
  const cy = (tt.top + tt.bottom) / 2;
  const dx = cx < ti.left ? ti.left - cx : cx > ti.right ? cx - ti.right : 0;
  const dy = cy < ti.top ? ti.top - cy : cy > ti.bottom ? cy - ti.bottom : 0;
  return Math.hypot(dx, dy) <= slack;
}

// findRecentInput returns a tracked input that's currently in the
// DOM, visible, AND has non-empty text content. Preference goes to
// the input the user is actively typing in — typically the contenteditable
// div for ProseMirror-based hosts. Empty inputs (like ChatGPT's hidden
// form-backup textarea) are skipped so they don't shadow the real one.
//
// Used as a fallback when document.activeElement isn't an input
// (e.g., user clicked the send arrow or our modal's Cancel button,
// which both steal focus from the chat input).
function findRecentInput(tracked: WeakSet<HTMLElement>): HTMLElement | null {
  let firstVisible: HTMLElement | null = null;
  for (const sel of ['[contenteditable="true"]', '[role="textbox"]', 'textarea']) {
    const els = Array.from(document.querySelectorAll<HTMLElement>(sel));
    for (const el of els) {
      if (!tracked.has(el)) continue;
      if (!el.isConnected || el.offsetParent === null) continue;
      const text = el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement
        ? el.value
        : el.innerText;
      if (text.trim().length > 0) return el;
      if (!firstVisible) firstVisible = el;
    }
  }
  // Nothing has text — fall back to the first visible tracked input
  // so callers still get something pointing at the right host.
  return firstVisible;
}

function readInput(el: HTMLElement): string {
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
    return el.value;
  }
  return el.innerText;
}

function findActiveInput(): HTMLElement | null {
  const active = document.activeElement as HTMLElement | null;
  if (!active) return null;
  for (const sel of INPUT_SELECTORS) {
    if (active.matches(sel)) return active;
  }
  // Fallback: pick the nearest visible input on the page.
  for (const sel of INPUT_SELECTORS) {
    const el = document.querySelector<HTMLElement>(sel);
    if (el) return el;
  }
  return null;
}


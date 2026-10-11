/**
 * ScamShield AI — Telegram Web Content Script
 * Targets web.telegram.org/a/ (Web A) and /k/ (Web K).
 * STRICT selectors: only message text, never UI chrome.
 */
(function () {
  'use strict';

  // ── Deduplication cache (FNV-1a 32-bit) ────────────────
  const scanCache = new Map();
  const DEDUP_WINDOW_MS = 60000;
  const MIN_TEXT_LEN = 12;

  function fnv1a32(str) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      hash ^= str.charCodeAt(i);
      hash = (hash * 0x01000193) >>> 0;
    }
    return hash;
  }

  function isDuplicate(text) {
    const hash = fnv1a32(text);
    const now = Date.now();
    if (scanCache.has(hash) && (now - scanCache.get(hash)) < DEDUP_WINDOW_MS) {
      return true;
    }
    scanCache.set(hash, now);
    if (scanCache.size > 500) {
      for (const [k, v] of scanCache) {
        if (now - v > DEDUP_WINDOW_MS) scanCache.delete(k);
      }
    }
    return false;
  }

  // ── Telegram message selectors ─────────────────────────
  // Web A selectors
  const WEB_A_SELECTORS = [
    '.message-content .text-content',
    '.translatable-message',
  ];

  // Web K selectors
  const WEB_K_SELECTORS = [
    '.message-container .text',
    '.message .text',
  ];

  // Exclusions — STRICTLY ignore Telegram UI buttons, labels, time, audio
  const EXCLUDE_SELECTORS = [
    '.reply-markup',
    '.audio-player',
    '.time',
    '.status',
    '.reply-title',
    'button',
    '[role="button"]',
    '.bubble-content-wrapper .reply-markup',
    '.forward-header',
  ];

  // Excluded text patterns (Telegram UI noise)
  const EXCLUDED_TEXTS = new Set([
    'voice message', 'video message', 'mark all as read',
    'photo', 'video', 'sticker', 'gif', 'document', 'contact',
    'location', 'poll', 'game', 'invoice', 'join',
  ]);

  function isExcluded(el) {
    for (const sel of EXCLUDE_SELECTORS) {
      if (el.closest(sel)) return true;
    }
    return false;
  }

  function isExcludedText(text) {
    return EXCLUDED_TEXTS.has(text.toLowerCase().trim());
  }

  // Detect which Telegram variant we're on
  function getSelectors() {
    if (location.pathname.includes('/k/') || location.pathname.includes('/k')) {
      return WEB_K_SELECTORS;
    }
    return WEB_A_SELECTORS;
  }

  // ── HUD Alert (Shadow DOM) ─────────────────────────────
  let hudHost = null;
  let hudShadow = null;

  function ensureHUD() {
    if (hudHost) return hudShadow;
    hudHost = document.createElement('div');
    hudHost.id = 'scamshield-hud-host';
    hudShadow = hudHost.attachShadow({ mode: 'closed' });
    hudShadow.innerHTML = `
      <style>
        .ss-alert {
          position: fixed;
          top: 16px;
          right: 16px;
          z-index: 2147483647;
          background: #fff;
          border: 1px solid #e2e8f0;
          border-radius: 12px;
          padding: 16px 20px;
          box-shadow: 0 20px 40px rgba(0,0,0,0.12);
          font-family: 'Inter', -apple-system, sans-serif;
          max-width: 360px;
          animation: slideIn 0.3s ease;
          display: none;
        }
        @keyframes slideIn {
          from { transform: translateX(120%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        .ss-alert.show { display: block; }
        .ss-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
        .ss-icon { width: 28px; height: 28px; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-size: 14px; }
        .ss-icon.danger { background: #fef2f2; color: #dc2626; }
        .ss-icon.warning { background: #fffbeb; color: #f59e0b; }
        .ss-title { font-size: 14px; font-weight: 700; color: #0f172a; }
        .ss-body { font-size: 12px; color: #475569; line-height: 1.5; margin-bottom: 10px; }
        .ss-chips { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 10px; }
        .ss-chip { padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; background: #fef2f2; color: #b91c1c; }
        .ss-chip.amber { background: #fffbeb; color: #b45309; }
        .ss-actions { display: flex; gap: 8px; }
        .ss-btn { padding: 6px 14px; border-radius: 6px; border: none; font-size: 11px; font-weight: 600; cursor: pointer; font-family: inherit; }
        .ss-btn.primary { background: #2563eb; color: #fff; }
        .ss-btn.secondary { background: #f1f5f9; color: #475569; }
      </style>
      <div class="ss-alert" id="ssAlert">
        <div class="ss-header">
          <div class="ss-icon danger" id="ssAlertIcon">🛡</div>
          <div class="ss-title" id="ssAlertTitle">Threat Detected</div>
        </div>
        <div class="ss-body" id="ssAlertBody"></div>
        <div class="ss-chips" id="ssAlertChips"></div>
        <div class="ss-actions">
          <button class="ss-btn primary" id="ssInspect">Inspect →</button>
          <button class="ss-btn secondary" id="ssDismiss">Dismiss</button>
        </div>
      </div>
    `;
    document.body.appendChild(hudHost);

    hudShadow.getElementById('ssDismiss').addEventListener('click', () => {
      hudShadow.getElementById('ssAlert').classList.remove('show');
    });

    hudShadow.getElementById('ssInspect').addEventListener('click', () => {
      const scanId = hudShadow.getElementById('ssAlert').dataset.scanId;
      if (scanId) {
        chrome.runtime.sendMessage({ type: 'OPEN_TRUSTLENS', scanId: parseInt(scanId) });
      }
      hudShadow.getElementById('ssAlert').classList.remove('show');
    });

    return hudShadow;
  }

  function showHUD(result) {
    if (!result || result.risk_score < 35) return;
    const shadow = ensureHUD();
    const alert = shadow.getElementById('ssAlert');
    const isHigh = result.risk_score >= 70;

    shadow.getElementById('ssAlertIcon').className = `ss-icon ${isHigh ? 'danger' : 'warning'}`;
    shadow.getElementById('ssAlertTitle').textContent =
      isHigh ? '🚨 High Risk Detected' : '⚠ Proceed with Caution';
    shadow.getElementById('ssAlertBody').textContent = result.explanation || '';

    const chips = shadow.getElementById('ssAlertChips');
    chips.innerHTML = '';
    (result.scam_dna || []).forEach(d => {
      const chip = document.createElement('span');
      chip.className = `ss-chip ${isHigh ? '' : 'amber'}`;
      chip.textContent = d;
      chips.appendChild(chip);
    });

    alert.dataset.scanId = result.id || '';
    alert.classList.add('show');
    setTimeout(() => alert.classList.remove('show'), 12000);
  }

  // ── Message collection & scanning ──────────────────────
  let scanTimer = null;

  function collectMessages() {
    const selectors = getSelectors();
    const messages = [];
    for (const sel of selectors) {
      document.querySelectorAll(sel).forEach(el => {
        if (isExcluded(el)) return;
        const text = (el.textContent || '').trim();
        if (text.length >= MIN_TEXT_LEN && !isExcludedText(text) && !isDuplicate(text)) {
          messages.push(text);
        }
      });
    }
    return messages;
  }

  function scheduleScan() {
    if (scanTimer) return;
    scanTimer = setTimeout(async () => {
      scanTimer = null;
      const msgs = collectMessages();
      if (msgs.length === 0) return;

      try {
        chrome.runtime.sendMessage({
          type: 'SCAN_CONVERSATION',
          payload: {
            platform: 'Telegram',
            sender: document.title || 'Telegram Chat',
            messages: msgs.slice(-20),
            page_url: location.href,
          },
        }, (result) => {
          if (result && result.risk_score >= 35) {
            showHUD(result);
          }
        });
      } catch (_) { /* Extension context invalidated */ }
    }, 2000);
  }

  // ── MutationObserver ───────────────────────────────────
  const observer = new MutationObserver((mutations) => {
    let hasNewText = false;
    for (const m of mutations) {
      if (m.type === 'childList' && m.addedNodes.length > 0) {
        hasNewText = true;
        break;
      }
    }
    if (hasNewText) scheduleScan();
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // Initial scan after page load
  setTimeout(scheduleScan, 3000);
})();

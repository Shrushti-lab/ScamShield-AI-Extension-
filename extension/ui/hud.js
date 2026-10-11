/**
 * ScamShield AI — Zero-Click Floating Security HUD
 * Docked top:24px; right:24px inside an isolated CLOSED Shadow DOM.
 * Immune to host page styles. Slide-in animation, verdict badge, reason,
 * Scam DNA chips, dismiss button, and click-to-reveal conversation masking.
 */
(function (global) {
  'use strict';

  let hudHost = null;
  let hudShadow = null;
  let dismissTimer = null;

  function ensureHost() {
    if (!hudHost || !hudHost.isConnected) {
      hudHost = document.createElement('div');
      hudHost.id = 'scamshield-hud-host';
      hudHost.style.position = 'fixed';
      hudHost.style.top = '24px';
      hudHost.style.right = '24px';
      hudHost.style.zIndex = '2147483647';
      hudHost.style.pointerEvents = 'none';

      // Closed Shadow DOM for bulletproof CSS isolation
      hudShadow = hudHost.attachShadow({ mode: 'closed' });
      document.documentElement.appendChild(hudHost);
    }
    return hudShadow;
  }

  function showHUD(data) {
    const shadow = ensureHost();
    if (dismissTimer) clearTimeout(dismissTimer);

    const isHighRisk = data.verdict === 'High Risk' || (data.risk_score && data.risk_score >= 70);
    const borderColor = isHighRisk ? '#dc2626' : '#f59e0b';
    const badgeBg = isHighRisk ? '#fef2f2' : '#fffbeb';
    const badgeColor = isHighRisk ? '#dc2626' : '#b45309';
    const dotColor = isHighRisk ? '#dc2626' : '#f59e0b';

    const dnaChips = (data.scam_dna || []).map(tag => `
      <span class="dna-chip">${escapeHTML(tag)}</span>
    `).join('');

    const scanId = data.id || '';
    const detailsUrl = scanId ? `http://127.0.0.1:8000/#/investigation/${scanId}` : 'http://127.0.0.1:8000/';

    shadow.innerHTML = `
      <style>
        :host { all: initial; }
        .hud-card {
          pointer-events: auto;
          font-family: 'Inter', system-ui, -apple-system, sans-serif;
          width: 360px;
          background: #ffffff;
          color: #0f172a;
          border: 1px solid #e2e8f0;
          border-left: 4px solid ${borderColor};
          border-radius: 12px;
          box-shadow: 0 12px 32px -4px rgba(15, 23, 42, 0.15), 0 4px 12px -2px rgba(15, 23, 42, 0.08);
          padding: 14px 16px;
          box-sizing: border-box;
          animation: slideIn 0.28s cubic-bezier(0.16, 1, 0.3, 1) forwards;
          transition: transform 0.2s ease, opacity 0.2s ease;
        }
        @keyframes slideIn {
          from { transform: translateX(120%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        .hud-header {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 8px;
        }
        .shield-icon {
          width: 20px;
          height: 20px;
          background: #2563eb;
          border-radius: 5px;
          display: flex;
          align-items: center;
          justify-content: center;
          color: #fff;
          flex-shrink: 0;
        }
        .hud-brand {
          font-size: 13px;
          font-weight: 700;
          letter-spacing: -0.01em;
          color: #0f172a;
        }
        .hud-brand span { color: #2563eb; }
        .verdict-badge {
          margin-left: auto;
          font-size: 11px;
          font-weight: 600;
          padding: 2px 8px;
          border-radius: 12px;
          background: ${badgeBg};
          color: ${badgeColor};
          display: flex;
          align-items: center;
          gap: 5px;
        }
        .verdict-dot {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: ${dotColor};
        }
        .hud-reason {
          font-size: 12.5px;
          line-height: 1.45;
          color: #334155;
          margin-bottom: 10px;
        }
        .dna-container {
          display: flex;
          flex-wrap: wrap;
          gap: 5px;
          margin-bottom: 12px;
        }
        .dna-chip {
          font-size: 10.5px;
          font-weight: 600;
          padding: 2px 7px;
          border-radius: 6px;
          background: #f1f5f9;
          color: #475569;
          border: 1px solid #e2e8f0;
        }
        .hud-actions {
          display: flex;
          align-items: center;
          gap: 8px;
          border-top: 1px solid #f1f5f9;
          padding-top: 10px;
        }
        .btn-inspect {
          flex: 1;
          font-size: 11.5px;
          font-weight: 600;
          padding: 6px 12px;
          background: #2563eb;
          color: #ffffff;
          border: none;
          border-radius: 6px;
          cursor: pointer;
          text-align: center;
          text-decoration: none;
        }
        .btn-inspect:hover { background: #1d4ed8; }
        .btn-dismiss {
          font-size: 11.5px;
          font-weight: 500;
          padding: 6px 10px;
          background: #f8fafc;
          color: #64748b;
          border: 1px solid #cbd5e1;
          border-radius: 6px;
          cursor: pointer;
        }
        .btn-dismiss:hover { background: #f1f5f9; color: #0f172a; }
      </style>

      <div class="hud-card" id="hudCard">
        <div class="hud-header">
          <div class="shield-icon">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <span class="hud-brand">ScamShield <span>AI</span></span>
          <span class="verdict-badge">
            <span class="verdict-dot"></span>
            ${escapeHTML(data.verdict || 'Threat Detected')}
          </span>
        </div>

        <div class="hud-reason">
          ${escapeHTML(data.explanation || data.reason || 'Suspicious scam signature intercepted.')}
        </div>

        ${dnaChips ? `<div class="dna-container">${dnaChips}</div>` : ''}

        <div class="hud-actions">
          <button class="btn-inspect" id="btnInspect">Inspect with TrustLens →</button>
          <button class="btn-dismiss" id="btnDismiss">Dismiss</button>
        </div>
      </div>
    `;

    const btnDismiss = shadow.getElementById('btnDismiss');
    if (btnDismiss) {
      btnDismiss.addEventListener('click', () => hideHUD());
    }

    const btnInspect = shadow.getElementById('btnInspect');
    if (btnInspect) {
      btnInspect.addEventListener('click', () => {
        window.open(detailsUrl, '_blank');
        hideHUD();
      });
    }

    // Auto-dismiss for lower severities (Proceed Carefully hides after 8s; High Risk stays)
    if (!isHighRisk) {
      dismissTimer = setTimeout(() => hideHUD(), 8000);
    }
  }

  function hideHUD() {
    if (hudShadow) {
      const card = hudShadow.getElementById('hudCard');
      if (card) {
        card.style.transform = 'translateX(120%)';
        card.style.opacity = '0';
        setTimeout(() => {
          if (hudHost && hudHost.isConnected) hudHost.remove();
          hudHost = null;
          hudShadow = null;
        }, 250);
      }
    }
  }

  function escapeHTML(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function maskElement(element, handle) {
    if (!element || element.dataset.scamshieldMasked) return;
    element.dataset.scamshieldMasked = 'true';

    const originalFilter = element.style.filter;
    element.style.filter = 'blur(6px)';
    element.style.userSelect = 'none';
    element.style.position = 'relative';

    const overlay = document.createElement('div');
    overlay.className = 'scamshield-blocked-overlay';
    overlay.style.position = 'absolute';
    overlay.style.top = '0';
    overlay.style.left = '0';
    overlay.style.right = '0';
    overlay.style.bottom = '0';
    overlay.style.background = 'rgba(254, 242, 242, 0.85)';
    overlay.style.display = 'flex';
    overlay.style.alignItems = 'center';
    overlay.style.justifyContent = 'center';
    overlay.style.zIndex = '9999';
    overlay.style.borderRadius = '8px';
    overlay.style.cursor = 'pointer';

    overlay.innerHTML = `
      <div style="font-family:sans-serif; text-align:center; padding:10px;">
        <div style="color:#b91c1c; font-weight:700; font-size:12px; margin-bottom:4px;">🚫 Message from Blocked Sender (${escapeHTML(handle)})</div>
        <div style="color:#64748b; font-size:11px;">Click to reveal content</div>
      </div>
    `;

    overlay.addEventListener('click', (e) => {
      e.stopPropagation();
      element.style.filter = originalFilter;
      element.style.userSelect = 'auto';
      overlay.remove();
    });

    if (element.parentNode) {
      element.parentNode.insertBefore(overlay, element);
    }
  }

  global.ScamShieldHUD = {
    show: showHUD,
    hide: hideHUD,
    mask: maskElement,
  };
})(typeof window !== 'undefined' ? window : this);

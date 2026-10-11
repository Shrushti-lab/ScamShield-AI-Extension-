/**
 * ScamShield AI — Popup Logic
 */
(function () {
  'use strict';

  const API_BASE = 'http://127.0.0.1:8000';

  function verdictClass(v) {
    if (v === 'High Risk') return 'danger';
    if (v === 'Proceed Carefully') return 'warning';
    return 'safe';
  }

  function verdictLabel(v) {
    if (v === 'High Risk') return 'High Risk';
    if (v === 'Proceed Carefully') return 'Caution';
    return 'Safe';
  }

  function dotColor(v) {
    if (v === 'High Risk') return '#dc2626';
    if (v === 'Proceed Carefully') return '#f59e0b';
    return '#10b981';
  }

  async function loadStats() {
    try {
      const res = await fetch(`${API_BASE}/api/stats`);
      const data = await res.json();
      document.getElementById('popChecked').textContent = data.items_checked || 0;
      document.getElementById('popWarnings').textContent = data.warnings || 0;
      document.getElementById('popHighRisk').textContent = data.high_risk || 0;
    } catch (_) {
      document.getElementById('popChecked').textContent = '—';
    }
  }

  async function loadRecent() {
    try {
      const res = await fetch(`${API_BASE}/api/scans?limit=5`);
      const data = await res.json();
      const el = document.getElementById('popScans');
      if (!data.scans || data.scans.length === 0) {
        el.innerHTML = '<div style="font-size:11px;color:#94a3b8;text-align:center;padding:8px;">No scans yet</div>';
        return;
      }
      el.innerHTML = data.scans.map(s => `
        <div class="popup-scan-item">
          <span class="popup-dot" style="background:${dotColor(s.verdict)}"></span>
          <span class="popup-scan-target">${s.target || 'Unknown'}</span>
          <span class="popup-badge ${verdictClass(s.verdict)}">${verdictLabel(s.verdict)}</span>
        </div>
      `).join('');
    } catch (_) {
      document.getElementById('popScans').innerHTML =
        '<div style="font-size:11px;color:#94a3b8;text-align:center;padding:8px;">Server offline</div>';
    }
  }

  // Open Portal
  document.getElementById('btnPortal').addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'OPEN_PORTAL' });
    window.close();
  });

  // Scan current page URL
  document.getElementById('btnScanPage').addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) return;
    chrome.runtime.sendMessage({
      type: 'SCAN_URL',
      payload: { url: tab.url },
    }, (result) => {
      if (result && result.id) {
        chrome.runtime.sendMessage({ type: 'OPEN_TRUSTLENS', scanId: result.id });
        window.close();
      }
    });
  });

  loadStats();
  loadRecent();
})();

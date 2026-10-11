/**
 * ScamShield AI — Popup Logic
 * 3 Working Buttons:
 *  1. [ Block Sender ] -> saves handle to chrome.storage.local AND POST /api/blocklist
 *  2. [ Report Scam ] -> POST /api/reports
 *  3. [ View Details ] -> opens http://127.0.0.1:8000/#/investigation/<id> in new tab
 */
(function () {
  'use strict';

  const API_BASE = 'http://127.0.0.1:8000';
  let currentTargetHandle = '@unknown_user';
  let currentPlatform = 'Web';
  let latestScanId = 1;

  async function apiCall(endpoint, method = 'GET', body = null) {
    try {
      const opts = { method, headers: { 'Content-Type': 'application/json' } };
      if (body) opts.body = JSON.stringify(body);
      const res = await fetch(`${API_BASE}${endpoint}`, opts);
      return await res.json();
    } catch (e) {
      console.warn('ScamShield popup fetch error:', e);
      return null;
    }
  }

  async function initPopup() {
    // 1. Query active tab
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs && tabs[0]) {
          const tab = tabs[0];
          const url = tab.url || '';
          if (url.includes('facebook.com') || url.includes('messenger.com')) {
            currentPlatform = 'Messenger';
            currentTargetHandle = '@fb_conversation';
          } else if (url.includes('web.telegram.org')) {
            currentPlatform = 'Telegram';
            currentTargetHandle = '@telegram_chat';
          } else {
            currentPlatform = 'Web';
            try {
              const u = new URL(url);
              currentTargetHandle = u.hostname || url;
            } catch (_) {
              currentTargetHandle = url;
            }
          }
          document.getElementById('popCurrentTarget').textContent = `${currentPlatform}: ${currentTargetHandle}`;
        }
      });
    } else {
      document.getElementById('popCurrentTarget').textContent = 'Web: 127.0.0.1:8000';
    }

    // 2. Fetch stats
    const stats = await apiCall('/api/stats');
    if (stats) {
      document.getElementById('miniChecked').textContent = stats.items_checked || 0;
      document.getElementById('miniWarnings').textContent = stats.warnings || 0;
      document.getElementById('miniHighRisk').textContent = stats.high_risk || 0;
    }

    // 3. Fetch latest scan ID for View Details
    const scansData = await apiCall('/api/scans?limit=1');
    if (scansData && scansData.scans && scansData.scans.length > 0) {
      latestScanId = scansData.scans[0].id;
    }

    // 4. Wire 3 Buttons
    const btnBlock = document.getElementById('btnBlockSender');
    btnBlock.addEventListener('click', async () => {
      const handleToBlock = currentTargetHandle;
      btnBlock.disabled = true;
      btnBlock.textContent = 'Blocking...';

      // 1. Save in chrome.storage.local
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['blocked_senders'], (res) => {
          const list = (res && res.blocked_senders) || [];
          if (!list.includes(handleToBlock)) {
            list.push(handleToBlock);
            chrome.storage.local.set({ blocked_senders: list });
          }
        });
      }

      // 2. POST /api/blocklist
      await apiCall('/api/blocklist', 'POST', {
        handle: handleToBlock,
        platform: currentPlatform,
      });

      btnBlock.textContent = 'Sender Blocked ✓';
      setTimeout(() => {
        btnBlock.disabled = false;
        btnBlock.textContent = 'Block Current Sender';
      }, 2000);
    });

    const btnReport = document.getElementById('btnReportScam');
    btnReport.addEventListener('click', async () => {
      btnReport.disabled = true;
      btnReport.textContent = 'Submitting...';

      await apiCall('/api/reports', 'POST', {
        platform: currentPlatform,
        handle_or_url: currentTargetHandle,
        category: 'Suspicious Activity',
        note: 'Reported directly via ScamShield Chrome Extension popup',
      });

      btnReport.textContent = 'Report Submitted ✓';
      setTimeout(() => {
        btnReport.disabled = false;
        btnReport.textContent = 'Report Scam Incident';
      }, 2000);
    });

    const btnDetails = document.getElementById('btnViewDetails');
    btnDetails.addEventListener('click', () => {
      const targetUrl = `${API_BASE}/#/investigation/${latestScanId}`;
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
        chrome.tabs.create({ url: targetUrl });
      } else {
        window.open(targetUrl, '_blank');
      }
    });
  }

  document.addEventListener('DOMContentLoaded', initPopup);
})();

/**
 * ScamShield AI — Background Service Worker (Manifest V3)
 * Relays scans from content scripts to backend, manages heartbeat, and badge updates.
 */

const API_BASE = 'http://127.0.0.1:8000';

// ── Periodic Heartbeat Alarm ──────────────────────────────────
chrome.alarms.create('scamshield_heartbeat', { periodInMinutes: 0.35 });

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'scamshield_heartbeat') {
    try {
      await fetch(`${API_BASE}/api/extension/heartbeat`, { method: 'POST' });
    } catch (_) {
      // Backend server offline
    }
  }
});

// Immediate heartbeat on worker activation
try {
  fetch(`${API_BASE}/api/extension/heartbeat`, { method: 'POST' }).catch(() => {});
} catch (_) {}

// ── Message Dispatcher ─────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'SCAN_CONVERSATION') {
    postJSON('/api/scan/conversation', msg.payload)
      .then(res => {
        updateBadge(res);
        sendResponse(res);
      })
      .catch(err => sendResponse({ error: err.message }));
    return true;
  }

  if (msg.type === 'SCAN_LISTING') {
    postJSON('/api/scan/listing', msg.payload)
      .then(res => {
        updateBadge(res);
        sendResponse(res);
      })
      .catch(err => sendResponse({ error: err.message }));
    return true;
  }

  if (msg.type === 'SCAN_URL') {
    postJSON('/api/scan/url', msg.payload)
      .then(res => {
        updateBadge(res);
        sendResponse(res);
      })
      .catch(err => sendResponse({ error: err.message }));
    return true;
  }

  if (msg.type === 'SCAN_PAYMENT') {
    postJSON('/api/scan/payment-form', msg.payload)
      .then(res => {
        updateBadge(res);
        sendResponse(res);
      })
      .catch(err => sendResponse({ error: err.message }));
    return true;
  }

  if (msg.type === 'OPEN_INVESTIGATION') {
    const id = msg.scanId || '';
    chrome.tabs.create({ url: `${API_BASE}/#/investigation/${id}` });
    sendResponse({ status: 'opened' });
    return false;
  }
});

async function postJSON(endpoint, data) {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  return await res.json();
}

function updateBadge(result) {
  if (!result || !result.verdict) return;
  if (result.verdict === 'High Risk') {
    chrome.action.setBadgeText({ text: '!' });
    chrome.action.setBadgeBackgroundColor({ color: '#dc2626' });
  } else if (result.verdict === 'Proceed Carefully') {
    chrome.action.setBadgeText({ text: '▲' });
    chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' });
  } else {
    chrome.action.setBadgeText({ text: '✓' });
    chrome.action.setBadgeBackgroundColor({ color: '#10b981' });
  }
}

/**
 * ScamShield AI — Content Script Common Utilities
 * - FNV-1a 32-bit in-memory text hash set for zero-duplicate scanning
 * - Debounce utility for virtualized MutationObservers
 * - Storage sync for blocked senders
 * - Backend API relay through service worker
 */
(function (global) {
  'use strict';

  // 32-bit FNV-1a hash implementation
  function fnv1a(str) {
    let hash = 2166136261;
    for (let i = 0; i < str.length; i++) {
      hash ^= str.charCodeAt(i);
      hash = (hash * 16777619) >>> 0;
    }
    return hash;
  }

  const scannedTextHashes = new Set();
  const blockedSenders = new Set();

  function isScanned(sender, text) {
    const key = `${sender || ''}::${(text || '').trim()}`;
    const hash = fnv1a(key);
    if (scannedTextHashes.has(hash)) {
      return true;
    }
    scannedTextHashes.add(hash);
    return false;
  }

  function debounce(fn, wait = 300) {
    let timeout;
    return function (...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => fn.apply(this, args), wait);
    };
  }

  // Load and sync blocked senders from storage
  function syncBlockedSenders() {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['blocked_senders'], (res) => {
        if (res && res.blocked_senders) {
          blockedSenders.clear();
          (res.blocked_senders || []).forEach(h => blockedSenders.add(h.toLowerCase()));
        }
      });
    }
  }

  function isSenderBlocked(handle) {
    if (!handle) return false;
    return blockedSenders.has(handle.toLowerCase().trim());
  }

  // Send scan request to background service worker
  function relayScan(type, payload) {
    return new Promise((resolve, reject) => {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ type, payload }, (res) => {
          if (chrome.runtime.lastError) {
            resolve({ error: chrome.runtime.lastError.message });
          } else {
            resolve(res || {});
          }
        });
      } else {
        // Direct fetch fallback for local demo offline testing
        fetch(`http://127.0.0.1:8000/api/${type === 'SCAN_CONVERSATION' ? 'scan/conversation' : (type === 'SCAN_LISTING' ? 'scan/listing' : 'scan/payment-form')}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        })
          .then(r => r.json())
          .then(resolve)
          .catch(err => resolve({ error: err.message }));
      }
    });
  }

  // Handle detection result: show HUD and play chime if threat
  function handleScanResult(result, senderHandle, messageElements = []) {
    if (!result || result.error) return;

    if (result.verdict === 'High Risk' || result.verdict === 'Proceed Carefully') {
      if (global.ScamShieldHUD) {
        global.ScamShieldHUD.show(result);
      }
      if (global.ScamShieldChime) {
        const severity = result.verdict === 'High Risk' ? 'critical' : 'warning';
        global.ScamShieldChime.play(severity);
      }
    }

    if (senderHandle && isSenderBlocked(senderHandle)) {
      if (global.ScamShieldHUD) {
        global.ScamShieldHUD.show({
          verdict: 'Blocked Sender',
          explanation: `Messages from ${senderHandle} are blocked by your security settings.`,
          scam_dna: ['Blocked Sender'],
        });
      }
      messageElements.forEach(el => {
        if (global.ScamShieldHUD) global.ScamShieldHUD.mask(el, senderHandle);
      });
    }
  }

  syncBlockedSenders();

  global.ScamShieldCommon = {
    fnv1a,
    isScanned,
    debounce,
    isSenderBlocked,
    syncBlockedSenders,
    relayScan,
    handleScanResult,
  };
})(typeof window !== 'undefined' ? window : this);

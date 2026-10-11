/**
 * ScamShield AI — Facebook Messenger Content Script
 * Real-time interception for Messenger chats on facebook.com & messenger.com
 * Includes UI noise filters, virtualized DOM mutation debounce, deduplication, and HUD triggers.
 */
(function () {
  'use strict';

  const FB_CONFIG = {
    // Selectors with fallbacks
    messageContainers: [
      "div[role='row'] .x1n2onr6",
      "div[data-testid='outgoing_group']",
      "div[data-testid='incoming_group']",
      ".x1n2onr6 div[dir='auto']",
      ".message-bubble-text", // demo fallback
      "div[role='main'] div[dir='auto']",
    ],
    senderSelectors: [
      "h2 span",
      "span[data-testid='conversation_header_title']",
      ".chat-header-name", // demo fallback
      "span.x193iq5w",
    ],
    // UI chrome noise to ignore
    ignoredTextPatterns: [
      /^seen\b/i,
      /^delivered$/i,
      /^sent$/i,
      /^active now$/i,
      /^\d{1,2}:\d{2}\s*(am|pm)?$/i,
      /^reacted to your message/i,
      /^replying to/i,
      /^press enter to send/i,
    ],
  };

  function getSenderName() {
    for (const sel of FB_CONFIG.senderSelectors) {
      const el = document.querySelector(sel);
      if (el && el.innerText.trim()) {
        return el.innerText.trim();
      }
    }
    return "@facebook_user";
  }

  function isNoise(text) {
    if (!text || text.length < 3) return true;
    for (const pattern of FB_CONFIG.ignoredTextPatterns) {
      if (pattern.test(text.trim())) return true;
    }
    return false;
  }

  function scanMessengerMessages() {
    const sender = getSenderName();
    const newMessages = [];
    const elementsToMask = [];

    for (const selector of FB_CONFIG.messageContainers) {
      const nodes = document.querySelectorAll(selector);
      nodes.forEach(node => {
        const text = (node.innerText || node.textContent || '').trim();
        if (!text || isNoise(text)) return;

        // Check if sender is blocked
        if (window.ScamShieldCommon && window.ScamShieldCommon.isSenderBlocked(sender)) {
          elementsToMask.push(node);
        }

        // Deduplicate with FNV-1a hash
        if (window.ScamShieldCommon && !window.ScamShieldCommon.isScanned(sender, text)) {
          newMessages.push(text);
        }
      });
    }

    if (newMessages.length === 0 && elementsToMask.length === 0) return;

    if (elementsToMask.length > 0 && window.ScamShieldCommon) {
      window.ScamShieldCommon.handleScanResult(
        { verdict: 'Blocked Sender', explanation: `Blocked sender ${sender}`, scam_dna: ['Blocked Sender'] },
        sender,
        elementsToMask
      );
    }

    if (newMessages.length > 0 && window.ScamShieldCommon) {
      window.ScamShieldCommon.relayScan('SCAN_CONVERSATION', {
        platform: 'Messenger',
        sender: sender,
        messages: newMessages,
        page_url: window.location.href,
      }).then(result => {
        window.ScamShieldCommon.handleScanResult(result, sender, elementsToMask);
      });
    }
  }

  const debouncedScan = window.ScamShieldCommon
    ? window.ScamShieldCommon.debounce(scanMessengerMessages, 350)
    : scanMessengerMessages;

  const observer = new MutationObserver((mutations) => {
    let shouldScan = false;
    for (const m of mutations) {
      if (m.addedNodes.length > 0) {
        shouldScan = true;
        break;
      }
    }
    if (shouldScan) debouncedScan();
  });

  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true,
  });

  // Initial check
  setTimeout(scanMessengerMessages, 600);
})();

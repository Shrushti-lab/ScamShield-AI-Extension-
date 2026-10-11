/**
 * ScamShield AI — Telegram Web Content Script
 * Supports web.telegram.org/a/ and web.telegram.org/k/
 * Detects: Crypto airdrop lures, wallet drainers, 12/24-word seed phrase harvesting,
 * INR/UPI lotteries, fake admin impersonation.
 * Filters: Voice messages, timestamps, service notifications.
 */
(function () {
  'use strict';

  const TG_CONFIG = {
    // Selectors for Telegram A and Telegram K
    messageSelectors: [
      ".message-content-wrapper",     // Telegram A
      ".bubble-content-wrapper",      // Telegram A
      ".im-message-text",             // Telegram K
      ".bubble .message",             // Telegram K
      ".tg-message-text",             // Demo fallback
      ".text-content",                // Generic Telegram Web
    ],
    senderSelectors: [
      ".chat-info .peer-title",       // Telegram A
      ".im-page-chat-header .user-title", // Telegram K
      ".chat-title",                  // Fallback
      ".tg-chat-name",                // Demo fallback
      ".top-bar .title",
    ],
    ignoredPatterns: [
      /^voice message$/i,
      /^video message$/i,
      /^mark all as read$/i,
      /^\d{1,2}:\d{2}$/,
      /^\d{1,2}:\d{2}\s*(am|pm)$/i,
      /^pinned a message$/i,
      /^joined the group$/i,
      /^audio$/i,
    ],
  };

  function getSender() {
    for (const sel of TG_CONFIG.senderSelectors) {
      const el = document.querySelector(sel);
      if (el && el.innerText.trim()) {
        return el.innerText.trim();
      }
    }
    return "@telegram_user";
  }

  function isNoise(text) {
    if (!text || text.length < 4) return true;
    for (const p of TG_CONFIG.ignoredPatterns) {
      if (p.test(text.trim())) return true;
    }
    return false;
  }

  function scanTelegramChat() {
    const sender = getSender();
    const newMessages = [];
    const elementsToMask = [];

    for (const sel of TG_CONFIG.messageSelectors) {
      const nodes = document.querySelectorAll(sel);
      nodes.forEach(node => {
        // Skip audio/media player sub-nodes
        if (node.querySelector('.audio-player') || node.classList.contains('service-msg')) {
          return;
        }

        const text = (node.innerText || node.textContent || '').trim();
        if (!text || isNoise(text)) return;

        // Check blocked sender
        if (window.ScamShieldCommon && window.ScamShieldCommon.isSenderBlocked(sender)) {
          elementsToMask.push(node);
        }

        // Deduplication
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
        platform: 'Telegram',
        sender: sender,
        messages: newMessages,
        page_url: window.location.href,
      }).then(result => {
        window.ScamShieldCommon.handleScanResult(result, sender, elementsToMask);
      });
    }
  }

  const debouncedScan = window.ScamShieldCommon
    ? window.ScamShieldCommon.debounce(scanTelegramChat, 300)
    : scanTelegramChat;

  const observer = new MutationObserver(debouncedScan);
  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true,
  });

  setTimeout(scanTelegramChat, 500);
})();

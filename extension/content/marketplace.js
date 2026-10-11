/**
 * ScamShield AI — Facebook Marketplace Content Script
 * Detects severe price deviations (>60%), burner seller accounts, and courier pretexts.
 */
(function () {
  'use strict';

  const MKT_CONFIG = {
    itemContainers: [
      "div[data-testid='marketplace_feed_item']",
      ".marketplace-listing-card", // demo fallback
      "div[role='main'] div.x1gslohp",
    ],
    titleSelectors: [
      "span[data-testid='marketplace_listing_title']",
      "h1",
      ".listing-title",
      "span.x1lliihq.x6ikm8r.x10wlt62",
    ],
    priceSelectors: [
      "span[data-testid='marketplace_listing_price']",
      ".listing-price",
      "span.x193iq5w.xeuugli.x13faqbe",
    ],
    sellerSelectors: [
      "a[href*='/marketplace/profile/']",
      ".seller-name",
      "span.seller-info",
    ],
  };

  function parsePrice(text) {
    if (!text) return 0;
    const clean = text.replace(/[^0-9.]/g, '');
    return parseFloat(clean) || 0;
  }

  function scanMarketplaceListings() {
    for (const containerSel of MKT_CONFIG.itemContainers) {
      const items = document.querySelectorAll(containerSel);
      items.forEach(item => {
        let title = '';
        let price = 0;
        let seller = '';

        for (const sel of MKT_CONFIG.titleSelectors) {
          const el = item.querySelector(sel);
          if (el && el.innerText.trim()) {
            title = el.innerText.trim();
            break;
          }
        }

        for (const sel of MKT_CONFIG.priceSelectors) {
          const el = item.querySelector(sel);
          if (el && el.innerText.trim()) {
            price = parsePrice(el.innerText);
            break;
          }
        }

        for (const sel of MKT_CONFIG.sellerSelectors) {
          const el = item.querySelector(sel);
          if (el && el.innerText.trim()) {
            seller = el.innerText.trim();
            break;
          }
        }

        if (!title && !price) {
          // If viewing listing details directly
          const h1 = document.querySelector('h1');
          if (h1) title = h1.innerText.trim();
          const priceEl = document.querySelector('.listing-price');
          if (priceEl) price = parsePrice(priceEl.innerText);
        }

        if (!title) return;

        // Deduplication
        if (window.ScamShieldCommon && window.ScamShieldCommon.isScanned('mkt', `${title}:${price}`)) {
          return;
        }

        const description = (item.innerText || '').slice(0, 500);

        if (window.ScamShieldCommon) {
          window.ScamShieldCommon.relayScan('SCAN_LISTING', {
            title: title,
            price: price,
            currency: 'USD',
            seller_joined: 'Recently joined',
            seller_name: seller || 'Marketplace Seller',
            description: description,
            messages: [],
          }).then(result => {
            window.ScamShieldCommon.handleScanResult(result, seller);
          });
        }
      });
    }
  }

  const debouncedScan = window.ScamShieldCommon
    ? window.ScamShieldCommon.debounce(scanMarketplaceListings, 400)
    : scanMarketplaceListings;

  const observer = new MutationObserver(debouncedScan);
  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true,
  });

  setTimeout(scanMarketplaceListings, 700);
})();

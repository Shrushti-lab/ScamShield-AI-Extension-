/**
 * ScamShield AI — CardGuard Content Script
 * STRICT ZERO-ACCESS PRIVACY POLICY: Never reads or transmits user typed values.
 * Only reads input attribute names (e.g. name, id, autocomplete).
 */
(function () {
  'use strict';

  const CARD_FIELD_SELECTOR = [
    'input[autocomplete*="cc-"]',
    'input[name*="card"]',
    'input[name*="cvv"]',
    'input[name*="cvc"]',
    'input[name*="exp"]',
    'input[id*="card"]',
    'input[id*="cvv"]',
    'input[id*="cvc"]',
  ].join(', ');

  let hasFlaggedPage = false;

  function inspectCheckoutForms() {
    if (hasFlaggedPage) return;

    const cardFields = document.querySelectorAll(CARD_FIELD_SELECTOR);
    if (cardFields.length === 0) return;

    // Zero-access: collect only attribute names, NEVER input values!
    const fieldSignals = [];
    cardFields.forEach(f => {
      const nameAttr = f.getAttribute('name') || f.getAttribute('id') || f.getAttribute('autocomplete') || '';
      fieldSignals.push(nameAttr);
    });

    if (window.ScamShieldCommon) {
      window.ScamShieldCommon.relayScan('SCAN_PAYMENT', {
        url: window.location.href,
        field_signals: fieldSignals,
      }).then(result => {
        if (!result || result.error) return;

        if (result.verdict === 'High Risk' || result.verdict === 'Proceed Carefully') {
          hasFlaggedPage = true;

          // Show security HUD
          if (window.ScamShieldHUD) {
            window.ScamShieldHUD.show({
              id: result.id,
              verdict: 'High Risk',
              risk_score: 95,
              explanation: 'CardGuard Alert: Unverified or deceptive domain detected requesting credit card payment information. Form submit intercepted.',
              scam_dna: ['Credit Card Harvester', 'Unverified Merchant'],
            });
          }

          if (window.ScamShieldChime) {
            window.ScamShieldChime.play('critical');
          }

          // Intercept and prevent form submit
          document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', (e) => {
              e.preventDefault();
              e.stopPropagation();
              alert('ScamShield CardGuard: Form submission blocked. This checkout domain is unverified or potentially malicious.');
              return false;
            }, true);
          });
        }
      });
    }
  }

  // Monitor DOM for dynamically injected checkout forms
  const observer = new MutationObserver(() => {
    inspectCheckoutForms();
  });

  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true,
  });

  setTimeout(inspectCheckoutForms, 500);
})();

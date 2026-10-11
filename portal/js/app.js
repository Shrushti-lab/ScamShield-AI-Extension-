/**
 * ScamShield AI — Portal Application Logic
 * Powers all dashboard, investigations, TrustLens, reports, and settings views.
 */
(function () {
  'use strict';

  const API = '';  // same origin
  let allScans = [];
  let currentFilter = 'all';

  // ── Utility ──────────────────────────────────────────────
  function $(sel) { return document.querySelector(sel); }
  function $$(sel) { return document.querySelectorAll(sel); }

  async function api(path, opts) {
    try {
      const res = await fetch(`${API}${path}`, opts);
      return await res.json();
    } catch (e) {
      console.error('API error:', path, e);
      return null;
    }
  }

  function verdictClass(v) {
    if (v === 'High Risk') return 'danger';
    if (v === 'Proceed Carefully') return 'warning';
    return 'safe';
  }

  function verdictLabel(v) {
    if (v === 'High Risk') return 'High Risk';
    if (v === 'Proceed Carefully') return 'Proceed Carefully';
    return 'Safe';
  }

  function dotColor(v) {
    if (v === 'High Risk') return 'var(--red)';
    if (v === 'Proceed Carefully') return 'var(--amber)';
    return 'var(--green)';
  }

  function timeAgo(ts) {
    if (!ts) return '';
    const d = new Date(ts + 'Z');
    const diff = (Date.now() - d.getTime()) / 1000;
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return d.toLocaleDateString();
  }

  function escHTML(str) {
    if (str === null || str === undefined) return '';
    const d = document.createElement('div');
    d.textContent = String(str);
    return d.innerHTML;
  }

  // ── Navigation & Hash Routing ─────────────────────────────
  function showPage(name) {
    $$('.page').forEach(p => p.classList.remove('active'));
    $$('.nav-tab').forEach(t => t.classList.remove('active'));
    const page = $(`#page-${name}`);
    if (page) page.classList.add('active');
    const tab = $(`.nav-tab[data-page="${name}"]`);
    if (tab) tab.classList.add('active');
  }

  function handleRoute() {
    const hash = window.location.hash || '#/dashboard';
    if (hash.startsWith('#/investigation/')) {
      const id = hash.replace('#/investigation/', '').trim();
      if (id) {
        window._openTrustLens(id, false);
        return;
      }
    }

    if (hash === '#/investigations') {
      showPage('investigations');
      loadInvestigations();
    } else if (hash === '#/reports') {
      showPage('reports');
      loadReports();
      loadBenchmark();
    } else if (hash === '#/settings') {
      showPage('settings');
      loadSettings();
      loadBlocklist();
    } else {
      showPage('dashboard');
      loadStats();
      loadRecentScans();
    }
  }

  window.addEventListener('hashchange', handleRoute);

  $$('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const page = tab.dataset.page;
      window.location.hash = `#/${page}`;
    });
  });

  // ── Stats ────────────────────────────────────────────────
  async function loadStats() {
    const data = await api('/api/stats');
    if (!data) return;
    const statusEl = $('#stat-status');
    const checkedEl = $('#stat-checked');
    const warningsEl = $('#stat-warnings');
    const highriskEl = $('#stat-highrisk');

    if (statusEl) statusEl.textContent = data.status || 'Active';
    if (checkedEl) checkedEl.textContent = data.items_checked || 0;
    if (warningsEl) warningsEl.textContent = data.warnings || 0;
    if (highriskEl) highriskEl.textContent = data.high_risk || 0;

    // Update platform distribution chart if present
    if (data.by_platform) {
      updatePlatformChart(data.by_platform, data.items_checked || 0);
    }
  }

  function updatePlatformChart(byPlatform, total) {
    const fb = (byPlatform.Facebook || 0) + (byPlatform.Messenger || 0) + (byPlatform.Marketplace || 0);
    const tg = byPlatform.Telegram || 0;
    const web = (byPlatform.Web || 0) + (byPlatform.Other || 0);

    const safeTotal = total > 0 ? total : 1;
    const fbPct = Math.round((fb / safeTotal) * 100);
    const tgPct = Math.round((tg / safeTotal) * 100);
    const webPct = Math.max(0, 100 - fbPct - tgPct);

    const barFb = $('#bar-fb');
    const valFb = $('#val-fb');
    if (barFb && valFb) {
      barFb.style.width = `${fbPct}%`;
      valFb.textContent = `${fbPct}% (${fb})`;
    }

    const barTg = $('#bar-tg');
    const valTg = $('#val-tg');
    if (barTg && valTg) {
      barTg.style.width = `${tgPct}%`;
      valTg.textContent = `${tgPct}% (${tg})`;
    }

    const barWeb = $('#bar-web');
    const valWeb = $('#val-web');
    if (barWeb && valWeb) {
      barWeb.style.width = `${webPct}%`;
      valWeb.textContent = `${webPct}% (${web})`;
    }
  }

  // ── Scan Item HTML ───────────────────────────────────────
  function scanItemHTML(s) {
    const targetText = s.target || s.primary_text || 'Threat Target';
    const subText = s.secondary_text || `${s.platform || 'System'} Threat Scan for ${s.category || 'Endpoint'}`;
    const badgeCls = verdictClass(s.verdict);
    const label = verdictLabel(s.verdict);

    return `
      <div class="scan-item" data-id="${s.id}" onclick="if(!event.target.closest('button')) window.location.hash='#/investigation/${s.id}'" style="cursor: pointer;">
        <div class="scan-left">
          <span class="scan-dot" style="background:${dotColor(s.verdict)}"></span>
          <div class="scan-info">
            <div class="scan-target" style="font-weight: 700;">${escHTML(targetText)}</div>
            <div class="scan-meta" style="color: var(--muted);">${escHTML(subText)}</div>
          </div>
        </div>
        <div class="scan-right">
          <span class="badge ${badgeCls}"><span class="bdot"></span>${label}</span>
          <button class="btn-trustlens" onclick="event.stopPropagation(); window.location.hash='#/investigation/${s.id}';">Inspect with TrustLens →</button>
        </div>
      </div>`;
  }

  // ── Recent Scans (Dashboard) ─────────────────────────────
  async function loadRecentScans() {
    const data = await api('/api/scans?limit=10');
    if (!data || !data.scans) return;
    allScans = data.scans;
    const el = $('#recentScans');
    if (data.scans.length === 0) {
      el.innerHTML = '<div class="empty-state">No scans yet. Install the extension to start scanning.</div>';
      return;
    }
    el.innerHTML = data.scans.map(scanItemHTML).join('');

    // Update provenance trace for latest scan
    if (data.scans.length > 0) {
      const latest = data.scans[0];
      const traceDom = $('#trace-dom');
      const traceEp = $('#trace-endpoint');
      const traceEng = $('#trace-engine');
      const traceRec = $('#trace-record-id');

      if (traceDom && latest.pipeline_trace && latest.pipeline_trace.dom_selector) {
        traceDom.innerHTML = `Observed via <code>${escHTML(latest.pipeline_trace.dom_selector)}</code>`;
      }
      if (traceEp && latest.endpoint) {
        traceEp.innerHTML = `Relayed to <code>${escHTML(latest.endpoint)}</code>`;
      }
      if (traceEng && latest.engine_used) {
        traceEng.textContent = latest.engine_used;
      }
      if (traceRec) {
        traceRec.textContent = latest.id;
      }
    }
  }

  // ── Investigations ───────────────────────────────────────
  async function loadInvestigations() {
    const data = await api('/api/scans?limit=200');
    if (!data || !data.scans) return;
    allScans = data.scans;
    renderInvestigations();
  }

  function renderInvestigations() {
    const el = $('#investigationList');
    if (!el) return;
    let filtered = allScans;
    if (currentFilter !== 'all') {
      filtered = allScans.filter(s =>
        s.verdict === currentFilter || s.category === currentFilter
      );
    }
    if (filtered.length === 0) {
      el.innerHTML = '<div class="empty-state">No matching investigations found.</div>';
      return;
    }
    el.innerHTML = filtered.map(scanItemHTML).join('');
  }

  // Filter pills
  $$('.filter-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      $$('.filter-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentFilter = pill.dataset.filter;
      renderInvestigations();
    });
  });

  // Category card click → go to investigations filtered
  $$('.cat-card').forEach(card => {
    card.addEventListener('click', () => {
      currentFilter = card.dataset.filter;
      window.location.hash = '#/investigations';
      $$('.filter-pill').forEach(p => {
        p.classList.toggle('active', p.dataset.filter === currentFilter);
      });
      loadInvestigations();
    });
  });

  // View All button
  const btnViewAll = $('#btnViewAll');
  if (btnViewAll) {
    btnViewAll.addEventListener('click', () => {
      currentFilter = 'all';
      window.location.hash = '#/investigations';
      $$('.filter-pill').forEach(p => p.classList.toggle('active', p.dataset.filter === 'all'));
      loadInvestigations();
    });
  }

  // ── TrustLens Detail ─────────────────────────────────────
  window._openTrustLens = async function (id, updateHash = true) {
    if (updateHash) {
      window.location.hash = `#/investigation/${id}`;
      return;
    }
    const s = await api(`/api/scans/${id}`);
    if (!s || s.error) {
      $('#trustlensContent').innerHTML = '<div class="empty-state">Scan investigation not found. <a href="#/investigations">Return to Investigations</a></div>';
      showPage('trustlens');
      return;
    }
    showPage('trustlens');

    const vc = verdictClass(s.verdict);
    const dna = (s.scam_dna || []);
    const evidence = (s.matched_evidence || []);
    const recs = (s.recommendations || []);
    const timeline = (s.timeline || []);

    let html = `
      <button class="btn-action back" onclick="window.location.hash='#/investigations'" style="margin-bottom:20px; cursor: pointer;">← Back to Investigations</button>

      <div class="trustlens-header">
        <div class="score-gauge ${vc}">${s.risk_score}</div>
        <div class="trustlens-meta">
          <div style="display:flex; align-items:center; gap:10px; margin-bottom: 6px;">
            <span class="badge ${vc}"><span class="bdot"></span>${verdictLabel(s.verdict)}</span>
            <span style="font-size:12px; color:var(--muted);">Risk Score ${s.risk_score}/100</span>
          </div>
          <h2>${escHTML(s.target || s.primary_text || 'Threat Target')}</h2>
          <p>${escHTML(s.platform)} · ${escHTML(s.category)} · ${escHTML(s.engine_used || 'Heuristic')} · ${timeAgo(s.timestamp)}</p>
        </div>
      </div>

      <div class="explanation-box">
        <strong style="color:var(--navy); display:block; margin-bottom:4px;">TrustLens Plain-Language Assessment:</strong>
        ${escHTML(s.explanation || 'No detailed explanation available.')}
      </div>`;

    // Scam DNA chips
    if (dna.length > 0) {
      html += `<div class="section-card" style="margin-bottom:20px;"><div class="section-header"><span class="section-title">Detected Scam DNA Signatures</span></div><div style="padding:16px 22px;"><div class="dna-chips">`;
      dna.forEach(d => {
        const cls = s.risk_score >= 70 ? '' : 'amber';
        html += `<span class="dna-chip ${cls}">${escHTML(d)}</span>`;
      });
      html += `</div></div></div>`;
    }

    // Evidence table
    if (evidence.length > 0) {
      html += `<div class="section-card" style="margin-bottom:20px;"><div class="section-header"><span class="section-title">Matched Heuristic & Linguistic Evidence</span></div>
        <table class="evidence-table"><thead><tr><th>#</th><th>Scam DNA Tag</th><th>Matched Evidence Excerpt</th></tr></thead><tbody>`;
      evidence.forEach((e, i) => {
        html += `<tr><td>${i + 1}</td><td><span class="dna-chip amber" style="font-size:11px;">${escHTML(dna[i] || dna[0] || 'Behavioral Lure')}</span></td><td style="font-family:monospace; font-size:12px;">${escHTML(e)}</td></tr>`;
      });
      html += `</tbody></table></div>`;
    }

    // Timeline
    if (timeline.length > 0) {
      html += `<div class="section-card" style="margin-bottom:20px;"><div class="section-header"><span class="section-title">Conversation Trust Timeline</span></div><div style="padding:16px 22px;"><div class="timeline">`;
      timeline.forEach((t, i) => {
        const isIntercepted = t.stage === 'Intercepted' || t.is_threat;
        const dotCls = isIntercepted ? 'danger' : 'active';
        html += `
          <div class="timeline-step">
            <div class="timeline-dot ${dotCls}">${i + 1}</div>
            <div class="timeline-content">
              <h4>${escHTML(t.stage)}</h4>
              <p>${escHTML(t.evidence || t.detail || '')}</p>
            </div>
          </div>`;
      });
      html += `</div></div></div>`;
    }

    // Recommendations
    if (recs.length > 0) {
      html += `<div class="section-card" style="margin-bottom:20px;"><div class="section-header"><span class="section-title">Actionable Protective Recommendations</span></div><div style="padding:16px 22px;"><ul class="rec-list">`;
      recs.forEach(r => { html += `<li>${escHTML(r)}</li>`; });
      html += `</ul></div></div>`;
    }

    // Provenance
    html += `
      <div class="section-card" style="margin-bottom:20px;">
        <div class="section-header"><span class="section-title">Telemetry & Data Provenance Trace</span></div>
        <div style="padding:16px 22px;">
          <div class="prov-card">
            <div class="prov-title">Verified Audit Trail</div>
            <div class="prov-step"><span class="arrow">→</span> Database Record ID: #${s.id}</div>
            <div class="prov-step"><span class="arrow">→</span> Ingestion Endpoint: ${escHTML(s.endpoint || 'POST /api/scan/conversation')}</div>
            <div class="prov-step"><span class="arrow">→</span> DOM Element Selector: <code>${escHTML((s.pipeline_trace && s.pipeline_trace.dom_selector) || 'div[role=\'row\'] .x1n2onr6')}</code></div>
            <div class="prov-step"><span class="arrow">→</span> Detection Engine: ${escHTML(s.engine_used || 'Multi-Stage Behavioral Heuristics')}</div>
            <div class="prov-step"><span class="arrow">→</span> Inference Latency: ${s.latency_ms || 0.42}ms</div>
            <div class="prov-step"><span class="arrow">→</span> Final Risk Verdict: ${escHTML(s.verdict)} (Score: ${s.risk_score}/100)</div>
          </div>
        </div>
      </div>`;

    // Original text preview
    if (s.primary_text) {
      html += `
        <div class="section-card" style="margin-bottom:20px;">
          <div class="section-header"><span class="section-title">Scanned Content Snippet</span></div>
          <div style="padding:16px 22px;">
            <div class="explanation-box" style="margin-bottom:0; font-size:12.5px; font-family:monospace; background:#f8fafc; border-color:#e2e8f0; color:#334155;">${escHTML(s.primary_text)}</div>
          </div>
        </div>`;
    }

    // Action buttons
    html += `
      <div class="action-row" style="margin-top: 10px;">
        <button class="btn-action block" onclick="window._blockSender('${escHTML(s.target)}', '${escHTML(s.platform)}')">Block Sender</button>
        <button class="btn-action report" onclick="window._reportFromTrustLens('${escHTML(s.target)}', '${escHTML(s.platform)}', '${escHTML(s.category)}')">Report Scam</button>
      </div>`;

    $('#trustlensContent').innerHTML = html;
  };

  window._blockSender = async function (handle, platform) {
    const data = await api('/api/blocklist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ handle, platform })
    });
    if (data) alert(`Sender "${handle}" has been blocked. Incoming messages from this handle will now be intercepted and masked.`);
  };

  window._reportFromTrustLens = async function (handle, platform, category) {
    const data = await api('/api/reports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ platform, handle_or_url: handle, category, note: 'Submitted via TrustLens investigation' })
    });
    if (data) alert(`Threat report logged for "${handle}". Thank you for contributing to collective defense.`);
  };

  // ── Model Benchmark ──────────────────────────────────────
  async function loadBenchmark() {
    const wrap = $('#benchmarkTableWrap');
    if (!wrap) return;
    const data = await api('/api/model/benchmark');
    if (!data || !data.models) {
      wrap.innerHTML = '<div class="empty-state">No benchmark data available.</div>';
      return;
    }

    let html = `
      <table class="benchmark-table">
        <thead>
          <tr>
            <th>Model Architecture</th>
            <th>Accuracy</th>
            <th>Precision</th>
            <th>Recall</th>
            <th>F1-Score</th>
            <th>MCC</th>
            <th>ROC-AUC</th>
            <th>Latency (ms)</th>
          </tr>
        </thead>
        <tbody>`;

    data.models.forEach(m => {
      const isBest = m.model.includes('GWO') || m.is_best;
      const highlightCls = isBest ? 'class="highlight"' : '';
      html += `
        <tr>
          <td ${highlightCls}><strong>${escHTML(m.model)}</strong></td>
          <td>${(m.accuracy * 100).toFixed(2)}%</td>
          <td>${(m.precision * 100).toFixed(2)}%</td>
          <td>${(m.recall * 100).toFixed(2)}%</td>
          <td>${(m.f1 * 100).toFixed(2)}%</td>
          <td ${highlightCls}>${m.mcc.toFixed(4)}</td>
          <td>${(m.roc_auc * 100).toFixed(2)}%</td>
          <td>${m.latency_ms.toFixed(4)} ms</td>
        </tr>`;
    });

    html += `</tbody></table>`;
    wrap.innerHTML = html;
  }

  // ── Reports ──────────────────────────────────────────────
  async function loadReports() {
    const data = await api('/api/reports');
    const el = $('#reportsTableWrap');
    if (!el) return;
    if (!data || !data.reports || data.reports.length === 0) {
      el.innerHTML = '<div class="empty-state">No reports submitted yet.</div>';
      return;
    }
    let html = `<table class="report-table"><thead><tr><th>Platform</th><th>Handle / URL</th><th>Category</th><th>Notes</th><th>Date</th></tr></thead><tbody>`;
    data.reports.forEach(r => {
      html += `<tr><td><strong>${escHTML(r.platform)}</strong></td><td>${escHTML(r.handle_or_url)}</td><td><span class="dna-chip amber" style="font-size:11px;">${escHTML(r.category)}</span></td><td>${escHTML(r.note)}</td><td style="color:var(--muted); font-size:12px;">${r.created_at || ''}</td></tr>`;
    });
    html += '</tbody></table>';
    el.innerHTML = html;
  }

  async function loadBlocklist() {
    const data = await api('/api/blocklist');
    const el = $('#blockedListWrap');
    if (!el) return;
    if (!data || !data.blocked_senders || data.blocked_senders.length === 0) {
      el.innerHTML = '<div class="empty-state">No blocked senders. Block malicious senders from the extension popup or TrustLens.</div>';
      return;
    }
    let html = `<table class="report-table"><thead><tr><th>Handle</th><th>Platform</th><th>Blocked At</th><th>Action</th></tr></thead><tbody>`;
    data.blocked_senders.forEach(b => {
      html += `<tr><td><strong>${escHTML(b.handle)}</strong></td><td>${escHTML(b.platform)}</td><td style="color:var(--muted); font-size:12px;">${b.blocked_at || ''}</td><td><button class="btn-outline-sm" onclick="window._unblock('${escHTML(b.handle)}')">Unblock</button></td></tr>`;
    });
    html += '</tbody></table>';
    el.innerHTML = html;
  }

  window._unblock = async function (handle) {
    await api(`/api/blocklist/${encodeURIComponent(handle)}`, { method: 'DELETE' });
    loadBlocklist();
  };

  // Submit report
  const btnReport = $('#btnSubmitReport');
  if (btnReport) {
    btnReport.addEventListener('click', async () => {
      const handleInput = $('#reportHandle');
      const noteInput = $('#reportNote');
      if (!handleInput.value.trim()) {
        alert('Please provide a sender handle, phone number, or URL.');
        return;
      }
      const data = await api('/api/reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          platform: $('#reportPlatform').value,
          handle_or_url: handleInput.value.trim(),
          category: $('#reportCategory').value,
          note: noteInput.value.trim() || 'Submitted via web portal',
        })
      });
      if (data && data.status === 'submitted') {
        handleInput.value = '';
        noteInput.value = '';
        alert('Report successfully submitted.');
        loadReports();
      }
    });
  }

  // ── Settings ─────────────────────────────────────────────
  async function loadSettings() {
    const data = await api('/api/settings');
    if (!data) return;
    $('#set-facebook').checked = data.facebook_enabled !== false;
    $('#set-telegram').checked = data.telegram_enabled !== false;
    $('#set-web').checked = data.web_enabled !== false;
    $('#set-cardguard').checked = data.cardguard_enabled !== false;
    $('#set-chime').checked = data.chime_enabled !== false;
    $('#set-hud').checked = data.hud_enabled !== false;
  }

  // Auto-save on toggle
  ['set-facebook', 'set-telegram', 'set-web', 'set-cardguard', 'set-chime', 'set-hud'].forEach(id => {
    const el = $(`#${id}`);
    if (el) {
      el.addEventListener('change', async () => {
        const key = id.replace('set-', '') + '_enabled';
        await api('/api/settings', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ [key]: el.checked })
        });
      });
    }
  });

  // Reset Demo Data Button
  const btnReset = $('#btnResetDemo');
  if (btnReset) {
    btnReset.addEventListener('click', async () => {
      if (!confirm('Reset local database back to baseline 35 verified scans?')) return;
      const res = await api('/api/reset-demo-data', { method: 'POST' });
      if (res && res.status === 'reset_complete') {
        alert('Demonstration database reset successfully. 35 baseline scans restored.');
        loadStats();
        loadRecentScans();
      }
    });
  }

  // ── Extension Heartbeat ──────────────────────────────────
  async function checkExtension() {
    const data = await api('/api/extension/heartbeat');
    const pill = $('#extPill');
    const label = $('#extLabel');
    if (!pill || !label) return;
    if (data && data.connected) {
      pill.classList.remove('disconnected');
      label.textContent = 'Extension Connected';
    } else {
      pill.classList.add('disconnected');
      label.textContent = 'Extension Not Detected';
    }
  }

  // ── Init ─────────────────────────────────────────────────
  async function init() {
    handleRoute();
    loadStats();
    loadRecentScans();
    checkExtension();

    // Auto-refresh stats every 5s per spec
    setInterval(loadStats, 5000);
    // Extension heartbeat poll every 10s
    setInterval(checkExtension, 10000);
  }

  init();
})();

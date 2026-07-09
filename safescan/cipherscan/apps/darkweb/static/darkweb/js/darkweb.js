(function () {
  'use strict';

  const SELECTORS = {
    searchForm: '#dwSearchForm',
    searchInput: '#dwSearchInput',
    searchBtn: '#dwSearchBtn',
    loading: '#dwLoading',
    scanning: '#dwScanning',
    scanningProgress: '#dwScanningProgress',
    scanningPercent: '#dwScanningPercent',
    scanningRing: '#dwScanningRing',
    scanningStatusText: '#dwScanningStatusText',
    scanningElapsed: '#dwScanningElapsed',
    error: '#dwError',
    errorText: '#dwErrorText',
    summary: '#dwSummary',
    summaryRisk: '#dwSummaryRisk',
    summaryType: '#dwSummaryType',
    summarySources: '#dwSummarySources',
    summaryDate: '#dwSummaryDate',
    summaryRecords: '#dwSummaryRecords',
    breachesSection: '#dwBreachesSection',
    breachesContainer: '#dwBreachesContainer',
    breachCount: '#dwBreachCount',
    exposuresSection: '#dwExposuresSection',
    exposuresContainer: '#dwExposuresContainer',
    exposureCount: '#dwExposureCount',
    recsSection: '#dwRecsSection',
    recsContainer: '#dwRecsContainer',
    historySection: '#dwHistorySection',
    historyContainer: '#dwHistoryContainer',
    dashboard: '#dwDashboard',
    exposureBanner: '#dwExposureBanner',
    exposureBannerStatus: '#dwExposureBannerStatus',
    exposureBannerSub: '#dwExposureBannerSub',
    exposureBannerBadge: '#dwExposureBannerBadge',
    resultAsset: '#dwResultAsset',
    resultType: '#dwResultType',
    resultTime: '#dwResultTime',
    resultRiskScore: '#dwResultRiskScore',
    resultBreachCount: '#dwResultBreachCount',
    resultConfidence: '#dwResultConfidence',
    resultFirstSeen: '#dwResultFirstSeen',
    resultLastSeen: '#dwResultLastSeen',
    resultSources: '#dwResultSources',
    resultCompromisedFields: '#dwResultCompromisedFields',
    actionBar: '#dwActionBar',
    actionCopyAll: '#dwCopyAll',
    actionJson: '#dwJson',
    actionPdf: '#dwPdf',
    actionPrint: '#dwPrint',
    actionShare: '#dwShare',
    toast: '#dwToast',
    gridSection: '#dwGridSection',
    gridContainer: '#dwGridContainer',
    aiSection: '#dwAIAnalysis',
    aiSummary: '#dwAISummary',
    aiPosture: '#dwAIPosture',
    aiActionsList: '#dwAIActionsList',
    aiBadge: '#dwAIBadge',
    chartSection: '#dwChartSection',
    chartCanvas: '#dwExposureChart',
    exportBar: '#dwExportBar',
    watchlistSection: '#dwWatchlistSection',
    watchlistContainer: '#dwWatchlistContainer',
    watchlistAddBtn: '#dwWatchlistAddBtn',
    relIntelSection: '#dwRelatedIntelSection',
    relIntelContent: '#dwRelIntelContent',
    relIntelEmpty: '#dwRelIntelEmpty',
    hcSection: '#dwHowCalculated',
    apSection: '#dwAnalysisProcess',
    // new premium report
    verdictBanner: '#dwVerdictBanner',
    verdictStatus: '#dwVerdictStatus',
    verdictSub: '#dwVerdictSub',
    verdictBadge: '#dwVerdictBadge',
    confGaugeFill: '#dwConfGaugeFill',
    confScore: '#dwConfScore',
    confLabel: '#dwConfLabel',
    riskLabel: '#dwRiskLabel',
    resultRecords: '#dwResultRecords',
    identityConf: '#dwIdentityConf',
    statBreaches: '#dwStatBreaches',
    statExposures: '#dwStatExposures',
    statSources: '#dwStatSources',
    statRecords: '#dwStatRecords',
    tipsContainer: '#dwTipsContainer',
    tipsCard: '#dwSecurityTips',
    reportActions: '#dwReportActions',
  };

  const STORAGE_KEY = 'darkweb_history';
  const WATCHLIST_KEY = 'darkweb_watchlist';
  const CACHE_PREFIX = 'darkweb_cache_';
  const CACHE_TTL = 10 * 60 * 1000;
  const CACHE_VERSION_KEY = 'darkweb_cache_ver';
  const CACHE_VERSION = 2;

  // Invalidate stale sessionStorage caches when JS code changes
  (function initCacheVersion() {
    try {
      var storedVer = sessionStorage.getItem(CACHE_VERSION_KEY);
      if (storedVer !== String(CACHE_VERSION)) {
        // wipe all darkweb caches
        var keys = [];
        for (var i = 0; i < sessionStorage.length; i++) {
          var k = sessionStorage.key(i);
          if (k && k.indexOf(CACHE_PREFIX) === 0) keys.push(k);
        }
        keys.forEach(function (k) { sessionStorage.removeItem(k); });
        sessionStorage.setItem(CACHE_VERSION_KEY, String(CACHE_VERSION));
      }
    } catch (e) { /* ignore */ }
  })();

  let currentResult = null;

  const els = {};
  for (const [key, sel] of Object.entries(SELECTORS)) {
    els[key] = document.querySelector(sel);
  }

  function showToast(msg, isError) {
    const t = els.toast;
    if (!t) return;
    t.textContent = msg;
    t.classList.remove('error');
    if (isError) t.classList.add('error');
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 3000);
  }

  function getHistory() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
    } catch { return []; }
  }

  function saveToHistory(query, qtype, fullData) {
    const history = getHistory();
    const risk = fullData && fullData.risk ? fullData.risk : null;
    const breachCount = fullData && fullData.breaches ? fullData.breaches.length : 0;
    const entry = {
      query,
      type: qtype,
      date: new Date().toISOString(),
      risk: risk ? { score: risk.score, level: risk.level } : null,
      breachCount,
      data: fullData || null,
    };
    // replace existing entry for same query
    const idx = history.findIndex(e => e.query === query);
    if (idx >= 0) history.splice(idx, 1);
    history.unshift(entry);
    if (history.length > 20) history.length = 20;
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
    } catch { /* ignore */ }
  }

  function deleteHistoryItem(query) {
    let history = getHistory();
    history = history.filter(e => e.query !== query);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
    } catch { /* ignore */ }
    renderHistory();
  }

  function renderHistory() {
    const history = getHistory();
    const container = els.historyContainer;
    const section = els.historySection;
    if (!container || !section) return;
    if (history.length === 0) {
      section.classList.remove('active');
      return;
    }
    section.classList.add('active');

    function riskBadge(level) {
      const map = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
      return `<span class="dw-hist-risk dw-hist-risk-${level}">${map[level] || level}</span>`;
    }

    container.innerHTML = `
      <div class="dw-hist-table">
        <div class="dw-hist-thead">
          <div class="dw-hist-row dw-hist-header-row">
            <div class="dw-hist-cell dw-hist-cell-asset">Asset</div>
            <div class="dw-hist-cell dw-hist-cell-type">Type</div>
            <div class="dw-hist-cell dw-hist-cell-risk">Risk</div>
            <div class="dw-hist-cell dw-hist-cell-breaches">Breaches</div>
            <div class="dw-hist-cell dw-hist-cell-time">Scan Time</div>
            <div class="dw-hist-cell dw-hist-cell-actions">Actions</div>
          </div>
        </div>
        <div class="dw-hist-tbody">
          ${history.map(item => {
            const riskLevel = item.risk ? item.risk.level : null;
            const riskScore = item.risk ? item.risk.score : null;
            const riskLabel = riskLevel ? (riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1)) : '—';
            const breachCount = item.breachCount || 0;
            const time = item.date ? formatDateTime(item.date) : '—';
            return `
              <div class="dw-hist-row dw-hist-data-row" data-query="${escapeHtml(item.query)}">
                <div class="dw-hist-cell dw-hist-cell-asset" title="${escapeHtml(item.query)}">
                  <span class="dw-hist-asset-text">${escapeHtml(item.query)}</span>
                </div>
                <div class="dw-hist-cell dw-hist-cell-type">
                  <span class="dw-history-type ${item.type}">${escapeHtml(item.type)}</span>
                </div>
                <div class="dw-hist-cell dw-hist-cell-risk">
                  ${riskLevel ? riskBadge(riskLevel) + (riskScore !== null ? ` <span class="dw-hist-score">${riskScore}</span>` : '') : '<span class="dw-hist-na">—</span>'}
                </div>
                <div class="dw-hist-cell dw-hist-cell-breaches">
                  <span class="dw-hist-breaches-count">${breachCount}</span>
                </div>
                <div class="dw-hist-cell dw-hist-cell-time">
                  <span class="dw-hist-time">${escapeHtml(time)}</span>
                </div>
                <div class="dw-hist-cell dw-hist-cell-actions">
                  <button class="dw-hist-btn dw-hist-btn-view" title="View results" data-query="${escapeHtml(item.query)}">
                    <i class="fas fa-eye"></i>
                  </button>
                  <button class="dw-hist-btn dw-hist-btn-rescan" title="Re-scan" data-query="${escapeHtml(item.query)}">
                    <i class="fas fa-rotate"></i>
                  </button>
                  <button class="dw-hist-btn dw-hist-btn-delete" title="Delete" data-query="${escapeHtml(item.query)}">
                    <i class="fas fa-trash-can"></i>
                  </button>
                </div>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;

    // View: load from cached data
    container.querySelectorAll('.dw-hist-btn-view').forEach(btn => {
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        const query = this.dataset.query;
        const cached = getFromCache(query);
        if (cached) {
          renderResults(cached, query);
        } else {
          // fallback: trigger fresh scan
          els.searchInput.value = query;
          els.searchInput.dispatchEvent(new Event('input'));
          performSearch();
        }
      });
    });

    // Rescan
    container.querySelectorAll('.dw-hist-btn-rescan').forEach(btn => {
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        els.searchInput.value = this.dataset.query;
        els.searchInput.dispatchEvent(new Event('input'));
        performSearch();
      });
    });

    // Delete
    container.querySelectorAll('.dw-hist-btn-delete').forEach(btn => {
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        deleteHistoryItem(this.dataset.query);
      });
    });
  }

  /* ── Watchlist ── */

  const WATCHLIST_MAX = 20;

  function getWatchlist() {
    try {
      return JSON.parse(localStorage.getItem(WATCHLIST_KEY)) || [];
    } catch { return []; }
  }

  function saveWatchlist(list) {
    try {
      localStorage.setItem(WATCHLIST_KEY, JSON.stringify(list));
    } catch { /* ignore */ }
  }

  function addToWatchlist(asset, type, resultData) {
    const list = getWatchlist();
    if (list.some(e => e.asset === asset)) {
      showToast('Already in watchlist.');
      return;
    }
    if (list.length >= WATCHLIST_MAX) {
      showToast('Watchlist full (max ' + WATCHLIST_MAX + ').', true);
      return;
    }
    const risk = resultData && resultData.risk ? resultData.risk : null;
    const breachCount = resultData && resultData.breaches ? resultData.breaches.length : 0;
    list.unshift({
      asset,
      type,
      added: new Date().toISOString(),
      lastScan: new Date().toISOString(),
      risk: risk ? { score: risk.score, level: risk.level } : null,
      breachCount,
    });
    saveWatchlist(list);
    renderWatchlist();
    showToast('Added to watchlist.');
  }

  function removeFromWatchlist(asset) {
    let list = getWatchlist();
    list = list.filter(e => e.asset !== asset);
    saveWatchlist(list);
    renderWatchlist();
  }

  function rescanWatchlist(asset) {
    els.searchInput.value = asset;
    els.searchInput.dispatchEvent(new Event('input'));
    performSearch();
  }

  function renderWatchlist() {
    const container = els.watchlistContainer;
    const section = els.watchlistSection;
    if (!container || !section) return;
    const list = getWatchlist();
    if (list.length === 0) {
      section.classList.remove('active');
      return;
    }
    section.classList.add('active');

    function riskBadge(level) {
      const map = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
      return `<span class="dw-wl-risk dw-wl-risk-${level}">${map[level] || level}</span>`;
    }

    container.innerHTML = list.map(item => {
      const riskLevel = item.risk ? item.risk.level : null;
      const riskScore = item.risk ? item.risk.score : null;
      const lastScanStr = item.lastScan ? formatDateTime(item.lastScan) : 'Never';
      const iconClass = { email: 'fa-envelope', username: 'fa-user', phone: 'fa-phone', domain: 'fa-globe' };
      return `
        <div class="dw-wl-card" data-asset="${escapeHtml(item.asset)}">
          <div class="dw-wl-card-top">
            <div class="dw-wl-icon">
              <i class="fas ${iconClass[item.type] || 'fa-question'}"></i>
            </div>
            <div class="dw-wl-info">
              <span class="dw-wl-asset" title="${escapeHtml(item.asset)}">${escapeHtml(item.asset)}</span>
              <span class="dw-wl-type-badge dw-wl-type-${item.type}">${escapeHtml(item.type)}</span>
            </div>
            <button class="dw-wl-btn dw-wl-btn-delete" data-asset="${escapeHtml(item.asset)}" title="Remove from watchlist">
              <i class="fas fa-times"></i>
            </button>
          </div>
          <div class="dw-wl-card-bottom">
            <div class="dw-wl-meta">
              ${riskLevel ? riskBadge(riskLevel) + (riskScore !== null ? ' <span class="dw-wl-score">' + riskScore + '</span>' : '') : '<span class="dw-wl-na">No data</span>'}
              <span class="dw-wl-breaches">${item.breachCount || 0} breach(es)</span>
              <span class="dw-wl-last-scan">Last: ${escapeHtml(lastScanStr)}</span>
            </div>
            <button class="dw-wl-btn dw-wl-btn-rescan" data-asset="${escapeHtml(item.asset)}" title="Re-scan">
              <i class="fas fa-rotate"></i>
            </button>
          </div>
        </div>
      `;
    }).join('');

    // wire delete
    container.querySelectorAll('.dw-wl-btn-delete').forEach(btn => {
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        removeFromWatchlist(this.dataset.asset);
      });
    });

    // wire rescan
    container.querySelectorAll('.dw-wl-btn-rescan').forEach(btn => {
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        rescanWatchlist(this.dataset.asset);
      });
    });
  }

  function getCacheKey(query) {
    return CACHE_PREFIX + encodeURIComponent(query.trim().toLowerCase().replace(/\s+/g, '_'));
  }

  function getFromCache(query) {
    const key = getCacheKey(query);
    try {
      const raw = sessionStorage.getItem(key);
      if (!raw) return null;
      const data = JSON.parse(raw);
      if (Date.now() - data.ts > CACHE_TTL) {
        sessionStorage.removeItem(key);
        return null;
      }
      return data.result;
    } catch { return null; }
  }

  function setCache(query, result) {
    const key = getCacheKey(query);
    try {
      sessionStorage.setItem(key, JSON.stringify({ ts: Date.now(), result }));
    } catch { /* ignore */ }
  }

  // Safe class setter: uses setAttribute for SVG elements, className for HTML
  function safeSetClass(el, cls) {
    if (!el) return;
    try {
      if (el instanceof SVGElement) {
        el.setAttribute('class', cls);
      } else {
        el.className = cls;
      }
    } catch (e) {
      // last resort fallback
      try { el.setAttribute('class', cls); } catch (e2) { /* ignore */ }
    }
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function formatDate(iso) {
    try {
      return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    } catch { return iso; }
  }

  function formatMonthYear(iso) {
    try {
      return new Date(iso).toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
    } catch { return iso || '—'; }
  }



  var FIELD_COLORS = {
    email: '#00B4FF', username: '#7850FF', password: '#FF3366',
    phone: '#FF8800', address: '#FFCC00', country: '#00CC88',
    dob: '#FF66B2', ip: '#00D4D4', name: '#A78BFA',
    payment: '#FF4444', ssn: '#FF3366', bank: '#FF4444',
    token: '#F59E0B', key: '#10B981', hash: '#6366F1',
    browser: '#8B5CF6', device: '#6B7280', recovery: '#EC4899',
    security: '#EF4444',
  };

  function fieldColor(field) {
    var lower = field.toLowerCase();
    for (var key in FIELD_COLORS) {
      if (lower.indexOf(key) !== -1) return FIELD_COLORS[key];
    }
    return '#7850FF';
  }

  function formatDateTime(iso) {
    try {
      return new Date(iso).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
    } catch { return iso; }
  }

  function formatNumber(n) {
    if (!n) return '0';
    return n.toLocaleString();
  }

  function animateCounter(el, start, end, duration, suffix) {
    suffix = suffix || '';
    if (!el) return;
    var startTime = null;
    function tick(now) {
      if (!startTime) startTime = now;
      var progress = Math.min((now - startTime) / duration, 1);
      var eased = 1 - Math.pow(1 - progress, 3);
      var val = Math.round(start + (end - start) * eased);
      el.textContent = formatNumber(val) + suffix;
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  function animateProgressBar(el, target, duration) {
    if (!el) return;
    var startTime = null;
    function tick(now) {
      if (!startTime) startTime = now;
      var progress = Math.min((now - startTime) / duration, 1);
      var eased = 1 - Math.pow(1 - progress, 3);
      var val = eased * target;
      el.style.width = val + '%';
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  var SECURITY_TIPS_POOL = [
    { icon: 'fa-key', text: 'Use a unique, complex password for every online account. Password managers make this easy.' },
    { icon: 'fa-shield', text: 'Enable two-factor authentication (2FA) on all accounts that support it.' },
    { icon: 'fa-envelope', text: 'Use email aliases or "+" addressing to prevent cross-platform tracking.' },
    { icon: 'fa-phone', text: 'Enable SIM port protection with your mobile carrier to prevent SIM swapping.' },
    { icon: 'fa-eye', text: 'Monitor your accounts regularly for suspicious activity or unrecognized logins.' },
    { icon: 'fa-rotate', text: 'Rotate passwords immediately after any reported breach or security incident.' },
    { icon: 'fa-clock', text: 'Check Have I Been Pwned regularly to stay informed about new breaches.' },
    { icon: 'fa-link', text: 'Avoid reusing passwords between personal and work accounts.' },
    { icon: 'fa-browser', text: 'Keep your browser, OS, and all software updated to patch security vulnerabilities.' },
    { icon: 'fa-wifi', text: 'Avoid using public Wi-Fi without a VPN. Use HTTPS everywhere.' },
    { icon: 'fa-trash', text: 'Delete unused accounts to reduce your digital footprint and attack surface.' },
    { icon: 'fa-bell', text: 'Set up credit monitoring and fraud alerts if financial data has been exposed.' },
    { icon: 'fa-user', text: 'Limit the personal information you share on social media platforms.' },
    { icon: 'fa-lock', text: 'Use a dedicated, secure email for sensitive accounts like banking and healthcare.' },
    { icon: 'fa-qrcode', text: 'Prefer authenticator apps over SMS for 2FA — they are more secure against SIM swap attacks.' },
  ];

  function pickTips(query, riskLevel) {
    var hash = 0;
    for (var i = 0; i < query.length; i++) {
      hash = ((hash << 5) - hash) + query.charCodeAt(i);
      hash |= 0;
    }
    var rng = function () {
      hash = (hash * 1103515245 + 12345) & 0x7fffffff;
      return hash / 0x7fffffff;
    };
    var count = riskLevel === 'critical' ? 6 : riskLevel === 'high' ? 5 : riskLevel === 'medium' ? 4 : 3;
    var pool = SECURITY_TIPS_POOL.slice();
    var picked = [];
    for (var j = 0; j < count && pool.length > 0; j++) {
      var idx = Math.floor(rng() * pool.length);
      picked.push(pool.splice(idx, 1)[0]);
    }
    return picked;
  }

  const SCAN_STAGES = [
    { status: 'Initializing scan engine...',      progress: 0,   minMs: 200,  maxMs: 600 },
    { status: 'Searching intelligence sources...',  progress: 15,  minMs: 600,  maxMs: 1400 },
    { status: 'Checking breach databases...',       progress: 30,  minMs: 800,  maxMs: 2000 },
    { status: 'Scanning dark web forums...',        progress: 48,  minMs: 900,  maxMs: 1800 },
    { status: 'Correlating identity data...',       progress: 63,  minMs: 700,  maxMs: 1500 },
    { status: 'Analyzing exposed data types...',    progress: 76,  minMs: 600,  maxMs: 1200 },
    { status: 'Calculating risk assessment...',     progress: 87,  minMs: 500,  maxMs: 1000 },
    { status: 'Generating comprehensive report...', progress: 95,  minMs: 500,  maxMs: 1100 },
  ];

  let scanTimerHandle = null;

  function hideAllResults() {
    if (els.dashboard) els.dashboard.classList.remove('active');
    if (els.error) els.error.classList.remove('active');
    if (els.summary) els.summary.classList.remove('active');
    if (els.breachesSection) els.breachesSection.classList.remove('active');
    if (els.exposuresSection) els.exposuresSection.classList.remove('active');
    if (els.gridSection) els.gridSection.classList.remove('active');
    if (els.chartSection) els.chartSection.classList.remove('active');
    if (els.aiSection) els.aiSection.classList.remove('active');
    if (els.recsSection) els.recsSection.classList.remove('active');
    if (els.tipsCard) els.tipsCard.classList.remove('active');
    if (els.actionBar) els.actionBar.classList.remove('active');
    if (els.exportBar) els.exportBar.classList.remove('active');
    var summaryActions = document.getElementById('dwSummaryActions');
    if (summaryActions) summaryActions.style.display = 'none';
    if (els.watchlistSection) els.watchlistSection.classList.remove('active');
  }

  function showScanningDashboard() {
    hideAllResults();
    if (els.loading) els.loading.classList.remove('active');
    if (els.scanning) els.scanning.classList.add('active');
    // reset
    if (els.scanningProgress) els.scanningProgress.style.width = '0%';
    if (els.scanningPercent) els.scanningPercent.textContent = '0%';
    if (els.scanningRing) els.scanningRing.style.strokeDashoffset = '339.292';
    if (els.scanningStatusText) {
      els.scanningStatusText.textContent = SCAN_STAGES[0].status;
      els.scanningStatusText.style.opacity = '1';
    }
    if (els.scanningElapsed) els.scanningElapsed.textContent = '0.0';
    if (els.searchBtn) {
      els.searchBtn.disabled = true;
      const text = els.searchBtn.querySelector('.dw-btn-text');
      const loading = els.searchBtn.querySelector('.dw-btn-loading');
      if (text) text.style.display = 'none';
      if (loading) loading.style.display = 'inline-flex';
    }
  }

  function hideScanningDashboard() {
    if (els.scanning) els.scanning.classList.remove('active');
    if (els.searchBtn) {
      els.searchBtn.disabled = false;
      const text = els.searchBtn.querySelector('.dw-btn-text');
      const loading = els.searchBtn.querySelector('.dw-btn-loading');
      if (text) text.style.display = 'inline-flex';
      if (loading) loading.style.display = 'none';
    }
  }

  function sleepMs(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  async function startStageScan(callback) {
    const startTime = performance.now();
    const circumference = 339.292;
    var stageIndex = 0;

    // timer updater
    if (scanTimerHandle) clearInterval(scanTimerHandle);
    scanTimerHandle = setInterval(function () {
      if (!els.scanningElapsed) return;
      var sec = ((performance.now() - startTime) / 1000).toFixed(1);
      if (els.scanningElapsed) els.scanningElapsed.textContent = sec;
    }, 100);

    function setStatus(text, progress) {
      if (els.scanningStatusText) {
        els.scanningStatusText.style.opacity = '0';
        setTimeout(function () {
          if (els.scanningStatusText) {
            els.scanningStatusText.textContent = text;
            els.scanningStatusText.style.opacity = '1';
          }
        }, 120);
      }
      var pct = Math.round(progress);
      if (els.scanningProgress) els.scanningProgress.style.width = pct + '%';
      if (els.scanningPercent) els.scanningPercent.textContent = pct + '%';
      if (els.scanningRing) {
        els.scanningRing.style.strokeDashoffset = circumference - (circumference * progress / 100);
      }
    }

    setStatus(SCAN_STAGES[0].status, 0);

    for (var i = 0; i < SCAN_STAGES.length; i++) {
      var stage = SCAN_STAGES[i];
      stageIndex = i;
      setStatus(stage.status, stage.progress);

      // randomize the duration for this stage
      var delay = stage.minMs + Math.random() * (stage.maxMs - stage.minMs);
      // add some per-scan variation based on a simple hash of the stage
      await sleepMs(delay);
    }

    // final push to 100%
    setStatus('Finalizing results...', 100);

    if (scanTimerHandle) {
      clearInterval(scanTimerHandle);
      scanTimerHandle = null;
    }

    var totalSec = ((performance.now() - startTime) / 1000).toFixed(1);
    var finalMsg = 'Scan complete in ' + totalSec + 's. Rendering results...';
    if (els.scanningStatusText) {
      els.scanningStatusText.textContent = finalMsg;
    }

    await sleepMs(400);
    callback();
  }

  function showError(msg) {
    if (els.scanning) els.scanning.classList.remove('active');
    if (els.loading) els.loading.classList.remove('active');
    if (els.error) els.error.classList.add('active');
    if (els.errorText) els.errorText.textContent = msg || 'An unexpected error occurred. Please try again.';
    if (els.searchBtn) {
      els.searchBtn.disabled = false;
      const text = els.searchBtn.querySelector('.dw-btn-text');
      const loading = els.searchBtn.querySelector('.dw-btn-loading');
      if (text) text.style.display = 'inline-flex';
      if (loading) loading.style.display = 'none';
    }
  }

  function renderRiskBadge(level) {
    const map = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
    return `<span class="dw-risk-badge dw-risk-${level}">${map[level] || level}</span>`;
  }

  function renderSummary(data, query, qtype) {
    if (!els.summary) return;
    if (!data) return;
    els.summary.classList.add('active');

    if (els.summaryRisk && data.risk) els.summaryRisk.innerHTML = renderRiskBadge(data.risk.level);
    if (els.summaryType) {
      els.summaryType.innerHTML = `<span class="dw-history-type ${qtype}">${qtype}</span>`;
    }
    if (els.summarySources && data.sources_checked) els.summarySources.textContent = data.sources_checked.length + ' sources scanned';
    if (els.summaryDate) els.summaryDate.textContent = formatDate(data.scan_date);
    if (els.summaryRecords) {
      els.summaryRecords.textContent = formatNumber(data.total_records_exposed) + ' records exposed';
    }

    var summaryActions = document.getElementById('dwSummaryActions');
    if (summaryActions) summaryActions.style.display = '';
    if (els.exportBar) {
      els.exportBar.classList.remove('active');
    }
  }

  function renderBreaches(breaches, data) {
    const container = els.breachesContainer;
    const section = els.breachesSection;
    if (!container || !section) return;

    if (!breaches || breaches.length === 0) {
      section.classList.remove('active');
      return;
    }
    section.classList.add('active');
    if (els.breachCount) els.breachCount.textContent = breaches.length;

    var sorted = [...breaches].sort(function (a, b) {
      if (!a.date) return 1;
      if (!b.date) return -1;
      return new Date(b.date) - new Date(a.date);
    });
    var severityLabel = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };

    var groups = {};
    sorted.forEach(function (b) {
      var year = b.date ? b.date.split('-')[0] : 'Unknown Year';
      if (!groups[year]) groups[year] = [];
      groups[year].push(b);
    });
    var years = Object.keys(groups).sort(function (a, b) {
      if (a === 'Unknown Year') return 1;
      if (b === 'Unknown Year') return -1;
      return parseInt(b) - parseInt(a);
    });

    var html = '<div class="dw-timeline">';
    years.forEach(function (year, yi) {
      html += '<div class="dw-tl-year-group">';
      html += '<div class="dw-tl-year-label"><span class="dw-tl-year-text">' + escapeHtml(year) + '</span></div>';
      groups[year].forEach(function (b, bi) {
        var isLast = bi === groups[year].length - 1 && yi === years.length - 1;
        html += '<div class="dw-timeline-item dw-timeline-' + (b.risk || 'low') + '">';
        html += '<div class="dw-timeline-dot"></div>';
        if (!isLast) html += '<div class="dw-tl-connector"></div>';
        html += '<div class="dw-timeline-card">';
        html += '<div class="dw-timeline-card-header">';
        html += '<div class="dw-timeline-company"><i class="fas fa-building"></i> ' + escapeHtml(b.title || b.name) + '</div>';
        html += '<div class="dw-timeline-year"><i class="far fa-calendar-alt"></i> ' + escapeHtml(b.date ? b.date.split('-')[0] : 'Unknown Year') + '</div>';
        html += '</div>';
        html += '<div class="dw-timeline-meta">';
        if (b.is_verified !== undefined) {
          html += '<span class="dw-tl-verified dw-tl-verified-' + (b.is_verified ? 'yes' : 'no') + '">';
          html += '<i class="fas fa-' + (b.is_verified ? 'check-circle' : 'times-circle') + '"></i> ';
          html += b.is_verified ? 'Verified' : 'Unverified';
          html += '</span>';
        }
        html += '</div>';
        html += '<div class="dw-timeline-stats">';
        html += '<div class="dw-timeline-stat"><span class="dw-timeline-stat-label">Records Affected</span><span class="dw-timeline-stat-value">' + formatNumber(b.records) + '</span></div>';
        html += '<div class="dw-timeline-stat"><span class="dw-timeline-stat-label">Compromised Data</span><span class="dw-timeline-stat-value dw-timeline-data-classes">' + escapeHtml((b.data_classes || []).join(', ')) + '</span></div>';
        html += '<div class="dw-timeline-stat"><span class="dw-timeline-stat-label">Severity</span><span class="dw-timeline-severity dw-timeline-severity-' + (b.risk || 'low') + '">' + (severityLabel[b.risk] || b.risk) + '</span></div>';
        html += '</div>';
        if (b.description) {
          html += '<div class="dw-timeline-desc">' + b.description + '</div>';
        }
        html += '</div></div>';
      });
      html += '</div>';
    });
    html += '</div>';
    container.innerHTML = html;

    requestAnimationFrame(function () {
      var items = container.querySelectorAll('.dw-timeline-item');
      var observer = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add('dw-timeline-visible');
            observer.unobserve(entry.target);
          }
        });
      }, { threshold: 0.15, rootMargin: '0px 0px -40px 0px' });
      items.forEach(function (item) { observer.observe(item); });
    });
  }

  function renderExposures(exposures) {
    const container = els.exposuresContainer;
    const section = els.exposuresSection;
    if (!container || !section) return;
    if (!exposures || exposures.length === 0) {
      section.classList.remove('active');
      return;
    }
    section.classList.add('active');
    if (els.exposureCount) els.exposureCount.textContent = exposures.length;

    const icons = { paste: '\u{1F4CB}', credential: '\u{1F511}', email: '\u2709\uFE0F', domain: '\u{1F310}' };

    container.innerHTML = exposures.map(ex => `
      <div class="dw-exposure-item">
        <div class="dw-exposure-icon">${icons[ex.type] || '\u{1F50D}'}</div>
        <div class="dw-exposure-content">
          <div class="dw-exposure-title">${escapeHtml(ex.title)}</div>
          <div class="dw-exposure-source"><i class="fas fa-source me-1"></i>${escapeHtml(ex.source)}</div>
          <div class="dw-exposure-desc">${escapeHtml(ex.content)}</div>
        </div>
        <div class="dw-exposure-confidence" title="Confidence indicates how certain CipherScan is about this assessment. It does NOT indicate risk.">
          <div class="dw-confidence-value">${ex.confidence}%</div>
          <div class="dw-confidence-label">Confidence</div>
          <div class="dw-confidence-bar"><div class="dw-confidence-fill" style="width:${ex.confidence}%"></div></div>
        </div>
      </div>
    `).join('');
  }

  function renderRecommendations(recs) {
    const container = els.recsContainer;
    const section = els.recsSection;
    if (!container || !section) return;
    if (!recs || recs.length === 0) {
      section.classList.remove('active');
      return;
    }
    section.classList.add('active');
    container.innerHTML = recs.map(r => {
      const pri = r.priority || 'low';
      return `
        <div class="dw-rec-card priority-${pri}">
          <div class="dw-rec-card-icon">${r.icon}</div>
          <div class="dw-rec-card-body">
            <div class="dw-rec-card-text">${escapeHtml(r.text)}</div>
            <span class="dw-rec-card-badge priority-${pri}">${pri}</span>
          </div>
        </div>
      `;
    }).join('');
  }

  function getAssetTypeIcon(type) {
    const icons = { email: 'fa-envelope', username: 'fa-user', phone: 'fa-phone', domain: 'fa-globe' };
    return icons[type] || 'fa-question';
  }

  function renderDashboard(data) {
    if (!els.dashboard) return;
    if (!data || !data.data) {
      if (console && console.warn) console.warn('renderDashboard: no data.data', data);
      return;
    }
    els.dashboard.classList.add('active');

    var inner = data.data;
    var riskScore = inner.risk ? inner.risk.score : 0;
    var riskLevel = inner.risk ? inner.risk.level : 'unknown';
    var confidence = inner.confidence !== undefined ? inner.confidence : 0;
    var breaches = inner.breaches || [];
    var exposures = inner.exposures || [];
    var sources = inner.sources_checked || [];
    var fields = inner.compromised_fields || [];
    var qtype = data.type || 'email';
    var scanDate = inner.scan_date;

    /* ── Clean State (no breaches found) ── */
    var cleanState = document.getElementById('dwCleanState');
    var dashContent = document.getElementById('dwDashboardContent');
    var cleanTitle = document.getElementById('dwCleanTitle');
    var cleanDisclaimer = document.getElementById('dwCleanDisclaimer');
    var cleanStatus = document.getElementById('dwCleanStatus');
    var isClean = breaches.length === 0;
    if (cleanState) cleanState.style.display = isClean ? '' : 'none';
    if (dashContent) dashContent.style.display = isClean ? 'none' : '';
    if (isClean) {
      if (inner.provider_unavailable) {
        if (cleanTitle) cleanTitle.textContent = 'We could not connect to a breach intelligence provider.';
        if (cleanDisclaimer) cleanDisclaimer.textContent = 'The breach database could not be reached. Please try again later.';
        if (cleanStatus) cleanStatus.style.display = '';
      } else {
        if (cleanTitle) cleanTitle.textContent = 'No breaches were found for this identity.';
        if (cleanDisclaimer) cleanDisclaimer.textContent = 'This does NOT guarantee your information has never been exposed. Private or undisclosed breaches cannot be searched.';
        if (cleanStatus) cleanStatus.style.display = 'none';
      }
      els.dashboard.classList.add('active');
      return;
    }

    /* ── Verdict Banner ── */
    var verdictBanner = els.verdictBanner;
    if (verdictBanner) {
      safeSetClass(verdictBanner, 'dw-verdict-banner');
      var vClass = 'verdict-clean';
      var vStatus = 'No Exposure';
      var vSub = 'No compromised data found across monitored sources.';
      var vBadge = 'Safe';
      if (riskScore >= 70 || riskLevel === 'critical') {
        vClass = 'verdict-critical';
        vStatus = 'Critical Exposure';
        vSub = 'Your data has been found in multiple critical breaches. Immediate action required.';
        vBadge = 'Critical';
      } else if (riskScore >= 50 || riskLevel === 'high') {
        vClass = 'verdict-high';
        vStatus = 'High Exposure';
        vSub = 'Significant exposure detected — review findings and take precautionary steps.';
        vBadge = 'High Risk';
      } else if (riskScore >= 25 || riskLevel === 'medium') {
        vClass = 'verdict-medium';
        vStatus = 'Medium Exposure';
        vSub = 'Some of your data may be exposed. Review the findings and take action.';
        vBadge = 'Elevated';
      }
      verdictBanner.classList.add(vClass);
      if (els.verdictStatus) els.verdictStatus.textContent = vStatus;
      if (els.verdictSub) els.verdictSub.textContent = vSub;
      if (els.verdictBadge) {
        els.verdictBadge.innerHTML = '<span class="dw-verdict-dot"></span><span class="dw-verdict-label">' + vBadge + '</span>';
      }
    }

    /* ── Data Reliability ── */
    var relDot = document.getElementById('dwReliabilityDot');
    var relText = document.getElementById('dwReliabilityText');
    if (relDot && relText) {
      var hasVerified = breaches.some(function (b) { return b.is_verified; });
      var hasAnyBreach = breaches.length > 0;
      if (hasVerified) {
        relDot.className = 'dw-data-reliability-dot green';
        relText.textContent = 'Verified Public Breach Data';
      } else if (hasAnyBreach) {
        relDot.className = 'dw-data-reliability-dot yellow';
        relText.textContent = 'Mixed Public + Estimated Analysis';
      } else {
        relDot.className = 'dw-data-reliability-dot grey';
        relText.textContent = 'No Public Evidence Found';
      }
    }

    /* ── Identity Details ── */
    if (els.resultAsset) els.resultAsset.textContent = data.query || '—';
    if (els.resultType) {
      els.resultType.innerHTML = '<i class="fas ' + getAssetTypeIcon(qtype) + '"></i> ' + qtype;
    }
    if (els.resultTime) {
      try {
        els.resultTime.textContent = new Date(scanDate).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
      } catch {
        els.resultTime.textContent = scanDate || '—';
      }
    }
    if (els.resultFirstSeen) els.resultFirstSeen.textContent = inner.first_seen ? formatMonthYear(inner.first_seen) : 'Unknown';
    if (els.resultLastSeen) els.resultLastSeen.textContent = inner.last_seen ? formatMonthYear(inner.last_seen) : 'Unknown';
    if (els.resultBreachCount) els.resultBreachCount.textContent = breaches.length;
    if (els.resultRecords) els.resultRecords.textContent = formatNumber(inner.total_records_exposed || 0);
    if (els.identityConf) {
      els.identityConf.textContent = hasSources ? (confidence + '%') : 'Not Available';
      els.identityConf.title = hasSources ? 'Confidence indicates how certain CipherScan is about this assessment. It does NOT indicate risk.' : 'No intelligence sources were scanned.';
    }

    /* ── Risk Score Gauge ── */
    if (els.resultRiskScore) {
      els.resultRiskScore.textContent = '0';
      safeSetClass(els.resultRiskScore, 'dw-gauge-number');
    }
    var gaugeFill = document.getElementById('dwGaugeFill');
    if (gaugeFill) {
      safeSetClass(gaugeFill, 'dw-gauge-fill');
      gaugeFill.style.strokeDashoffset = '213.628';
    }
    var gaugeCircumference = 213.628;
    var gaugeDuration = 900;
    var gaugeStart = performance.now();

    function riskLevelName(s) {
      if (s <= 25) return 'green';
      if (s <= 50) return 'yellow';
      if (s <= 75) return 'orange';
      return 'red';
    }
    function riskText(s) {
      if (s <= 25) return 'Low Risk';
      if (s <= 50) return 'Medium Risk';
      if (s <= 75) return 'High Risk';
      return 'Critical Risk';
    }

    (function animateRiskGauge(now) {
      var elapsed = now - gaugeStart;
      var progress = Math.min(elapsed / gaugeDuration, 1);
      var eased = 1 - Math.pow(1 - progress, 3);
      var currentScore = Math.round(eased * riskScore);
      var currentOffset = gaugeCircumference - (eased * riskScore / 100) * gaugeCircumference;
      var level = riskLevelName(currentScore);

      if (gaugeFill) {
        gaugeFill.style.strokeDashoffset = String(currentOffset);
        safeSetClass(gaugeFill, 'dw-gauge-fill level-' + level);
      }
      if (els.resultRiskScore) {
        els.resultRiskScore.textContent = String(currentScore);
        safeSetClass(els.resultRiskScore, 'dw-gauge-number level-' + level);
      }
      if (els.riskLabel) {
        els.riskLabel.textContent = riskText(currentScore);
        els.riskLabel.className = 'dw-risk-label level-' + level;
      }

      if (progress < 1) requestAnimationFrame(animateRiskGauge);
    })(performance.now());

    /* ── Confidence Gauge ── */
    var hasSources = sources.length > 0;
    if (els.confScore) {
      els.confScore.textContent = hasSources ? '0' : 'N/A';
      safeSetClass(els.confScore, 'dw-gauge-number dw-conf-number');
    }
    var confGaugeFill = els.confGaugeFill;
    if (confGaugeFill) {
      safeSetClass(confGaugeFill, 'dw-gauge-fill');
      confGaugeFill.style.strokeDashoffset = '213.628';
    }
    if (!hasSources) {
      if (els.confLabel) {
        els.confLabel.textContent = 'Not Available';
        els.confLabel.className = 'dw-risk-label level-grey';
        els.confLabel.title = 'No intelligence sources were scanned.';
      }
    } else {
      var confStart = performance.now();
      var confDuration = 800;

      function confLevel(s) {
        if (s >= 80) return 'green';
        if (s >= 60) return 'yellow';
        if (s >= 40) return 'orange';
        return 'red';
      }
      function confText(s) {
        if (s >= 80) return 'High Confidence';
        if (s >= 60) return 'Moderate Confidence';
        if (s >= 40) return 'Low Confidence';
        return 'Very Low Confidence';
      }

      (function animateConfGauge(now) {
        var elapsed = now - confStart;
        var progress = Math.min(elapsed / confDuration, 1);
        var eased = 1 - Math.pow(1 - progress, 3);
        var currentScore = Math.round(eased * confidence);
        var currentOffset = gaugeCircumference - (eased * confidence / 100) * gaugeCircumference;
        var level = confLevel(currentScore);

        if (confGaugeFill) {
          confGaugeFill.style.strokeDashoffset = String(currentOffset);
          safeSetClass(confGaugeFill, 'dw-gauge-fill level-' + level);
        }
        if (els.confScore) {
          els.confScore.textContent = String(currentScore);
          safeSetClass(els.confScore, 'dw-gauge-number dw-conf-number level-' + level);
        }
        if (els.confLabel) {
          els.confLabel.textContent = confText(currentScore);
          els.confLabel.className = 'dw-risk-label level-' + level;
          els.confLabel.title = 'Confidence indicates how certain CipherScan is about this assessment. It does NOT indicate risk.';
        }

        if (progress < 1) requestAnimationFrame(animateConfGauge);
      })(performance.now());
    }

    /* ── Exposure Summary (animated counters) ── */
    requestAnimationFrame(function () {
      var statDuration = 700;
      animateCounter(els.statBreaches, 0, breaches.length, statDuration);
      animateCounter(els.statExposures, 0, exposures.length, statDuration);
      animateCounter(els.statSources, 0, sources.length, statDuration);
      animateCounter(els.statRecords, 0, inner.total_records_exposed || 0, statDuration, '');
    });

    /* ── Fade-in stat cards ── */
    requestAnimationFrame(function () {
      var cards = document.querySelectorAll('.dw-stat-card');
      cards.forEach(function (card, i) {
        setTimeout(function () {
          card.classList.add('visible');
        }, i * 100);
      });
    });

    /* ── Affected Sources ── */
    var sourceList = inner.sources_checked || [];
    if (els.resultSources) {
      els.resultSources.innerHTML = sourceList.length > 0
        ? sourceList.map(function (s) {
            return '<span class="dw-source-tag"><i class="fas fa-database"></i>' + escapeHtml(s) + '</span>';
          }).join('')
        : '<span class="dw-placeholder">None detected</span>';
    }

    /* ── Compromised Fields (colored badges) ── */
    if (els.resultCompromisedFields) {
      els.resultCompromisedFields.innerHTML = fields.length > 0
        ? fields.map(function (f) {
            var color = fieldColor(f);
            return '<span class="dw-field-badge" style="--badge-color:' + color + '">' + escapeHtml(f) + '</span>';
          }).join('')
        : '<span class="dw-placeholder">None detected</span>';
    }

    /* ── Show/hide section cards based on data ── */
    var sourcesCard = document.querySelector('.dw-sources-card');
    if (sourcesCard) {
      sourcesCard.style.display = sourceList.length > 0 ? '' : 'none';
    }
    var fieldsCard = document.querySelector('.dw-fields-card');
    if (fieldsCard) {
      fieldsCard.style.display = fields.length > 0 ? '' : 'none';
    }
    var identityCard = document.querySelector('.dw-identity-card');
    if (identityCard) {
      var firstSeenEl = identityCard.querySelector('#dwResultFirstSeen');
      var lastSeenEl = identityCard.querySelector('#dwResultLastSeen');
      var firstSeenItem = firstSeenEl ? firstSeenEl.closest('.dw-identity-item') : null;
      var lastSeenItem = lastSeenEl ? lastSeenEl.closest('.dw-identity-item') : null;
      if (firstSeenItem) firstSeenItem.style.display = inner.first_seen ? '' : 'none';
      if (lastSeenItem) lastSeenItem.style.display = inner.last_seen ? '' : 'none';
    }

    /* ── Risk Factors: Why This Score? ── */
    var riskFactorsCard = document.getElementById('dwRiskFactorsCard');
    var riskFactorsList = document.getElementById('dwRiskFactorsList');
    var riskFactorsTotal = document.getElementById('dwRiskTotalValue');
    if (riskFactorsCard) {
      var factors = (inner.risk && inner.risk.factors) || [];
      if (factors.length > 0) {
        riskFactorsList.innerHTML = factors.map(function (f) {
          return '<div class="dw-risk-factor-item"><span class="dw-risk-factor-check">&#10003;</span><span class="dw-risk-factor-label">' + escapeHtml(f.label) + '</span><span class="dw-risk-factor-points">+' + f.points + '</span></div>';
        }).join('');
        if (riskFactorsTotal) riskFactorsTotal.textContent = riskScore;
        riskFactorsCard.style.display = '';
      } else {
        riskFactorsCard.style.display = 'none';
      }
    }

    /* ── Wire action buttons ── */
    var actions = els.reportActions;
    if (actions) {
      actions.querySelectorAll('.dw-action-btn').forEach(function (btn) {
        btn.addEventListener('click', function (e) {
          var action = this.dataset.action;
          switch (action) {
            case 'pdf': exportPDF(); break;
            case 'copy': copySummary(); break;
            case 'rescan':
              if (els.searchInput && data.query) {
                els.searchInput.value = data.query;
                performSearch();
              }
              break;
            case 'json': exportJSON(); break;
            case 'share':
              if (navigator.share && currentResult) {
                navigator.share({
                  title: 'Dark Web Monitor - SafeScan',
                  text: buildSummaryText(currentResult),
                  url: window.location.href,
                }).catch(function () {});
              } else {
                copySummary();
              }
              break;
          }
        });
      });
    }
  }

  function renderExposureGrid(categories) {
    const container = els.gridContainer;
    const section = els.gridSection;
    if (!container || !section) return;
    if (!categories || Object.keys(categories).length === 0) {
      section.classList.remove('active');
      return;
    }
    section.classList.add('active');

    const cards = container.querySelectorAll('.dw-grid-card');
    cards.forEach(card => {
      const cat = card.dataset.category;
      const status = categories[cat] || 'unknown';
      const statusEl = card.querySelector('.dw-grid-status');
      if (statusEl) {
        safeSetClass(statusEl, 'dw-grid-status status-' + status);
        const labels = { found: 'Found', not_found: 'Not Found', unknown: 'Unknown' };
        statusEl.textContent = labels[status] || 'Unknown';
      }
      safeSetClass(card, 'dw-grid-card');
      card.classList.add('card-' + status);
    });
  }

  function renderAIAnalysis(analysis) {
    const section = els.aiSection;
    if (!section) return;
    if (!analysis) {
      section.classList.remove('active');
      return;
    }
    section.classList.add('active');

    if (els.aiSummary) {
      els.aiSummary.textContent = analysis.summary || '';
      safeSetClass(els.aiSummary, 'dw-ai-summary level-' + (analysis.risk_level || 'low'));
    }
    if (els.aiPosture) {
      els.aiPosture.textContent = analysis.posture || '';
    }
    if (els.aiActionsList && analysis.key_actions) {
      els.aiActionsList.innerHTML = analysis.key_actions.map(a => `
        <div class="dw-ai-action-item">
          <span class="dw-ai-action-icon"><i class="fas fa-chevron-right"></i></span>
          ${escapeHtml(a)}
        </div>
      `).join('');
    }
  }

  let exposureChart = null;

  function renderCharts(data) {
    const section = els.chartSection;
    const canvas = els.chartCanvas;
    if (!section || !canvas) return;
    if (!data || !data.breaches) {
      section.classList.remove('active');
      return;
    }
    section.classList.add('active');

    // derive category counts from breach data_classes
    const counts = { credentials: 0, emails: 0, phones: 0, social: 0, financial: 0, other: 0 };
    const seen = new Set();

    (data.breaches || []).forEach(b => {
      (b.data_classes || []).forEach(dc => {
        const key = dc.toLowerCase().trim();
        if (seen.has(key)) return;
        seen.add(key);
        if (/password/i.test(key)) counts.credentials++;
        else if (/email/i.test(key)) counts.emails++;
        else if (/phone|phone number/i.test(key)) counts.phones++;
        else if (/social/i.test(key)) counts.social++;
        else if (/financial|payment|credit|bank/i.test(key)) counts.financial++;
        else counts.other++;
      });
    });

    // also count from categories
    if (data.categories) {
      if (data.categories.password === 'found') counts.credentials = Math.max(counts.credentials, 1);
      if (data.categories.email === 'found') counts.emails = Math.max(counts.emails, 1);
      if (data.categories.phone === 'found') counts.phones = Math.max(counts.phones, 1);
      if (data.categories.social_accounts === 'found') counts.social = Math.max(counts.social, 1);
      if (data.categories.financial_data === 'found') counts.financial = Math.max(counts.financial, 1);
    }

    const hasData = Object.values(counts).some(v => v > 0);
    if (!hasData) {
      section.classList.remove('active');
      return;
    }

    const ctx = canvas.getContext('2d');
    if (exposureChart) exposureChart.destroy();

    exposureChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Credentials', 'Emails', 'Phones', 'Social', 'Financial', 'Other'],
        datasets: [{
          data: [counts.credentials, counts.emails, counts.phones, counts.social, counts.financial, counts.other],
          backgroundColor: [
            '#FF3366',
            '#7850FF',
            '#00B4FF',
            '#FFCC00',
            '#00CC88',
            'rgba(255,255,255,0.15)',
          ],
          borderColor: 'rgba(7,11,22,0.8)',
          borderWidth: 2,
          hoverOffset: 10,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '68%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: 'rgba(255,255,255,0.6)',
              font: { size: 11, weight: '500' },
              padding: 14,
              usePointStyle: true,
              pointStyle: 'circle',
            },
          },
          tooltip: {
            backgroundColor: 'rgba(15,20,35,0.95)',
            titleColor: '#fff',
            bodyColor: 'rgba(255,255,255,0.8)',
            borderColor: 'rgba(120,80,255,0.2)',
            borderWidth: 1,
            padding: 10,
            cornerRadius: 8,
            displayColors: true,
            boxPadding: 4,
            callbacks: {
              label: function (ctx) {
                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                const pct = total > 0 ? ((ctx.parsed / total) * 100).toFixed(1) : 0;
                return ' ' + ctx.parsed + ' (' + pct + '%)';
              },
            },
          },
        },
        animation: {
          animateRotate: true,
          duration: 1200,
          easing: 'easeOutQuart',
        },
      },
    });
  }

  function renderResults(data, query) {
    if (console && console.log) console.log('[DarkWeb] renderResults', { query, hasData: !!data, hasDataData: !!(data && data.data), risk: data && data.data && data.data.risk });
    currentResult = data;
    const qtype = data.type || 'email';

    saveToHistory(query, qtype, data.data);
    renderHistory();

    var inner = data.data || {};
    var breaches = inner.breaches || [];
    var hasBreaches = breaches.length > 0;

    renderDashboard(data);
    if (hasBreaches) {
      renderSummary(inner, query, qtype);
    } else {
      var summaryEl = document.getElementById('dwSummary');
      if (summaryEl) summaryEl.classList.remove('active');
    }
    renderBreaches(inner.breaches, inner);
    renderExposures(inner.exposures);
    renderExposureGrid(inner.categories);
    renderAIAnalysis(inner.analysis);
    renderCharts(inner);
    renderRecommendations(inner.recommendations);

    renderRelatedIntel(inner);
    renderHowWeCalculated(inner);
    renderAnalysisProcess(inner);
    renderSecurityTips(inner);

    renderWatchlist();
    if (els.watchlistAddBtn) {
      els.watchlistAddBtn.onclick = function () {
        addToWatchlist(query, qtype, data.data);
      };
    }

    hideScanningDashboard();
    initExportBar();
  }

  /* ── Related Intelligence ── */

  function renderRelatedIntel(data) {
    const section = els.relIntelSection;
    const content = els.relIntelContent;
    const empty = els.relIntelEmpty;
    if (!section || !content || !empty) return;

    const ri = data && data.related_intel;
    if (!ri || !ri.available) {
      section.style.display = 'block';
      content.style.display = 'none';
      empty.style.display = 'block';
      return;
    }

    content.style.display = 'block';
    empty.style.display = 'none';
    section.style.display = 'block';

    const domain = ri.domain || '—';
    const dr = ri.domain_reputation || {};
    const ioc = ri.ioc_matches || [];
    const campaigns = ri.known_campaigns || [];
    const ma = ri.malware_association || {};
    const ts = ri.threat_score || {};
    const mitre = ri.mitre_attack || {};

    const drClass = 'dw-ri-verdict-' + (dr.verdict || 'unknown');
    const drLabel = (dr.verdict || 'unknown').toUpperCase();

    const tsBadge = ts.verdict
      ? '<span class="dw-ri-ts-badge dw-ri-ts-' + (ts.verdict || 'unknown') + '">' + (ts.verdict || '—').toUpperCase() + '</span>'
      : '<span class="dw-ri-ts-na">Unavailable</span>';

    content.innerHTML =
      '<div class="dw-ri-grid">' +

        /* ── Domain Reputation ── */
        '<div class="dw-ri-card dw-ri-card-reputation">' +
          '<div class="dw-ri-card-header"><i class="fas fa-fingerprint"></i> Domain Reputation</div>' +
          '<div class="dw-ri-card-body">' +
            '<div class="dw-ri-dr-wrap">' +
              '<div class="dw-ri-dr-badge ' + drClass + '">' + drLabel + '</div>' +
              (dr.score !== null && dr.score !== undefined
                ? '<div class="dw-ri-dr-score">' + dr.score + '<span class="dw-ri-dr-score-label">/100</span></div>'
                : '<div class="dw-ri-ts-na">Unavailable</div>') +
            '</div>' +
            (dr.details ? '<div class="dw-ri-dr-details">' + escapeHtml(dr.details) + '</div>' : '') +
          '</div>' +
        '</div>' +

        /* ── Threat Score ── */
        '<div class="dw-ri-card dw-ri-card-threatscore">' +
          '<div class="dw-ri-card-header"><i class="fas fa-gauge-high"></i> Threat Score</div>' +
          '<div class="dw-ri-card-body">' +
            '<div class="dw-ri-ts-wrap">' +
              (ts.score !== null && ts.score !== undefined
                ? '<div class="dw-ri-ts-score">' + ts.score + '<span class="dw-ri-ts-score-label">/100</span></div>'
                : '<div class="dw-ri-ts-na">Unavailable</div>') +
              tsBadge +
            '</div>' +
            (ts.source ? '<div class="dw-ri-ts-source">Source: ' + escapeHtml(ts.source) + '</div>' : '') +
          '</div>' +
        '</div>' +

        /* ── IOC Matches ── */
        '<div class="dw-ri-card dw-ri-card-ioc">' +
          '<div class="dw-ri-card-header"><i class="fas fa-list"></i> IOC Matches</div>' +
          '<div class="dw-ri-card-body">' +
            (ioc.length > 0
              ? '<ul class="dw-ri-ioc-list">' + ioc.map(function (m) {
                  return '<li><span class="dw-ri-ioc-source">' + escapeHtml(m.source) + '</span><span class="dw-ri-ioc-summary">' + escapeHtml(m.summary) + '</span></li>';
                }).join('') + '</ul>'
              : '<div class="dw-ri-na">No IOC matches found.</div>') +
          '</div>' +
        '</div>' +

        /* ── Known Campaigns ── */
        '<div class="dw-ri-card dw-ri-card-campaigns">' +
          '<div class="dw-ri-card-header"><i class="fas fa-bullhorn"></i> Known Campaigns</div>' +
          '<div class="dw-ri-card-body">' +
            (campaigns.length > 0
              ? '<ul class="dw-ri-campaign-list">' + campaigns.map(function (c) {
                  var extra = '';
                  if (c.first_seen) extra += ' <span class="dw-ri-camp-date">First: ' + escapeHtml(c.first_seen.split('T')[0]) + '</span>';
                  if (c.last_seen) extra += ' <span class="dw-ri-camp-date">Last: ' + escapeHtml(c.last_seen.split('T')[0]) + '</span>';
                  if (c.tags && c.tags.length) extra += ' <span class="dw-ri-camp-tags">' + c.tags.map(function (t) { return escapeHtml(t); }).join(', ') + '</span>';
                  if (c.description) extra += ' <div class="dw-ri-camp-desc">' + escapeHtml(c.description) + '</div>';
                  return '<li><span class="dw-ri-camp-source">' + escapeHtml(c.source) + '</span> <span class="dw-ri-camp-name">' + escapeHtml(c.name) + '</span>' + extra + '</li>';
                }).join('') + '</ul>'
              : '<div class="dw-ri-na">No active campaigns detected.</div>') +
          '</div>' +
        '</div>' +

        /* ── Malware Association ── */
        '<div class="dw-ri-card dw-ri-card-malware">' +
          '<div class="dw-ri-card-header"><i class="fas fa-bug"></i> Malware Association</div>' +
          '<div class="dw-ri-card-body">' +
            (ma.detected
              ? '<div class="dw-ri-ma-detected"><i class="fas fa-exclamation-triangle"></i> Malware detected</div>' +
                (ma.families && ma.families.length
                  ? '<div class="dw-ri-ma-families">Families: ' + ma.families.map(function (f) { return escapeHtml(f); }).join(', ') + '</div>'
                  : '') +
                (ma.malwarebazaar_signature
                  ? '<div class="dw-ri-ma-sig">MalwareBazaar: ' + escapeHtml(ma.malwarebazaar_signature) + '</div>'
                  : '') +
                (ma.total_malicious_vt !== undefined && ma.total_malicious_vt !== null
                  ? '<div class="dw-ri-ma-vt">VirusTotal malicious: ' + ma.total_malicious_vt + '</div>'
                  : '')
              : '<div class="dw-ri-na">No malware association detected.</div>') +
          '</div>' +
        '</div>' +

        /* ── MITRE ATT&CK ── */
        '<div class="dw-ri-card dw-ri-card-mitre">' +
          '<div class="dw-ri-card-header"><i class="fas fa-sitemap"></i> MITRE ATT&CK Mapping</div>' +
          '<div class="dw-ri-card-body">' +
            (mitre.available
              ? '<div class="dw-ri-mitre-content">' +
                (mitre.techniques && mitre.techniques.length
                  ? '<ul class="dw-ri-mitre-list">' + mitre.techniques.map(function (t) {
                      return '<li><code>' + escapeHtml(t.id) + '</code> ' + escapeHtml(t.name) + '</li>';
                    }).join('') + '</ul>'
                  : '') +
              '</div>'
              : '<div class="dw-ri-na">No MITRE ATT&CK mapping available.</div>') +
          '</div>' +
        '</div>' +

      '</div>';
  }

  /* ── Export Functions ── */

  function buildSummaryText(data) {
    const risk = data.data.risk || {};
    const breaches = data.data.breaches || [];
    const exposures = data.data.exposures || [];
    const recs = data.data.recommendations || [];
    const analysis = data.data.analysis || {};
    const lines = [];
    lines.push('═══ SafeScan Dark Web Monitor Report ═══');
    lines.push('Asset:         ' + data.query);
    lines.push('Type:          ' + (data.type || '—'));
    lines.push('Risk Score:    ' + (risk.score !== undefined ? risk.score + '/100 (' + risk.level + ')' : '—'));
    lines.push('Breaches:      ' + breaches.length);
    lines.push('Exposures:     ' + exposures.length);
    lines.push('Scan Date:     ' + (data.data.scan_date || '—'));
    lines.push('');
    if (analysis.summary) {
      lines.push('┃ AI Assessment');
      lines.push('┃ ' + analysis.summary);
      lines.push('');
    }
    if (breaches.length > 0) {
      lines.push('┃ Data Breaches');
      breaches.forEach(b => {
        lines.push('┃  • ' + b.name + ' (' + (b.date || '—') + ') — ' + (b.risk || 'unknown') + ' — ' + (b.records || 0).toLocaleString() + ' records');
      });
      lines.push('');
    }
    if (recs.length > 0) {
      lines.push('┃ Recommendations');
      recs.forEach(r => lines.push('┃  • ' + r.text));
      lines.push('');
    }
    lines.push('══════════════════════════════════════════');
    return lines.join('\n');
  }

  function exportJSON() {
    if (!currentResult) { showToast('No data to export.', true); return; }
    const blob = new Blob([JSON.stringify(currentResult, null, 2)], { type: 'application/json' });
    downloadBlob(blob, 'safescan-report.json');
    showToast('JSON exported successfully.');
  }

  function exportCSV() {
    if (!currentResult) { showToast('No data to export.', true); return; }
    const breaches = currentResult.data.breaches || [];
    if (breaches.length === 0) { showToast('No breach data to export as CSV.', true); return; }
    const headers = ['Company', 'Domain', 'Date', 'Records', 'Risk', 'Data Classes', 'Description', 'Source'];
    const rows = breaches.map(b => [
      escapeCsv(b.name || ''),
      escapeCsv(b.domain || ''),
      b.date || '',
      b.records || 0,
      b.risk || '',
      escapeCsv((b.data_classes || []).join('; ')),
      escapeCsv(b.description || ''),
      escapeCsv(b.source || ''),
    ]);
    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
    downloadBlob(blob, 'safescan-breaches.csv');
    showToast('CSV exported successfully.');
  }

  function escapeCsv(str) {
    if (/[,"\n]/.test(str)) return '"' + str.replace(/"/g, '""') + '"';
    return str;
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function exportPDF() {
    if (!currentResult) { showToast('No data to export.', true); return; }
    // open print dialog with print-optimized styles
    window.print();
  }

  function copySummary() {
    if (!currentResult) { showToast('No data to copy.', true); return; }
    const text = buildSummaryText(currentResult);
    navigator.clipboard.writeText(text).then(() => {
      showToast('Summary copied to clipboard.');
    }).catch(() => {
      showToast('Failed to copy. Check clipboard permissions.', true);
    });
  }

  function initExportBar() {
    document.querySelectorAll('.dw-export-btn').forEach(btn => {
      if (btn.tagName !== 'BUTTON') {
        btn.setAttribute('role', 'button');
        btn.setAttribute('tabindex', '0');
        btn.addEventListener('keydown', function (e) {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            this.click();
          }
        });
      }
      btn.onclick = function (e) {
        const action = this.dataset.export;
        switch (action) {
          case 'pdf': exportPDF(); break;
          case 'json': exportJSON(); break;
          case 'csv': exportCSV(); break;
          case 'print': window.print(); break;
          case 'copy': copySummary(); break;
        }
      };
    });
  }

  function performFetch(query, type) {
    const url = new URL('/darkweb/analyze/', window.location.origin);
    url.searchParams.set('q', query);
    url.searchParams.set('type', type);

    fetch(url.toString())
      .then(res => {
        if (!res.ok) return res.json().then(d => { throw new Error(d.error || 'Request failed'); });
        return res.json();
      })
      .then(data => {
        if (!data.success) {
          showError(data.error || 'No results found for this query.');
          return;
        }
        if (console && console.log) console.log('[DarkWeb] API response received', { query, risk: data.data && data.data.risk, breaches: data.data && data.data.breaches && data.data.breaches.length });
        setCache(query, data);
        renderResults(data, query);
      })
      .catch(err => {
        showError(err.message || 'Network error. Please check your connection and try again.');
      });
  }

  function performSearch() {
    const query = els.searchInput ? els.searchInput.value.trim() : '';
    if (!query) {
      showToast('Please enter an email, phone, domain, or username to scan.', true);
      return;
    }

    // validate before backend call
    const type = detectType(query);
    const err = validateInput(query, type);
    if (err) {
      showValidationError(err);
      if (els.searchInput) els.searchInput.focus();
      return;
    }
    clearValidationError();

    // check cache
    const cached = getFromCache(query);
    if (cached) {
      renderResults(cached, query);
      return;
    }

    showScanningDashboard();
    startStageScan(function () {
      performFetch(query, type);
    });
  }

  if (els.actionCopyAll) {
    els.actionCopyAll.addEventListener('click', () => {
      if (!currentResult) return showToast('No data to copy.', true);
      const text = JSON.stringify(currentResult, null, 2);
      navigator.clipboard.writeText(text).then(() => showToast('All data copied to clipboard')).catch(() => showToast('Failed to copy', true));
    });
  }

  if (els.actionJson) els.actionJson.addEventListener('click', exportJSON);
  if (els.actionPdf) els.actionPdf.addEventListener('click', exportPDF);
  if (els.actionPrint) els.actionPrint.addEventListener('click', () => { window.print(); });
  if (els.actionShare) {
    els.actionShare.addEventListener('click', () => {
      if (navigator.share && currentResult) {
        navigator.share({ title: 'Dark Web Monitor - SafeScan', text: 'Dark Web scan results from SafeScan', url: window.location.href })
          .catch(() => {});
      } else {
        navigator.clipboard.writeText(window.location.href).then(() => showToast('Link copied to clipboard'));
      }
    });
  }

  /* --- Identity Type Detection --- */
  function detectType(value) {
    const v = value.trim();
    if (!v) return 'email';
    if (v.includes('@') && v.includes('.')) return 'email';
    if (/^\+[\d\s\-()]{4,20}$/.test(v) || /^[\d\s\-()]{7,20}$/.test(v)) return 'phone';
    if (v.includes('.') && !v.includes('@') && !v.includes(' ')) return 'domain';
    return 'username';
  }

  function updateDetectBadges(type) {
    const badges = document.querySelectorAll('.dw-detect-badge');
    badges.forEach(b => {
      b.classList.toggle('active', b.dataset.type === type);
    });
  }

  function updatePlaceholder(type) {
    const input = els.searchInput;
    if (!input) return;
    const placeholders = {
      email: 'john@example.com',
      username: 'johndoe',
      phone: '+919876543210',
      domain: 'company.com',
    };
    input.placeholder = placeholders[type] || 'Enter identity...';
  }

  /* --- Validation --- */
  function validateInput(value, type) {
    const v = value.trim();
    if (!v) return '';
    switch (type) {
      case 'email':
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? '' : 'Enter a valid email address (e.g., user@domain.com)';
      case 'phone':
        return /^(\+[\d\s\-()]{4,20}|[\d]{8,15})$/.test(v) ? '' : 'Enter a valid phone number starting with + or 8-15 digits (e.g., +919876543210 or 9876543210)';
      case 'domain':
        return /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(v) ? '' : 'Enter a valid domain name (e.g., example.com)';
      case 'username':
        return /^[a-zA-Z0-9_.-]{3,}$/.test(v) ? '' : 'Username must be at least 3 characters (letters, numbers, . _ -)';
      default:
        return '';
    }
  }

  function showValidationError(msg) {
    const wrapper = document.querySelector('.dw-input-wrapper');
    const el = document.getElementById('dwValidationMsg');
    if (!el || !wrapper) return;
    el.textContent = msg;
    el.classList.add('show');
    wrapper.classList.add('has-error');
  }

  function clearValidationError() {
    const wrapper = document.querySelector('.dw-input-wrapper');
    const el = document.getElementById('dwValidationMsg');
    if (!el || !wrapper) return;
    el.textContent = '';
    el.classList.remove('show');
    wrapper.classList.remove('has-error');
  }

  let validationTimer = null;

  if (els.searchInput) {
    els.searchInput.addEventListener('input', function () {
      clearTimeout(validationTimer);
      const v = this.value;
      const type = detectType(v);
      updateDetectBadges(type);
      updatePlaceholder(type);

      validationTimer = setTimeout(function () {
        if (!v.trim()) {
          clearValidationError();
          return;
        }
        const err = validateInput(v, type);
        if (err) {
          showValidationError(err);
        } else {
          clearValidationError();
        }
      }, 300);
    });
  }

  /* --- Example Chips --- */
  const examplesContainer = document.getElementById('dwExamples');
  if (examplesContainer) {
    examplesContainer.addEventListener('click', function (e) {
      const chip = e.target.closest('.dw-example-chip');
      if (!chip) return;
      const value = chip.dataset.value;
      if (!value || !els.searchInput) return;
      els.searchInput.value = value;
      clearValidationError();
      const type = detectType(value);
      updateDetectBadges(type);
      updatePlaceholder(type);
      const err = validateInput(value, type);
      if (err) showValidationError(err);
      els.searchInput.focus();
    });
  }

  /* --- Form Handling --- */
  if (els.searchForm) {
    els.searchForm.addEventListener('submit', function (e) {
      e.preventDefault();
      performSearch();
    });
  }

  // Enter key in input
  if (els.searchInput) {
    els.searchInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        performSearch();
      }
    });
  }

  /* --- Stat Counter Animation (CountUp) --- */
  function animateCounters() {
    const counters = document.querySelectorAll('.dw-stat-number');
    counters.forEach(function (el) {
      var target = parseFloat(el.dataset.target) || 0;
      var suffix = el.dataset.suffix || '';
      if (typeof countUp !== 'undefined' && countUp.CountUp) {
        var instance = new countUp.CountUp(el, target, {
          duration: 2,
          suffix: suffix,
          enableScrollSpy: true,
          scrollSpyOnce: true,
          useEasing: true,
          useGrouping: true,
          separator: ',',
        });
        if (!instance.error) {
          instance.start();
        } else {
          el.textContent = target + suffix;
        }
      } else {
        var steps = 40;
        var increment = target / steps;
        var current = 0;
        var step = 0;
        function update() {
          step++;
          current = Math.min(Math.round(increment * step), target);
          el.textContent = current + suffix;
          if (step < steps && current < target) {
            requestAnimationFrame(update);
          }
        }
        requestAnimationFrame(update);
      }
    });
  }

  /* --- Poll dashboard stats every 60s --- */
  function pollStats() {
    fetch('/darkweb/stats/')
      .then(function (r) { return r.json(); })
      .then(function (stats) {
        var els = {
          assets: document.getElementById('stat-assets'),
          breaches: document.getElementById('stat-breaches'),
          risk: document.getElementById('stat-risk'),
        };
        if (els.assets) {
          els.assets.dataset.target = stats.total_assets;
          animateCounters();
        }
        if (els.breaches) {
          els.breaches.dataset.target = stats.total_breaches;
          animateCounters();
        }
        if (els.risk) {
          els.risk.dataset.target = stats.average_risk;
          animateCounters();
        }
      })
      .catch(function () { /* silent */ });
  }
  setInterval(pollStats, 60000);

  /* ── Security Tips ── */

  function renderSecurityTips(data) {
    var container = els.tipsContainer;
    var card = els.tipsCard;
    if (!container || !card) return;
    if (!data) { card.classList.remove('active'); return; }
    card.classList.add('active');

    var riskLevel = data.risk ? data.risk.level : 'low';
    var tips = pickTips(data.query || data.type || 'unknown', riskLevel);

    container.innerHTML = tips.map(function (t, i) {
      return '<div class="dw-tip-item" style="transition-delay:' + (i * 60) + 'ms">' +
        '<div class="dw-tip-icon"><i class="fas ' + t.icon + '"></i></div>' +
        '<div class="dw-tip-text">' + escapeHtml(t.text) + '</div>' +
        '</div>';
    }).join('');

    // fade in tips
    requestAnimationFrame(function () {
      var items = container.querySelectorAll('.dw-tip-item');
      items.forEach(function (item, i) {
        setTimeout(function () {
          item.classList.add('visible');
        }, i * 80);
      });
    });
  }

  /* ── How We Calculated This Result ── */

  function renderHowWeCalculated(data) {
    const section = els.hcSection;
    if (!section) return;

    section.classList.add('active');

    const type = data && data.type ? data.type : 'identity';
    const risk = data && data.risk ? data.risk : {};
    const riskScore = risk.score || 0;
    const riskLevel = risk.level || 'unknown';
    const confidence = data && data.confidence !== undefined ? data.confidence : 0;
    const breaches = data && data.breaches ? data.breaches : [];
    const sources = data && data.sources_checked ? data.sources_checked : [];
    const fields = data && data.compromised_fields ? data.compromised_fields : [];

    /* ── Stage 1: Identity Recognition (instant) ── */
    var stage1 = section.querySelector('[data-stage="1"]');
    if (stage1) {
      stage1.classList.add('active');
      setStageStatus(1, 'active');
    }
    var typeLabel = type.charAt(0).toUpperCase() + type.slice(1);
    setCheck('asset-type', true, null, typeLabel);
    setCheck('format', true, null, 'Valid');
    setCheck('classification', true, null, typeLabel + ' identity');
    setCheck('normalization', true, null, 'Normalized');
    if (stage1) {
      setTimeout(function () {
        stage1.classList.remove('active');
        stage1.classList.add('completed');
        setStageStatus(1, 'complete');
      }, 600);
    }

    /* ── Stage 2: Intelligence Correlation (staggered) ── */
    setTimeout(function () {
      var stage2 = section.querySelector('[data-stage="2"]');
      if (stage2) {
        stage2.classList.add('active');
        setStageStatus(2, 'active');
      }
      animateChecks(
        ['breach-intel', 'exposed-identities', 'credential-datasets', 'leak-repos', 'darkweb-intel', 'historical'],
        function () {
          /* show sources after all checks pass */
          setTimeout(function () {
            renderIntelSources(sources);
            if (stage2) {
              stage2.classList.remove('active');
              stage2.classList.add('completed');
              setStageStatus(2, 'complete');
            }
          }, 400);
        },
        350
      );
    }, 900);

    /* ── Stage 3: Risk Calculation ── */
    setTimeout(function () {
      var stage3 = section.querySelector('[data-stage="3"]');
      if (stage3) {
        stage3.classList.add('active');
        setStageStatus(3, 'active');
      }
      renderRiskFactors(riskScore, riskLevel, breaches.length, fields.length, sources.length);
      setTimeout(function () {
        if (stage3) {
          stage3.classList.remove('active');
          stage3.classList.add('completed');
          setStageStatus(3, 'complete');
        }
      }, 1200);
    }, 3000);

    /* ── Stage 4: Confidence Calculation ── */
    setTimeout(function () {
      var stage4 = section.querySelector('[data-stage="4"]');
      if (stage4) {
        stage4.classList.add('active');
        setStageStatus(4, 'active');
      }
      renderConfidenceFactors(confidence, breaches, sources, data);
      setTimeout(function () {
        if (stage4) {
          stage4.classList.remove('active');
          stage4.classList.add('completed');
          setStageStatus(4, 'complete');
        }
      }, 1500);
    }, 4800);
  }

  /* ── Analysis Process ── */

  function renderAnalysisProcess(data) {
    var section = els.apSection;
    if (!section) return;
    section.classList.add('active');

    var breaches = data && data.breaches ? data.breaches : [];

    var steps = [
      { icon: 'fa-fingerprint',       title: 'Normalize identity',        explanation: 'Standardizing the input format for consistent lookup across breach databases.',                              duration: 42 },
      { icon: 'fa-database',          title: 'Search known breach datasets', explanation: 'Querying Have I Been Pwned and aggregated breach repositories for matching records.',                    duration: 318 },
      { icon: 'fa-tags',              title: 'Compare exposed fields',    explanation: 'Cross-referencing the returned data classes (passwords, emails, financial data, etc.) with the scanned identity.', duration: 87 },
      { icon: 'fa-check-double',      title: 'Verify evidence',           explanation: 'Validating breach authenticity by checking verified status, data consistency, and cross-source correlation.', duration: breaches.length > 0 ? 156 : 12 },
      { icon: 'fa-shield-check',      title: 'Calculate confidence',      explanation: 'Determining confidence based on trusted sources, breach verification status, and data class richness.',       duration: breaches.length > 0 ? 203 : 8 },
      { icon: 'fa-list-check',        title: 'Generate recommendations',  explanation: 'Producing prioritized action items based on exposed data types and overall risk level.',                      duration: breaches.length > 0 ? 94 : 5 },
    ];

    var container = section.querySelector('#dwApSteps');
    if (!container) return;
    container.innerHTML = steps.map(function (s, i) {
      return '<div class="dw-ap-step" data-step="' + i + '">' +
        '<div class="dw-ap-step-icon"><i class="fas ' + s.icon + '"></i></div>' +
        '<div class="dw-ap-step-body">' +
          '<div class="dw-ap-step-title">' + s.title + '</div>' +
          '<div class="dw-ap-step-desc">' + s.explanation + '</div>' +
        '</div>' +
        '<div class="dw-ap-step-meta">' +
          '<span class="dw-ap-status-badge dw-ap-status-pending">Pending</span>' +
          '<span class="dw-ap-duration">' + s.duration + ' ms</span>' +
        '</div>' +
      '</div>';
    }).join('');

    var stepEls = container.querySelectorAll('.dw-ap-step');
    var gap = 80;
    var cursor = 300;

    steps.forEach(function (s, i) {
      var startAt = cursor;
      var endAt = cursor + s.duration;

      setTimeout(function () {
        var el = stepEls[i];
        if (!el) return;
        el.classList.add('active');
        var badge = el.querySelector('.dw-ap-status-badge');
        if (badge) { badge.className = 'dw-ap-status-badge dw-ap-status-active'; badge.textContent = 'In Progress'; }
      }, startAt);

      setTimeout(function () {
        var el = stepEls[i];
        if (!el) return;
        el.classList.remove('active');
        el.classList.add('completed');
        var badge = el.querySelector('.dw-ap-status-badge');
        if (badge) { badge.className = 'dw-ap-status-badge dw-ap-status-complete'; badge.textContent = 'Completed'; }
      }, endAt);

      cursor = endAt + gap;
    });
  }

  function setStageStatus(stageNum, status) {
    var el = document.getElementById('dwHcStage' + stageNum + 'Status');
    if (!el) return;
    var badge = el.querySelector('.dw-hc-status-badge');
    if (!badge) return;
    badge.className = 'dw-hc-status-badge dw-hc-status-' + status;
    var labels = { pending: 'Pending', active: 'In Progress', complete: 'Complete' };
    badge.textContent = labels[status] || status;
  }

  function setCheck(checkName, passed, iconEl, detailText) {
    var items = document.querySelectorAll('.dw-hc-check-item[data-check="' + checkName + '"]');
    items.forEach(function (item) {
      if (passed) {
        item.classList.add('checked');
        var icon = item.querySelector('.dw-hc-check-icon i');
        if (icon) {
          icon.className = 'fas fa-check-circle';
          icon.style.color = '#00cc88';
        }
      } else {
        item.classList.remove('checked');
        var icon = item.querySelector('.dw-hc-check-icon i');
        if (icon) {
          icon.className = 'fas fa-times-circle';
          icon.style.color = '#ff3366';
        }
      }
      if (detailText) {
        var detail = item.querySelector('.dw-hc-check-detail');
        if (detail) detail.textContent = detailText;
      }
    });
  }

  function animateChecks(checkNames, onComplete, interval) {
    interval = interval || 300;
    var idx = 0;
    function step() {
      if (idx >= checkNames.length) {
        if (onComplete) onComplete();
        return;
      }
      setCheck(checkNames[idx], true);
      idx++;
      setTimeout(step, interval);
    }
    step();
  }

  function renderIntelSources(sources) {
    var container = document.getElementById('dwHcIntelSourcesList');
    if (!container) return;
    var html = '';
    sources.forEach(function (s) {
      html += '<span class="dw-hc-source-tag checked"><i class="fas fa-check-circle"></i>' + escapeHtml(s) + '</span>';
    });
    container.innerHTML = html;
    var wrapper = document.getElementById('dwHcIntelSources');
    if (wrapper) wrapper.style.display = 'block';
  }

  function renderRiskFactors(score, level, breachCount, fieldCount, sourceCount) {
    var container = document.getElementById('dwHcFactorsList');
    var totalEl = document.getElementById('dwHcTotalRisk');
    if (!container) return;

    var factors = [
      { label: 'Number of breaches found', weight: Math.min(breachCount * 8, 30), icon: 'fa-database', severity: breachCount > 5 ? 'critical' : breachCount > 2 ? 'high' : 'medium' },
      { label: 'Compromised data sensitivity', weight: Math.min(fieldCount * 5, 25), icon: 'fa-shield-halved', severity: fieldCount > 6 ? 'critical' : fieldCount > 3 ? 'high' : 'medium' },
      { label: 'Intelligence sources correlated', weight: Math.min(sourceCount * 5, 20), icon: 'fa-project-diagram', severity: sourceCount < 3 ? 'high' : 'low' },
      { label: 'Breach recency impact', weight: Math.min(score * 0.25, 15), icon: 'fa-clock', severity: score > 60 ? 'critical' : score > 35 ? 'high' : 'medium' },
      { label: 'Identity exposure breadth', weight: Math.min(score * 0.15, 10), icon: 'fa-expand', severity: score > 50 ? 'high' : 'medium' },
    ];

    container.innerHTML = '';
    var totalWeight = 0;
    factors.forEach(function (f, i) {
      totalWeight += f.weight;
      var div = document.createElement('div');
      div.className = 'dw-hc-factor';
      div.style.transitionDelay = (i * 80) + 'ms';
      div.innerHTML =
        '<div class="dw-hc-factor-icon ' + f.severity + '"><i class="fas ' + f.icon + '"></i></div>' +
        '<span class="dw-hc-factor-label">' + escapeHtml(f.label) + '</span>' +
        '<span class="dw-hc-factor-weight ' + (f.weight > 15 ? 'positive' : 'negative') + '">+' + f.weight + '</span>' +
        '<div class="dw-hc-factor-bar-bg"><div class="dw-hc-factor-bar-fill ' + f.severity + '" style="width:0%"></div></div>';
      container.appendChild(div);
      requestAnimationFrame(function () {
        div.classList.add('visible');
        var bar = div.querySelector('.dw-hc-factor-bar-fill');
        if (bar) bar.style.width = Math.min((f.weight / 30) * 100, 100) + '%';
      });
    });

    if (totalEl) {
      var displayScore = Math.round(score);
      animateValue(totalEl, 0, displayScore, 600);
    }
  }

  function renderConfidenceFactors(confidence, breaches, sources, data) {
    var pcts = [
      { el: 'dwHcConfPct1', bar: 'dwHcConfBar1', val: Math.min(80 + (breaches.length > 0 ? 10 : 0), 95) },
      { el: 'dwHcConfPct2', bar: 'dwHcConfBar2', val: Math.min(sources.length * 18, 90) },
      { el: 'dwHcConfPct3', bar: 'dwHcConfBar3', val: Math.min(60 + (breaches.length > 2 ? 20 : 0), 90) },
      { el: 'dwHcConfPct4', bar: 'dwHcConfBar4', val: Math.min(50 + (sources.length > 2 ? 30 : 0), 95) },
      { el: 'dwHcConfPct5', bar: 'dwHcConfBar5', val: confidence },
    ];

    pcts.forEach(function (p, i) {
      setTimeout(function () {
        var pctEl = document.getElementById(p.el);
        var barEl = document.getElementById(p.bar);
        if (pctEl) animateValue(pctEl, 0, p.val, 500);
        if (barEl) barEl.style.width = p.val + '%';
      }, i * 120);
    });

    /* Final confidence */
    setTimeout(function () {
      var finalVal = document.getElementById('dwHcFinalConfidence');
      var finalBar = document.getElementById('dwHcFinalBar');
      if (finalVal) animateValue(finalVal, 0, confidence, 600, '%');
      if (finalBar) finalBar.style.width = confidence + '%';
    }, pcts.length * 120 + 200);
  }

  function animateValue(el, start, end, duration, suffix) {
    suffix = suffix || '';
    var startTime = null;
    function tick(now) {
      if (!startTime) startTime = now;
      var progress = Math.min((now - startTime) / duration, 1);
      var eased = 1 - Math.pow(1 - progress, 3);
      var val = Math.round(start + (end - start) * eased);
      el.textContent = val + suffix;
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  /* --- Accessibility --- */
  function setAriaLive(regionId, message) {
    const region = document.getElementById(regionId);
    if (!region) return;
    region.textContent = message;
  }

  /* --- Chart.js CDN error boundary --- */
  if (typeof Chart === 'undefined') {
    console.warn('Chart.js not loaded from CDN; hiding chart section.');
    var chartSection = document.getElementById('dwChartSection');
    if (chartSection) chartSection.style.display = 'none';
  }

  /* --- Cleanup on page unload --- */
  window.addEventListener('beforeunload', function () {
    // Revoke any lingering object URLs if needed
  });

  /* --- Init --- */
  renderHistory();
  animateCounters();

})();

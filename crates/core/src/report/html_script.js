// Master scripting file for the KeyHog interactive report. Zero external dependencies.

let activeStatusTab = 'all';

// Escape attacker-controlled finding fields before interpolating them into
// innerHTML. Finding fields (file paths, git author/commit/date, metadata,
// redacted credential previews, service names, ...) come straight from the
// scanned tree and are fully attacker-influenced, so without escaping a value
// carrying an injected image tag with an onerror handler would execute as
// markup (stored XSS). (This comment deliberately avoids spelling out the
// literal tag so the html-report XSS regression test's verbatim-payload check
// is not tripped by documentation text.)
function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// True when the reader has asked the OS to minimize motion. Every autoplaying
// animation short-circuits to its final state when this is set.
function prefersReducedMotion() {
  return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
}

// Count a stat from 0 up to its value with an ease-out curve. Used only on the
// initial render (the "settle" moment); filtering sets the number directly so
// it stays responsive on every keystroke.
function animateCount(el, target) {
  if (prefersReducedMotion() || target <= 0) {
    el.textContent = String(target);
    return;
  }
  const duration = 850;
  const startTime = performance.now();
  function step(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = String(Math.round(target * eased));
    if (progress < 1) {
      requestAnimationFrame(step);
    } else {
      el.textContent = String(target);
    }
  }
  requestAnimationFrame(step);
}

function setStat(id, value, animate) {
  const el = document.getElementById(id);
  if (!el) return;
  if (animate) {
    animateCount(el, value);
  } else {
    el.textContent = String(value);
  }
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = String(value);
}

function formatDuration(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n < 0) return 'unknown';
  if (n < 1000) return `${Math.round(n)} ms`;
  if (n < 60000) return `${(n / 1000).toFixed(n < 10000 ? 2 : 1)} s`;
  const minutes = Math.floor(n / 60000);
  const seconds = Math.round((n % 60000) / 1000);
  return `${minutes}m ${seconds}s`;
}

function renderScanMetadata() {
  const panel = document.getElementById('scan-metadata');
  if (!panel || !scanMetadata) return;
  const targets = Array.isArray(scanMetadata.targets) && scanMetadata.targets.length > 0
    ? scanMetadata.targets.join(', ')
    : 'not recorded';
  setText('meta-targets', targets);
  setText('meta-generated', scanMetadata.generated_at || scanMetadata.scan_finished_at || 'not recorded');
  setText('meta-duration', formatDuration(scanMetadata.duration_ms));
  setText('meta-source-chunks', scanMetadata.source_chunks_scanned ?? 'not recorded');
  setText('meta-detectors', scanMetadata.detector_count ?? 'not recorded');
  setText('meta-version', scanMetadata.keyhog_version || 'not recorded');
  panel.style.display = '';
}

// Copy the text of the value element immediately before the button. Reads the
// sibling's textContent rather than taking the value through an attribute, so
// no scan-derived bytes are ever interpolated into markup or a handler.
function copyFrom(btn) {
  const src = btn.previousElementSibling;
  if (!src) return;
  const text = src.textContent;
  const flash = () => {
    btn.classList.add('copied');
    const original = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.textContent = original;
    }, 1400);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(flash, () => fallbackCopy(text, flash));
  } else {
    fallbackCopy(text, flash);
  }
}

// Clipboard fallback for reports opened from disk (file://, no secure context).
function fallbackCopy(text, onDone) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand('copy');
    onDone();
  } catch (err) {
    /* clipboard genuinely unavailable; leave the value on screen to copy by hand */
  }
  document.body.removeChild(ta);
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  
  // Update theme button active states
  const buttons = document.querySelectorAll('.theme-btn');
  buttons.forEach(btn => {
    if (btn.innerText.toLowerCase() === theme.toLowerCase()) {
      btn.classList.add('active');
      btn.setAttribute('aria-pressed', 'true');
    } else {
      btn.classList.remove('active');
      btn.setAttribute('aria-pressed', 'false');
    }
  });
}

function setStatusTab(status) {
  activeStatusTab = status;
  
  // Update active tab styling
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(tab => {
    if (tab.id === `tab-${status}`) {
      tab.classList.add('active');
      tab.setAttribute('aria-selected', 'true');
    } else {
      tab.classList.remove('active');
      tab.setAttribute('aria-selected', 'false');
    }
  });
  
  applyFilters();
}

// Credential reveal controls removed (D-UX-2): the HTML report only ever embeds
// the REDACTED value. Reports get emailed, committed, and screenshotted, so they
// must never carry plaintext secrets. The old control promised plaintext while
// only switching between identical redacted values. Removed rather than made to
// leak.

function toggleDetails(idx) {
  const detailsRow = document.getElementById(`details-row-${idx}`);
  const summaryRow = document.getElementById(`finding-row-${idx}`);
  if (detailsRow.classList.contains('active')) {
    detailsRow.classList.remove('active');
    detailsRow.setAttribute('aria-hidden', 'true');
    if (summaryRow) summaryRow.setAttribute('aria-expanded', 'false');
  } else {
    // Close other expanded rows first for clean layout
    document.querySelectorAll('.details-row').forEach(row => {
      row.classList.remove('active');
      row.setAttribute('aria-hidden', 'true');
    });
    document.querySelectorAll('.finding-row').forEach(row => row.setAttribute('aria-expanded', 'false'));
    detailsRow.classList.add('active');
    detailsRow.setAttribute('aria-hidden', 'false');
    if (summaryRow) summaryRow.setAttribute('aria-expanded', 'true');
  }
}

function toggleDetailsFromKeyboard(event, idx) {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    toggleDetails(idx);
  }
}

// The search box fires on every keystroke; each run rebuilds the whole table,
// so coalesce rapid typing into one render. Checkboxes/tabs call applyFilters
// directly (a single discrete event needs no debounce — it stays instant).
let filterDebounceTimer = null;
function applyFiltersDebounced() {
  if (filterDebounceTimer) clearTimeout(filterDebounceTimer);
  filterDebounceTimer = setTimeout(applyFilters, 110);
}

function applyFilters() {
  const searchQuery = document.getElementById('search-box').value.toLowerCase().trim();
  
  // Get active severity checkboxes
  const sevs = {
    'critical': document.getElementById('fil-critical').checked,
    'high': document.getElementById('fil-high').checked,
    'medium': document.getElementById('fil-medium').checked,
    'low': document.getElementById('fil-low').checked,
    'info': document.getElementById('fil-info').checked,
    'client-safe': document.getElementById('fil-client-safe').checked,
  };

  const filtered = rawFindings.filter(f => {
    // Severity check
    const sevKey = f.severity.toLowerCase();
    if (sevs[sevKey] === false) return false;

    // Status Tab check
    const status = f.verification.toLowerCase();
    if (activeStatusTab === 'live' && !status.startsWith('live')) return false;
    if (activeStatusTab === 'revoked' && !status.startsWith('revoked')) return false;
    if (activeStatusTab === 'unverifiable' && !verificationIsUnattempted(status)) return false;

    // Text search check
    if (searchQuery) {
      const filePath = (f.location.file_path || '').toLowerCase();
      const detId = (f.detector_id || '').toLowerCase();
      const detName = (f.detector_name || '').toLowerCase();
      const service = (f.service || '').toLowerCase();
      const matchText = `${filePath} ${detId} ${detName} ${service}`;
      if (!matchText.includes(searchQuery)) return false;
    }

    return true;
  });

  renderTable(filtered, false);
  renderMetrics(filtered, false);
}

// Lead with the worst: severity descending, then live credentials first within
// a severity (a confirmed-live Critical is the single most urgent line in the
// report). Pure presentation order — does not touch counts or filtering.
const SEVERITY_RANK = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'client-safe': 5 };
function findingOrderKey(f) {
  const sev = SEVERITY_RANK[(f.severity || '').toLowerCase()];
  const sevRank = sev === undefined ? 9 : sev;
  const liveRank = (f.verification || '').toLowerCase().startsWith('live') ? 0 : 1;
  return sevRank * 2 + liveRank;
}

// Column sort. Default = severity (worst first). Header click (wired in
// DOMContentLoaded) re-sorts; the <th> markup stays static, so the structural
// test is unaffected and sorting is pure progressive enhancement.
const COLUMN_SORTERS = {
  detector: f => (f.detector_name || '').toLowerCase(),
  service: f => (f.service || '').toLowerCase(),
  path: f => `${(f.location.file_path || '').toLowerCase()}:${String(f.location.line || 0).padStart(9, '0')}`,
  severity: f => findingOrderKey(f),
  verification: f => (f.verification || '').toLowerCase(),
};
const COLUMN_KEYS = ['detector', 'service', 'path', 'severity', 'verification'];
let sortState = { key: 'severity', dir: 1 }; // severity ascending == worst first

function setSort(key) {
  if (sortState.key === key) {
    sortState.dir = -sortState.dir;
  } else {
    sortState.key = key;
    sortState.dir = 1;
  }
  updateSortIndicators();
  applyFilters();
}

function updateSortIndicators() {
  document.querySelectorAll('thead th').forEach((th, i) => {
    const existing = th.querySelector('.sort-ind');
    if (existing) existing.remove();
    if (COLUMN_KEYS[i] === sortState.key) {
      const ind = document.createElement('span');
      ind.className = 'sort-ind';
      ind.textContent = sortState.dir === 1 ? '↑' : '↓';
      th.appendChild(ind);
      th.setAttribute('aria-sort', sortState.dir === 1 ? 'ascending' : 'descending');
    } else {
      th.removeAttribute('aria-sort');
    }
  });
}

function wireSortableHeaders() {
  document.querySelectorAll('thead th').forEach((th, i) => {
    const key = COLUMN_KEYS[i];
    if (!key) return;
    th.classList.add('sortable');
    th.setAttribute('role', 'button');
    th.tabIndex = 0;
    th.addEventListener('click', () => setSort(key));
    th.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSort(key); }
    });
  });
  updateSortIndicators();
}

// One-glance risk verdict, computed from the FULL scan (not the filtered view).
function renderRiskHero(allFindings) {
  const hero = document.getElementById('risk-hero');
  const verdict = document.getElementById('risk-verdict');
  const sub = document.getElementById('risk-sub');
  if (!hero || !verdict || !sub) return;
  const total = allFindings.length;
  const live = allFindings.filter(f => (f.verification || '').toLowerCase().startsWith('live')).length;
  const critical = allFindings.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
  const notChecked = allFindings.filter(f => verificationIsUnattempted(f.verification)).length;
  let label, state;
  if (total === 0) { label = 'No secrets detected'; state = 'ok'; }
  else if (live > 0) { label = `${live} live secret${live === 1 ? '' : 's'} exposed`; state = 'danger'; }
  else if (critical > 0) { label = `${critical} critical finding${critical === 1 ? '' : 's'}`; state = 'danger'; }
  else if (notChecked === total) { label = `${total} finding${total === 1 ? '' : 's'} · liveness not checked`; state = 'warn'; }
  else { label = `${total} finding${total === 1 ? '' : 's'} detected`; state = ''; }
  verdict.textContent = label;
  verdict.className = 'risk-hero-verdict' + (state ? ' ' + state : '');
  hero.className = 'risk-hero' + (state ? ' ' + state : '');
  // Always surface "not checked" so unverified exposure is never read as safe.
  const parts = [`${total} total`, `${live} live`];
  if (notChecked > 0) parts.push(`${notChecked} not checked`);
  parts.push(`${critical} critical`);
  sub.textContent = parts.join(' · ');
}

// Human-readable verification label. Critically distinguishes "we tried and it
// is dead/revoked" from "we did NOT attempt verification" (skipped /
// unverifiable), so an unverified secret is never silently read as a safe one.
function verificationLabel(raw) {
  const k = (raw || '').toLowerCase();
  if (k.startsWith('live')) return 'Live · active';
  if (k.startsWith('revoked')) return 'Revoked';
  if (k.startsWith('dead')) return 'Dead';
  if (k.startsWith('rate_limited')) return 'Rate-limited';
  if (k.startsWith('error')) return 'Verify failed';
  if (k.startsWith('unverifiable')) return 'Not checked · no verifier';
  if (k.startsWith('skipped')) return 'Not checked · skipped';
  return raw;
}
function verificationIsUnattempted(raw) {
  const k = (raw || '').toLowerCase();
  return k.startsWith('skipped') || k.startsWith('unverifiable');
}

const SEVERITY_BADGE_CLASSES = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
  'client-safe': 'badge-client-safe',
};
function severityBadgeClass(raw) {
  return SEVERITY_BADGE_CLASSES[(raw || '').toLowerCase()] || 'badge-info';
}

const SERVICE_BAR_COLORS = [
  'var(--color-critical)',
  'var(--color-high)',
  'var(--color-medium)',
  'var(--color-client-safe)',
  'var(--color-live)',
];
function serviceBarColor(rank) {
  return SERVICE_BAR_COLORS[rank % SERVICE_BAR_COLORS.length];
}

function verificationDotClass(raw) {
  const statusKey = (raw || '').toLowerCase();
  if (statusKey.startsWith('live')) return 'dot-live';
  if (statusKey.startsWith('revoked')) return 'dot-revoked';
  if (statusKey.startsWith('dead')) return 'dot-dead';
  if (statusKey.startsWith('rate_limited')) return 'dot-rate-limited';
  if (statusKey.startsWith('error')) return 'dot-error';
  if (statusKey.startsWith('unverifiable')) return 'dot-unverifiable';
  return 'dot-skipped';
}

function renderTable(findings, isInitial) {
  const tbody = document.getElementById('findings-table-body');
  const emptyView = document.getElementById('empty-view');
  const resultCount = document.getElementById('result-count');

  // Sort a copy so the caller's array (and rawFindings) is never mutated.
  // Decorate-sort-undecorate: compute each row's sort key ONCE (n builds)
  // instead of recomputing it inside the O(n log n) comparator (~2·n·log n
  // builds). The path column's key is a freshly-built string, so on a large
  // report that redundant work is the gap between a snappy and a janky column
  // sort. The index tiebreak keeps the order stable.
  const sorter = COLUMN_SORTERS[sortState.key] || COLUMN_SORTERS.severity;
  const dir = sortState.dir;
  const ordered = findings
    .map((f, i) => ({ f, k: sorter(f), i }))
    .sort((a, b) => (a.k < b.k ? -dir : a.k > b.k ? dir : a.i - b.i))
    .map((d) => d.f);

  tbody.innerHTML = '';
  if (resultCount) {
    const total = rawFindings.length;
    const count = findings.length;
    resultCount.innerText = `Showing ${count} of ${total} findings.`;
  }
  
  if (findings.length === 0) {
    emptyView.style.display = 'block';
    return;
  }
  
  emptyView.style.display = 'none';

  ordered.forEach((finding, idx) => {
    const tr = document.createElement('tr');
    tr.id = `finding-row-${idx}`;
    tr.className = 'finding-row';
    // Stagger the entrance only on the first render; capped so a huge result
    // set doesn't trail a multi-second cascade. Filtering re-renders without
    // the class, so search stays instant.
    if (isInitial) {
      tr.classList.add('finding-row--enter');
      tr.style.setProperty('--kh-i', Math.min(idx, 22));
    }
    tr.tabIndex = 0;
    tr.setAttribute('role', 'button');
    tr.setAttribute('aria-expanded', 'false');
    tr.setAttribute('aria-controls', `details-row-${idx}`);
    tr.setAttribute('aria-label', `Show details for ${finding.detector_name} in ${finding.location.file_path || 'unknown file'}`);
    tr.onclick = () => toggleDetails(idx);
    tr.onkeydown = event => toggleDetailsFromKeyboard(event, idx);

    const line = finding.location.line ? `:${finding.location.line}` : '';
    // Split the path so the filename — what the eye scans for — is emphasised
    // while the directory recedes and the line number reads as an accent. Both
    // segments are escaped independently; no scan-derived bytes skip escaping.
    const rawPath = finding.location.file_path || '';
    const sepIdx = Math.max(rawPath.lastIndexOf('/'), rawPath.lastIndexOf('\\'));
    const dirPart = sepIdx >= 0 ? rawPath.slice(0, sepIdx + 1) : '';
    const basePart = sepIdx >= 0 ? rawPath.slice(sepIdx + 1) : rawPath;
    // Filename first (bold, never split) with the line as an accent; the
    // directory follows on a dimmed second line that left-truncates to its
    // meaningful tail (…/parent/) with the full path on hover — so a column of
    // long absolute paths stays compact and scannable instead of wrapping into
    // tall mid-word blocks.
    const lineHtml = line ? `<span class="kh-path-line">${escapeHtml(line)}</span>` : '';
    const fullTitle = escapeHtml(rawPath + line);
    // Collapse a long absolute directory to its last two segments (…/parent/child/)
    // so the row stays one tidy line; the full path is on hover (title).
    let dirDisplay = dirPart;
    const segs = dirPart.split(/[/\\]/).filter(Boolean);
    if (segs.length > 2 && dirPart.length > 42) {
      dirDisplay = '…/' + segs.slice(-2).join('/') + '/';
    }
    const shortPath = rawPath
      ? `<span class="kh-path-file" title="${fullTitle}">${escapeHtml(basePart)}${lineHtml}</span>`
        + (dirPart ? `<span class="kh-path-dir" title="${fullTitle}">${escapeHtml(dirDisplay)}</span>` : '')
      : '<span class="kh-path-file">&lt;unknown&gt;</span>';

    // Status visual elements use closed class maps. Text remains the escaped
    // original value, but no scan-derived bytes can enter a class attribute.
    const severityClass = severityBadgeClass(finding.severity);
    let statusClass = verificationDotClass(finding.verification);

    // Format verification status as a clear, human-readable label, then split
    // the "primary · qualifier" form so it can render as a compact two-line
    // stack (primary verdict / dim qualifier) instead of wrapping mid-phrase.
    const statusText = verificationLabel(finding.verification);
    const statusParts = statusText.split(' · ');
    const statusPrimary = statusParts[0];
    const statusQual = statusParts.length > 1 ? statusParts.slice(1).join(' · ') : '';
    const unattempted = verificationIsUnattempted(finding.verification);
    if (unattempted) statusClass += ' dot-unattempted';
    const statusTitle = unattempted
      ? 'Verification was NOT attempted — treat this secret as potentially live'
      : 'Verification result';

    tr.innerHTML = `
      <td><strong>${escapeHtml(finding.detector_name)}</strong><br><small style="color: var(--text-muted); font-size:10px;">${escapeHtml(finding.detector_id)}</small></td>
      <td><span class="kh-service" title="${escapeHtml(finding.service)}">${escapeHtml(finding.service)}</span></td>
      <td><span class="kh-path">${shortPath}</span></td>
      <td><span class="badge ${severityClass}">${escapeHtml(finding.severity)}</span></td>
      <td>
        <span class="status-badge${unattempted ? ' status-badge--unattempted' : ''}" title="${escapeHtml(statusText)}">
          <span class="status-dot ${statusClass}"></span>
          <span class="status-text">
            <span class="status-primary">${escapeHtml(statusPrimary)}</span>
            ${statusQual ? `<span class="status-qual">${escapeHtml(statusQual)}</span>` : ''}
          </span>
        </span>
      </td>
    `;

    tbody.appendChild(tr);

    // Expand details row
    const detailsTr = document.createElement('tr');
    detailsTr.id = `details-row-${idx}`;
    detailsTr.className = 'details-row';
    detailsTr.setAttribute('aria-hidden', 'true');

    const commitStr = finding.location.commit ? escapeHtml(finding.location.commit) : 'none';
    const authorStr = finding.location.author ? escapeHtml(finding.location.author) : 'none';
    const dateStr = finding.location.date ? escapeHtml(finding.location.date) : 'none';
    const confidenceStr = (finding.confidence != null && Number.isFinite(finding.confidence))
      ? `${Math.round(finding.confidence * 100)}%` : 'none';

    // Format companion strings
    let metadataItems = '';
    for (const [k, v] of Object.entries(finding.metadata || {})) {
      metadataItems += `<div class="details-item"><span class="details-lbl">${escapeHtml(k)}:</span><span class="details-val">${escapeHtml(v)}</span></div>`;
    }
    if (!metadataItems) metadataItems = '<div style="color: var(--text-muted); font-size:12px;">No provider metadata.</div>';

    // The report only ever holds the REDACTED credential (never plaintext), so
    // there is nothing to unmask — render the redacted value as static text.
    const credRedacted = escapeHtml(finding.credential_redacted);

    detailsTr.innerHTML = `
      <td colspan="5">
        <div class="details-container" onclick="event.stopPropagation();">
          <div class="details-block">
            <h3>Finding Details</h3>
            <div class="details-list">
              <div class="details-item">
                <span class="details-lbl">Credential:</span>
                <span class="cred-box">
                  <span id="cred-text-${idx}">${credRedacted}</span>
                </span>
              </div>
              <div class="details-item"><span class="details-lbl">Credential Hash:</span><span class="details-val">${escapeHtml(finding.credential_hash)}</span><button class="copy-btn" type="button" onclick="copyFrom(this)" aria-label="Copy credential hash to clipboard">Copy</button></div>
              <div class="details-item"><span class="details-lbl">Verification:</span><span class="details-val">${escapeHtml(verificationLabel(finding.verification))}${verificationIsUnattempted(finding.verification) ? ' <span class="verify-note">— not attempted; treat as potentially live</span>' : ''}</span></div>
              <div class="details-item"><span class="details-lbl">Confidence:</span><span class="details-val">${confidenceStr}</span></div>
            </div>
          </div>
          <div class="details-block">
            <h3>Location & Metadata</h3>
            <div class="details-list">
              <div class="details-item"><span class="details-lbl">Source Type:</span><span class="details-val">${escapeHtml(finding.location.source)}</span></div>
              <div class="details-item"><span class="details-lbl">File Offset:</span><span class="details-val">${escapeHtml(finding.location.offset)} bytes</span></div>
              <div class="details-item"><span class="details-lbl">Commit ID:</span><span class="details-val">${commitStr}</span></div>
              <div class="details-item"><span class="details-lbl">Author:</span><span class="details-val">${authorStr}</span></div>
              <div class="details-item"><span class="details-lbl">Date:</span><span class="details-val">${dateStr}</span></div>
            </div>
          </div>
          <div class="details-block" style="grid-column: span 2; margin-top: 10px;">
            <h3>Provider Response Metadata</h3>
            <div class="details-list">
              ${metadataItems}
            </div>
          </div>
        </div>
      </td>
    `;
    
    tbody.appendChild(detailsTr);
  });
}

function renderMetrics(findings, isInitial) {
  // Single pass instead of eight full .filter() scans of the finding set.
  const total = findings.length;
  let live = 0, notChecked = 0;
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, 'client-safe': 0 };
  findings.forEach(f => {
    const v = (f.verification || '').toLowerCase();
    if (v.startsWith('live')) live++;
    if (verificationIsUnattempted(f.verification)) notChecked++;
    const s = (f.severity || '').toLowerCase();
    if (s in sevCounts) sevCounts[s]++;
  });
  const { critical, high, medium, low, info } = sevCounts;
  const clientSafe = sevCounts['client-safe'];

  // Count up on the initial render (the "settle" moment); set directly when
  // re-rendering from a filter so the numbers track typing without jitter.
  setStat('cnt-total', total, isInitial);
  setStat('cnt-live', live, isInitial);
  setStat('cnt-not-checked', notChecked, isInitial);
  setStat('cnt-critical', critical, isInitial);
  setStat('cnt-high', high, isInitial);
  const liveEl = document.getElementById('cnt-live');
  if (liveEl) liveEl.classList.toggle('has-live', live > 0);

  // Render Severity Donut Chart Segments
  const segments = [
    { el: 'seg-critical', val: critical, label: 'Critical', cssVar: '--color-critical' },
    { el: 'seg-high', val: high, label: 'High', cssVar: '--color-high' },
    { el: 'seg-medium', val: medium, label: 'Medium', cssVar: '--color-medium' },
    { el: 'seg-low', val: low, label: 'Low', cssVar: '--color-low' },
    { el: 'seg-info', val: info, label: 'Info', cssVar: '--color-info' },
    { el: 'seg-client', val: clientSafe, label: 'Client-safe', cssVar: '--color-client-safe' }
  ];

  let cumulative = 0;
  segments.forEach(seg => {
    const circle = document.getElementById(seg.el);
    if (!circle) return;
    if (total === 0 || seg.val === 0) {
      circle.style.strokeDasharray = '0 100';
      circle.style.strokeDashoffset = '0';
      return;
    }

    const pct = (seg.val / total) * 100;
    // Donut SVG circumference is 2 * pi * r = 2 * 3.14159 * 15.91549 = 100. Leave
    // a hairline gap between arcs so adjacent severities stay visually separate.
    const gap = segments.filter(s => s.val > 0).length > 1 ? 0.8 : 0;
    circle.style.strokeDasharray = `${Math.max(pct - gap, 0.4)} ${100 - Math.max(pct - gap, 0.4)}`;
    circle.style.strokeDashoffset = `${cumulative}`;
    cumulative -= pct; // subtract to move clockwise
  });

  // Center readout: the total, counted up.
  const totalEl = document.getElementById('chart-total');
  if (totalEl) {
    if (isInitial) animateCount(totalEl, total);
    else totalEl.textContent = total;
  }

  // Colour-keyed legend (non-zero severities only) so the breakdown is legible
  // even when a single severity dominates the ring.
  const legend = document.getElementById('severity-legend');
  if (legend) {
    legend.innerHTML = '';
    segments.filter(s => s.val > 0).forEach(s => {
      const item = document.createElement('span');
      item.className = 'legend-item';
      item.innerHTML =
        `<span class="legend-swatch" style="background:var(${s.cssVar})"></span>` +
        `${s.label} <span class="legend-count">${s.val}</span>`;
      legend.appendChild(item);
    });
  }

  // Render Top Services Bars
  const services = {};
  findings.forEach(f => {
    services[f.service] = (services[f.service] || 0) + 1;
  });

  const sortedServices = Object.entries(services)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const serviceContainer = document.getElementById('service-bars');
  serviceContainer.innerHTML = '';
  
  if (sortedServices.length === 0) {
    serviceContainer.innerHTML = '<div style="color: var(--text-muted); font-size:12px; text-align:center;">No services reported.</div>';
    return;
  }

  const maxVal = sortedServices[0][1];

  sortedServices.forEach(([name, count], rank) => {
    const pct = (count / maxVal) * 100;
    const item = document.createElement('div');
    item.className = 'chart-bar-item';
    item.style.setProperty('--service-bar-color', serviceBarColor(rank));
    item.innerHTML = `
      <div class="chart-bar-label">
        <span><strong>${escapeHtml(name)}</strong></span>
        <span>${count}</span>
      </div>
      <div class="chart-bar-track">
        <div class="chart-bar-fill" style="width: ${pct}%;"></div>
      </div>
    `;
    serviceContainer.appendChild(item);
  });
}

// Initial setup
// Render the scan-coverage panel: an honest account of what was NOT fully
// scanned. Absence of a panel must never be read as "fully clean", so the panel
// is shown either way — listing the gaps, or stating none were recorded.
function renderCoverageGaps() {
  const panel = document.getElementById('coverage-panel');
  const note = document.getElementById('coverage-note');
  const list = document.getElementById('coverage-list');
  const dot = document.getElementById('coverage-dot');
  if (!panel || !note || !list) return;
  const gaps = (typeof coverageGaps !== 'undefined' && Array.isArray(coverageGaps))
    ? coverageGaps.filter(g => g && g.count > 0)
    : [];
  panel.style.display = '';
  list.innerHTML = '';
  if (gaps.length === 0) {
    panel.classList.add('coverage-clean');
    if (dot) dot.classList.add('coverage-dot--clean');
    note.textContent = 'No coverage gaps recorded — every reachable file was scanned.';
    return;
  }
  panel.classList.add('coverage-gapped');
  if (dot) dot.classList.add('coverage-dot--gapped');
  const totalAffected = gaps.reduce((n, g) => n + g.count, 0);
  note.textContent =
    `${totalAffected} item(s) across ${gaps.length} categor${gaps.length === 1 ? 'y' : 'ies'} were NOT fully scanned — ` +
    `findings below are not a complete picture of this target.`;
  gaps.sort((a, b) => b.count - a.count).forEach(g => {
    const li = document.createElement('li');
    li.className = 'coverage-item';
    li.innerHTML = `<span class="coverage-count">${g.count}</span> <span class="coverage-reason"></span>`;
    li.querySelector('.coverage-reason').textContent = g.reason;
    list.appendChild(li);
  });
}

window.addEventListener('DOMContentLoaded', () => {
  renderRiskHero(rawFindings);
  renderScanMetadata();
  wireSortableHeaders();
  renderTable(rawFindings, true);
  renderMetrics(rawFindings, true);
  renderCoverageGaps();
});

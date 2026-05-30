// Master scripting file for the KeyHog interactive report. Zero external dependencies.

let activeStatusTab = 'all';

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  
  // Update theme button active states
  const buttons = document.querySelectorAll('.theme-btn');
  buttons.forEach(btn => {
    if (btn.innerText.toLowerCase() === theme.toLowerCase()) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
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
    } else {
      tab.classList.remove('active');
    }
  });
  
  applyFilters();
}

function toggleMask(idx, btn) {
  const span = document.getElementById(`cred-text-${idx}`);
  const isMasked = span.getAttribute('data-masked') === 'true';
  
  if (isMasked) {
    span.innerText = span.getAttribute('data-plaintext');
    span.setAttribute('data-masked', 'false');
    btn.innerHTML = '👁️';
    btn.setAttribute('title', 'Mask secret');
  } else {
    span.innerText = span.getAttribute('data-redacted');
    span.setAttribute('data-masked', 'true');
    btn.innerHTML = '🕶️';
    btn.setAttribute('title', 'Show secret');
  }
}

function toggleDetails(idx) {
  const detailsRow = document.getElementById(`details-row-${idx}`);
  if (detailsRow.classList.contains('active')) {
    detailsRow.classList.remove('active');
  } else {
    // Close other expanded rows first for clean layout
    document.querySelectorAll('.details-row').forEach(row => row.classList.remove('active'));
    detailsRow.classList.add('active');
  }
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
    if (activeStatusTab === 'unverifiable' && !status.startsWith('unverifiable')) return false;

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

  renderTable(filtered);
  renderMetrics(filtered);
}

function renderTable(findings) {
  const tbody = document.getElementById('findings-table-body');
  const emptyView = document.getElementById('empty-view');
  
  tbody.innerHTML = '';
  
  if (findings.len === 0 || findings.length === 0) {
    emptyView.style.display = 'block';
    return;
  }
  
  emptyView.style.display = 'none';

  findings.forEach((finding, idx) => {
    const tr = document.createElement('tr');
    tr.onclick = () => toggleDetails(idx);

    const line = finding.location.line ? `:${finding.location.line}` : '';
    const filePath = finding.location.file_path || '&lt;unknown&gt;';
    const shortPath = `${filePath}${line}`;

    const sevKey = finding.severity.toLowerCase();
    const statusKey = finding.verification.toLowerCase();
    
    // Status visual elements
    let statusClass = 'dot-skipped';
    if (statusKey.startsWith('live')) statusClass = 'dot-live';
    else if (statusKey.startsWith('revoked')) statusClass = 'dot-revoked';
    else if (statusKey.startsWith('dead')) statusClass = 'dot-dead';
    else if (statusKey.startsWith('rate_limited')) statusClass = 'dot-rate-limited';
    else if (statusKey.startsWith('error')) statusClass = 'dot-error';
    else if (statusKey.startsWith('unverifiable')) statusClass = 'dot-unverifiable';

    // Format verification status readable name
    let statusText = finding.verification;
    if (statusText.length > 25) {
      statusText = statusText.substring(0, 22) + '...';
    }

    tr.innerHTML = `
      <td><strong>${finding.detector_name}</strong><br><small style="color: var(--text-muted); font-size:10px;">${finding.detector_id}</small></td>
      <td><span style="font-family:monospace; font-size:12px;">${finding.service}</span></td>
      <td><span style="font-family:monospace;">${shortPath}</span></td>
      <td><span class="badge badge-${sevKey}">${finding.severity}</span></td>
      <td>
        <span class="status-badge">
          <span class="status-dot ${statusClass}"></span>
          <span style="font-size:11px;">${statusText}</span>
        </span>
      </td>
    `;

    tbody.appendChild(tr);

    // Expand details row
    const detailsTr = document.createElement('tr');
    detailsTr.id = `details-row-${idx}`;
    detailsTr.className = 'details-row';

    const commitStr = finding.location.commit || 'none';
    const authorStr = finding.location.author || 'none';
    const dateStr = finding.location.date || 'none';
    const confidenceStr = finding.confidence ? `${Math.round(finding.confidence * 100)}%` : 'none';

    // Format companion strings
    let metadataItems = '';
    for (const [k, v] of Object.entries(finding.metadata || {})) {
      metadataItems += `<div class="details-item"><span class="details-lbl">${k}:</span><span class="details-val">${v}</span></div>`;
    }
    if (!metadataItems) metadataItems = '<div style="color: var(--text-muted); font-size:12px;">No provider metadata.</div>';

    // Redacted vs Plaintext logic
    const isUnmaskable = finding.credential_redacted.includes('...');
    let unmaskBtnHtml = '';
    if (isUnmaskable) {
      unmaskBtnHtml = `
        <button class="unmask-btn" onclick="event.stopPropagation(); toggleMask(${idx}, this)" title="Show secret">🕶️</button>
      `;
    }

    detailsTr.innerHTML = `
      <td colspan="5">
        <div class="details-container" onclick="event.stopPropagation();">
          <div class="details-block">
            <h3>Finding Details</h3>
            <div class="details-list">
              <div class="details-item">
                <span class="details-lbl">Credential:</span>
                <span class="cred-box">
                  <span id="cred-text-${idx}" data-masked="true" data-redacted="${finding.credential_redacted}" data-plaintext="${finding.credential_redacted}">${finding.credential_redacted}</span>
                  ${unmaskBtnHtml}
                </span>
              </div>
              <div class="details-item"><span class="details-lbl">Credential Hash:</span><span class="details-val">${finding.credential_hash}</span></div>
              <div class="details-item"><span class="details-lbl">Verification Result:</span><span class="details-val">${finding.verification}</span></div>
              <div class="details-item"><span class="details-lbl">Confidence:</span><span class="details-val">${confidenceStr}</span></div>
            </div>
          </div>
          <div class="details-block">
            <h3>Location & Metadata</h3>
            <div class="details-list">
              <div class="details-item"><span class="details-lbl">Source Type:</span><span class="details-val">${finding.location.source}</span></div>
              <div class="details-item"><span class="details-lbl">File Offset:</span><span class="details-val">${finding.location.offset} bytes</span></div>
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

function renderMetrics(findings) {
  const total = findings.length;
  const live = findings.filter(f => f.verification.toLowerCase().startsWith('live')).length;
  const critical = findings.filter(f => f.severity.toLowerCase() === 'critical').length;
  const high = findings.filter(f => f.severity.toLowerCase() === 'high').length;
  const medium = findings.filter(f => f.severity.toLowerCase() === 'medium').length;
  const low = findings.filter(f => f.severity.toLowerCase() === 'low').length;
  const info = findings.filter(f => f.severity.toLowerCase() === 'info').length;
  const clientSafe = findings.filter(f => f.severity.toLowerCase() === 'client-safe').length;

  document.getElementById('cnt-total').innerText = total;
  document.getElementById('cnt-live').innerText = live;
  document.getElementById('cnt-critical').innerText = critical;
  document.getElementById('cnt-high').innerText = high;

  // Render Severity Donut Chart Segments
  const segments = [
    { el: 'seg-critical', val: critical },
    { el: 'seg-high', val: high },
    { el: 'seg-medium', val: medium },
    { el: 'seg-low', val: low },
    { el: 'seg-info', val: info },
    { el: 'seg-client', val: clientSafe }
  ];

  let cumulative = 0;
  segments.forEach(seg => {
    const circle = document.getElementById(seg.el);
    if (total === 0 || seg.val === 0) {
      circle.style.strokeDasharray = '0 100';
      circle.style.strokeDashoffset = '0';
      return;
    }
    
    const pct = (seg.val / total) * 100;
    // Donut SVG circumference is 2 * pi * r = 2 * 3.14159 * 15.91549 = 100
    circle.style.strokeDasharray = `${pct} ${100 - pct}`;
    circle.style.strokeDashoffset = `${cumulative}`;
    cumulative -= pct; // subtract to move clockwise
  });

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

  sortedServices.forEach(([name, count]) => {
    const pct = (count / maxVal) * 100;
    const item = document.createElement('div');
    item.className = 'chart-bar-item';
    item.innerHTML = `
      <div class="chart-bar-label">
        <span><strong>${name}</strong></span>
        <span>${count}</span>
      </div>
      <div class="chart-bar-track">
        <div class="chart-bar-fill" style="width: ${pct}%; background-color: var(--accent-primary);"></div>
      </div>
    `;
    serviceContainer.appendChild(item);
  });
}

// Initial setup
window.addEventListener('DOMContentLoaded', () => {
  renderTable(rawFindings);
  renderMetrics(rawFindings);
});

// Loads detectors.json and populates the catalog table on detectors.html.
// Wires up the search + severity filter against the populated rows.

(async function () {
  const tbody = document.getElementById('cat-tbody');
  if (!tbody) return;

  let data;
  try {
    const res = await fetch('data/detectors.json', { cache: 'force-cache' });
    data = await res.json();
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="4" class="muted">Failed to load detectors.json — view source: <a href="https://github.com/santhsecurity/keyhog/tree/main/detectors">detectors/</a></td></tr>';
    return;
  }

  const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0, '': -1 };
  data.sort((a, b) => (sevRank[b.severity] - sevRank[a.severity]) || a.id.localeCompare(b.id));

  const frag = document.createDocumentFragment();
  for (const d of data) {
    const tr = document.createElement('tr');
    const kw = (d.keywords || []).slice(0, 4).join(' · ');
    const sev = d.severity || 'info';
    const sevClass = sev === 'critical' ? 'crit' : sev === 'medium' ? 'med' : sev;
    tr.dataset.search = (d.id + ' ' + d.service + ' ' + (d.keywords || []).join(' ')).toLowerCase();
    tr.dataset.severity = sev;
    tr.innerHTML =
      '<td>' + escapeHtml(d.id) + '</td>' +
      '<td><code>' + escapeHtml(d.service || '—') + '</code></td>' +
      '<td><span class="pill ' + sevClass + '">' + escapeHtml(sev) + '</span></td>' +
      '<td>' + escapeHtml(kw || '—') + '</td>';
    frag.appendChild(tr);
  }
  tbody.innerHTML = '';
  tbody.appendChild(frag);

  // Wire the filter against the freshly-inserted rows. (nav.js runs once at
  // load and captures the placeholder row only; we re-wire here after the
  // real rows exist.)
  const filter = document.getElementById('cat-filter');
  const sevSel = document.getElementById('cat-severity');
  const count = document.getElementById('cat-count');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  const total = rows.length;

  function apply() {
    const q = (filter && filter.value || '').trim().toLowerCase();
    const s = sevSel ? sevSel.value : '';
    let shown = 0;
    for (const r of rows) {
      const matchesQ = !q || r.dataset.search.includes(q);
      const matchesS = !s || r.dataset.severity === s;
      const visible = matchesQ && matchesS;
      r.style.display = visible ? '' : 'none';
      if (visible) shown++;
    }
    if (count) count.textContent = shown + ' / ' + total + ' detectors';
  }

  if (filter) filter.addEventListener('input', apply);
  if (sevSel) sevSel.addEventListener('change', apply);
  apply();
})();

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// keyhog docs — sidebar active state, copy buttons, catalog filter.

(function () {
  // Highlight the active page in the sidebar.
  const path = location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('aside.sidebar a').forEach(a => {
    const href = (a.getAttribute('href') || '').split('/').pop();
    if (href === path) a.classList.add('active');
  });

  // Build a simple right-side TOC from <h2> elements on long pages.
  const article = document.querySelector('main.content > article');
  if (article && article.dataset.toc !== 'off') {
    const hs = article.querySelectorAll('h2');
    if (hs.length >= 3) {
      const nav = document.createElement('nav');
      nav.className = 'toc';
      const items = [];
      hs.forEach(h => {
        if (!h.id) h.id = h.textContent.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
        items.push(`<li><a href="#${h.id}">${h.textContent}</a></li>`);
      });
      nav.innerHTML = `<h5>On this page</h5><ol>${items.join('')}</ol>`;
      document.body.appendChild(nav);

      const links = nav.querySelectorAll('a');
      const io = new IntersectionObserver(entries => {
        entries.forEach(e => {
          if (e.isIntersecting) {
            links.forEach(l => l.classList.toggle('active', l.getAttribute('href') === '#' + e.target.id));
          }
        });
      }, { rootMargin: '-80px 0px -70% 0px' });
      hs.forEach(h => io.observe(h));
    }
  }

  // Copy button on every <pre>.
  document.querySelectorAll('pre').forEach(pre => {
    if (pre.dataset.nocopy === 'true') return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy-btn';
    btn.setAttribute('aria-label', 'Copy code');
    btn.textContent = 'copy';
    pre.style.position = 'relative';
    btn.style.cssText = 'position:absolute;top:8px;right:8px;background:rgba(255,255,255,0.06);' +
      'border:1px solid #2a2a2a;color:#9ca3af;padding:3px 8px;border-radius:4px;' +
      'font-size:11px;font-family:inherit;cursor:pointer;opacity:0;transition:opacity 120ms ease;';
    pre.appendChild(btn);
    pre.addEventListener('mouseenter', () => btn.style.opacity = '1');
    pre.addEventListener('mouseleave', () => btn.style.opacity = '0');
    btn.addEventListener('click', async () => {
      const code = pre.querySelector('code') || pre;
      const text = code.innerText.replace(/^\s*\$\s/gm, '');
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = 'copied';
        btn.style.color = '#f5c518';
        setTimeout(() => { btn.textContent = 'copy'; btn.style.color = '#9ca3af'; }, 1100);
      } catch {
        btn.textContent = 'fail';
        setTimeout(() => { btn.textContent = 'copy'; }, 1100);
      }
    });
  });

  // Detector catalog filter (used on detectors.html).
  const filter = document.getElementById('cat-filter');
  const sev = document.getElementById('cat-severity');
  const count = document.getElementById('cat-count');
  const tbody = document.getElementById('cat-tbody');
  if (filter && tbody) {
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const total = rows.length;
    const apply = () => {
      const q = filter.value.trim().toLowerCase();
      const s = sev ? sev.value : '';
      let shown = 0;
      for (const r of rows) {
        const matchesQ = !q || r.dataset.search.includes(q);
        const matchesS = !s || r.dataset.severity === s;
        const visible = matchesQ && matchesS;
        r.style.display = visible ? '' : 'none';
        if (visible) shown++;
      }
      if (count) count.textContent = shown + ' / ' + total + ' detectors';
    };
    filter.addEventListener('input', apply);
    if (sev) sev.addEventListener('change', apply);
    apply();
  }
})();

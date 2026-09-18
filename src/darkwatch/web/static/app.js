/*
 * Darkwatch dashboard.
 *
 * Two rules run through this file:
 * 1. Every value that came from a scanned page (title, snippet, URL, term) is put on the page
 *    as a text node, never as HTML, and evidence URLs are never turned into links. The data is
 *    by definition attacker-controlled.
 * 2. Motion is decoration. The page is complete and usable with GSAP missing or motion off.
 */
(function () {
  'use strict';

  /* ---------------------------------------------------------------- token + api */
  const url = new URL(location.href);
  const fromUrl = url.searchParams.get('t');
  if (fromUrl) {
    try { sessionStorage.setItem('dw-token', fromUrl); } catch { /* private mode */ }
    url.searchParams.delete('t');
    history.replaceState(null, '', url.pathname + url.search + url.hash);
  }
  let TOKEN = fromUrl || '';
  if (!TOKEN) { try { TOKEN = sessionStorage.getItem('dw-token') || ''; } catch { TOKEN = ''; } }

  async function api(path, options) {
    const opts = Object.assign({ headers: {} }, options || {});
    opts.headers = Object.assign({ 'x-darkwatch-token': TOKEN }, opts.headers);
    if (opts.body !== undefined && typeof opts.body !== 'string') {
      opts.headers['content-type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    const res = await fetch(path, opts);
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = (await res.json()).detail || detail; } catch { /* not json */ }
      const err = new Error(detail);
      err.status = res.status;
      throw err;
    }
    return res.status === 204 ? null : res.json();
  }

  const $ = (sel, scope) => (scope || document).querySelector(sel);
  const $$ = (sel, scope) => Array.from((scope || document).querySelectorAll(sel));
  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  };
  const fmtInt = (n) => Number(n || 0).toLocaleString('en-US');
  const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const SEV_COLOR = { CRITICAL: '--crit', HIGH: '--high', MEDIUM: '--med', LOW: '--low' };

  function ago(iso) {
    if (!iso) return 'never';
    const then = Date.parse(iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z');
    if (Number.isNaN(then)) return iso;
    const s = Math.max(0, (Date.now() - then) / 1000);
    if (s < 90) return 'just now';
    if (s < 5400) return `${Math.round(s / 60)} min ago`;
    if (s < 172800) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} d ago`;
  }

  /* ---------------------------------------------------------------- motion */
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const hasGsap = typeof window.gsap !== 'undefined';
  if (hasGsap) {
    const plugins = [window.ScrollTrigger, window.Flip, window.ScrambleTextPlugin, window.DrawSVGPlugin].filter(Boolean);
    if (plugins.length) gsap.registerPlugin.apply(gsap, plugins);
  }
  const motion = {
    paused: false,
    get on() { return hasGsap && !reduceMotion && !this.paused; },
  };
  try { motion.paused = localStorage.getItem('dw-motion-paused') === '1'; } catch { /* ignore */ }

  function countTo(node, value) {
    const target = Number(value || 0);
    if (!motion.on) { node.textContent = fmtInt(target); return; }
    const state = { v: Number(String(node.textContent).replace(/[^\d]/g, '')) || 0 };
    gsap.to(state, {
      v: target, duration: 0.9, ease: 'power2.out',
      onUpdate: () => { node.textContent = fmtInt(Math.round(state.v)); },
    });
  }

  /* ---------------------------------------------------------------- toasts */
  const toastBox = $('[data-toasts]');
  function toast(message, kind) {
    const node = el('div', 'toast' + (kind ? ' ' + kind : ''), message);
    toastBox.appendChild(node);
    if (motion.on) gsap.from(node, { y: 14, opacity: 0, duration: 0.3, ease: 'power2.out' });
    setTimeout(() => {
      if (motion.on) gsap.to(node, { opacity: 0, y: 8, duration: 0.3, onComplete: () => node.remove() });
      else node.remove();
    }, kind === 'bad' ? 7000 : 4200);
  }

  /* ---------------------------------------------------------------- state */
  const state = {
    q: '', order: 'score', includeClosed: false,
    severity: new Set(), source: new Set(), status: new Set(), target: new Set(),
    limit: 25, offset: 0, total: 0, loading: false, summary: null,
  };

  function queryString() {
    const p = new URLSearchParams();
    if (state.q) p.set('q', state.q);
    p.set('order', state.order);
    p.set('limit', String(state.limit));
    p.set('offset', String(state.offset));
    if (state.includeClosed) p.set('include_closed', 'true');
    state.severity.forEach((v) => p.append('severity', v));
    state.source.forEach((v) => p.append('source', v));
    state.status.forEach((v) => p.append('status', v));
    state.target.forEach((v) => p.append('target', v));
    return p.toString();
  }

  /* ---------------------------------------------------------------- hits */
  const hitList = $('[data-hits]');
  const resultLine = $('[data-result-line]');
  const moreBtn = $('[data-more]');

  function highlight(text, tokens) {
    const frag = document.createDocumentFragment();
    if (!tokens.length) { frag.appendChild(document.createTextNode(text)); return frag; }
    const rx = new RegExp('(' + tokens.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')', 'ig');
    let last = 0;
    String(text).replace(rx, (match, _g, index) => {
      if (index > last) frag.appendChild(document.createTextNode(text.slice(last, index)));
      const mark = el('mark', null, match);
      frag.appendChild(mark);
      last = index + match.length;
      return match;
    });
    if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
    return frag;
  }

  function tokensOf(q) {
    return (q.match(/"([^"]*)"|(\S+)/g) || []).map((t) => t.replace(/"/g, '')).filter(Boolean);
  }

  function hitCard(hit, tokens) {
    const card = el('article', 'hit');
    card.dataset.sev = hit.severity;
    card.dataset.id = String(hit.id);

    const top = el('div', 'hit-top');
    const sev = el('span', 'sev', hit.severity);
    sev.dataset.v = hit.severity;
    top.append(sev, el('span', null, `#${hit.id}`), el('span', null, `score ${hit.score}`),
      el('span', null, hit.source), el('span', null, hit.status));
    if (hit.signals.length) top.append(el('span', null, hit.signals.join(' · ')));
    top.append(el('span', null, `first seen ${ago(hit.first_seen)}`));

    const title = el('h3', 'hit-title');
    title.appendChild(highlight(hit.title || hit.url, tokens));

    const meta = el('div', 'hit-meta');
    const code = el('code');
    code.appendChild(highlight(hit.term, tokens));
    meta.append(code, document.createTextNode(` ${hit.term_type} · ${hit.target}`));

    const urlLine = el('div', 'hit-meta hit-url');
    urlLine.appendChild(highlight(hit.url, tokens)); // text only: evidence URLs are never linked

    const snippet = el('pre', 'snippet');
    snippet.appendChild(highlight(hit.snippet, tokens));
    snippet.addEventListener('click', () => snippet.classList.toggle('open'));

    const actions = el('div', 'hit-actions');
    const mk = (label, status, cls) => {
      const b = el('button', 'btn btn-small' + (cls ? ' ' + cls : ''), label);
      b.addEventListener('click', () => setStatus([hit.id], status, b));
      return b;
    };
    if (hit.status !== 'acknowledged') actions.appendChild(mk('Acknowledge', 'acknowledged'));
    if (hit.status !== 'resolved') actions.appendChild(mk('Resolve', 'resolved'));
    if (hit.status !== 'false_positive') actions.appendChild(mk('False positive', 'false_positive'));
    if (hit.status !== 'new') actions.appendChild(mk('Reopen', 'new'));
    actions.appendChild(el('span', 'spacer'));
    const copy = el('button', 'btn btn-small', 'Copy URL');
    copy.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(hit.url); toast('URL copied', 'good'); }
      catch { toast('could not copy', 'bad'); }
    });
    actions.appendChild(copy);

    card.append(top, title, meta, urlLine, snippet, actions);

    if (hit.actions && hit.actions.length) {
      const det = el('details', 'advice');
      det.appendChild(el('summary', null, `What to do (${hit.actions.length})`));
      const ol = el('ol');
      hit.actions.forEach((a) => ol.appendChild(el('li', null, a)));
      det.appendChild(ol);
      card.appendChild(det);
    }
    if (hit.note) card.appendChild(el('div', 'hit-meta', `note: ${hit.note}`));
    return card;
  }

  async function setStatus(ids, status, button) {
    if (button) button.disabled = true;
    try {
      const res = await api('/api/hits/status', { method: 'POST', body: { ids, status } });
      toast(`${res.changed} finding${res.changed === 1 ? '' : 's'} marked ${status.replace('_', ' ')}`, 'good');
      await Promise.all([loadHits(true), loadSummary(), loadFacets()]);
    } catch (err) {
      toast(err.message, 'bad');
      if (button) button.disabled = false;
    }
  }

  async function loadHits(reset) {
    if (reset) state.offset = 0;
    state.loading = true;
    let data;
    try {
      data = await api('/api/hits?' + queryString());
    } catch (err) {
      resultLine.textContent = 'could not load findings: ' + err.message;
      state.loading = false;
      return;
    }
    state.total = data.total;
    const tokens = tokensOf(state.q);
    const flipState = motion.on && window.Flip && !reset ? Flip.getState(hitList.children) : null;
    if (reset) hitList.innerHTML = '';
    if (!data.hits.length && reset) {
      const empty = el('div', 'empty', state.q || state.severity.size || state.source.size
        ? 'Nothing matches those filters.'
        : 'No open findings. That is the good outcome.');
      hitList.appendChild(empty);
    }
    const added = [];
    data.hits.forEach((hit) => {
      const card = hitCard(hit, tokens);
      hitList.appendChild(card);
      added.push(card);
    });
    if (flipState) Flip.from(flipState, { duration: 0.4, ease: 'power2.out', absolute: true });
    if (motion.on && added.length) {
      gsap.from(added, { y: 16, opacity: 0, duration: 0.45, stagger: 0.035, ease: 'power2.out', clearProps: 'all' });
    }
    const shown = hitList.querySelectorAll('.hit').length;
    resultLine.textContent = `${fmtInt(data.total)} finding${data.total === 1 ? '' : 's'}`
      + (state.q ? ` for “${state.q}”` : '')
      + (shown < data.total ? ` · showing ${fmtInt(shown)}` : '')
      + ` · ${data.took_ms} ms`;
    moreBtn.hidden = shown >= data.total;
    state.loading = false;
  }

  moreBtn.addEventListener('click', () => {
    state.offset += state.limit;
    loadHits(false);
  });

  /* ---------------------------------------------------------------- facets */
  const facetBox = $('[data-facets]');
  function chipFor(group, value, count) {
    const chip = el('button', 'chip' + (group === 'severity' ? ' chip-sev' : ''));
    chip.dataset.v = value;
    chip.setAttribute('aria-pressed', String(state[group].has(value)));
    chip.append(el('span', null, group === 'status' ? value.replace('_', ' ') : value));
    chip.appendChild(el('span', 'n', fmtInt(count)));
    chip.addEventListener('click', () => {
      state[group].has(value) ? state[group].delete(value) : state[group].add(value);
      chip.setAttribute('aria-pressed', String(state[group].has(value)));
      syncTiles();
      loadHits(true);
    });
    return chip;
  }

  async function loadFacets() {
    let data;
    try { data = await api('/api/facets' + (state.includeClosed ? '?include_closed=true' : '')); }
    catch { return; }
    facetBox.innerHTML = '';
    const groups = [['severity', 'Severity'], ['source', 'Evidence'], ['target', 'Target'], ['status', 'Status']];
    groups.forEach(([key]) => {
      (data[key] || []).forEach((item) => {
        if (!item.value) return;
        if (key === 'status' && !state.includeClosed) return;
        facetBox.appendChild(chipFor(key, item.value, item.count));
      });
    });
    if (facetBox.children.length) {
      const clear = el('button', 'chip', 'Clear filters');
      clear.addEventListener('click', () => {
        ['severity', 'source', 'status', 'target'].forEach((k) => state[k].clear());
        $('[data-q]').value = '';
        state.q = '';
        loadFacets();
        syncTiles();
        loadHits(true);
      });
      facetBox.appendChild(clear);
    }
  }

  function syncTiles() {
    $$('[data-sev-tile]').forEach((tile) => {
      tile.setAttribute('aria-pressed', String(state.severity.has(tile.dataset.sevTile)));
    });
  }

  /* ---------------------------------------------------------------- summary + charts */
  async function loadSummary() {
    let data;
    try { data = await api('/api/summary'); }
    catch (err) {
      if (err.status === 401) {
        document.body.innerHTML = '';
        const box = el('div', 'empty', 'This dashboard needs the link that `darkwatch web` printed. Open that link again.');
        box.style.margin = '20vh auto';
        box.style.maxWidth = '38rem';
        document.body.appendChild(box);
        return;
      }
      toast('could not load the summary: ' + err.message, 'bad');
      return;
    }
    state.summary = data;
    countTo($('[data-open-count]'), data.open_hits);
    $('[data-open-word]').textContent = data.open_hits === 1 ? 'exposure' : 'exposures';
    SEVS.forEach((s) => countTo($(`[data-sev="${s}"]`), data.by_severity[s] || 0));
    $('[data-version]').textContent = 'v' + data.version;
    const names = (data.targets_configured || []).map((t) => t.name);
    $('[data-watch-line]').textContent = names.length
      ? `watching ${names.join(', ')}`
      : 'no targets in the watchlist';
    const lr = data.last_run;
    $('[data-last-run]').textContent = lr ? ago(lr.finished || lr.started) : 'never';
    $('[data-foot-meta]').textContent = `${fmtInt(data.total_hits)} findings stored · `
      + `${fmtInt(data.documents_seen)} documents seen · watchlist ${data.watchlist}`;
    const enabled = (data.sources || []).filter((s) => s.enabled).map((s) => s.name);
    $('[data-hero-sub]').textContent = enabled.length
      ? `Sources: ${enabled.join(', ')}. Evidence is stored as a URL, times and a short snippet.`
      : 'No sources are enabled in the watchlist.';
    buildSourcePicker(data.sources || []);
  }

  async function loadTimeline() {
    let data;
    try { data = await api('/api/timeline?days=30'); } catch { return; }
    const days = data.days || [];
    const svg = $('[data-timeline]');
    svg.innerHTML = '';
    const W = 640, H = 160, pad = 6;
    const max = Math.max(1, ...days.map((d) => d.total));
    const step = days.length > 1 ? (W - pad * 2) / (days.length - 1) : 0;
    const pt = (i, v) => [pad + i * step, H - pad - (v / max) * (H - pad * 2)];

    const area = days.map((d, i) => pt(i, d.total));
    const lineD = area.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`).join(' ');
    const fillD = `${lineD} L${(pad + (days.length - 1) * step).toFixed(1)} ${H - pad} L${pad} ${H - pad} Z`;

    const ns = 'http://www.w3.org/2000/svg';
    const grad = document.createElementNS(ns, 'linearGradient');
    grad.id = 'tl-fill';
    grad.setAttribute('x1', '0'); grad.setAttribute('y1', '0');
    grad.setAttribute('x2', '0'); grad.setAttribute('y2', '1');
    ['rgb(var(--accent-rgb) / .34)', 'rgb(var(--accent-rgb) / 0)'].forEach((c, i) => {
      const stop = document.createElementNS(ns, 'stop');
      stop.setAttribute('offset', i ? '1' : '0');
      stop.setAttribute('stop-color', c);
      grad.appendChild(stop);
    });
    const defs = document.createElementNS(ns, 'defs');
    defs.appendChild(grad);
    svg.appendChild(defs);

    const fill = document.createElementNS(ns, 'path');
    fill.setAttribute('d', fillD);
    fill.setAttribute('fill', 'url(#tl-fill)');
    svg.appendChild(fill);

    const line = document.createElementNS(ns, 'path');
    line.setAttribute('d', lineD);
    line.setAttribute('fill', 'none');
    line.setAttribute('stroke', 'var(--accent)');
    line.setAttribute('stroke-width', '2');
    line.setAttribute('stroke-linejoin', 'round');
    line.setAttribute('vector-effect', 'non-scaling-stroke');
    svg.appendChild(line);

    days.forEach((d, i) => {
      if (!d.total) return;
      const [x, y] = pt(i, d.total);
      const dot = document.createElementNS(ns, 'circle');
      dot.setAttribute('cx', x.toFixed(1));
      dot.setAttribute('cy', y.toFixed(1));
      dot.setAttribute('r', '3');
      const worst = SEVS.find((s) => d[s] > 0) || 'LOW';
      dot.setAttribute('fill', `var(${SEV_COLOR[worst]})`);
      const title = document.createElementNS(ns, 'title');
      title.textContent = `${d.day}: ${d.total} new`;
      dot.appendChild(title);
      svg.appendChild(dot);
    });

    const legend = $('[data-timeline-legend]');
    legend.innerHTML = '';
    const totals = days.reduce((n, d) => n + d.total, 0);
    legend.append(el('span', null, `${fmtInt(totals)} new in 30 days`));
    SEVS.forEach((s) => {
      const n = days.reduce((acc, d) => acc + (d[s] || 0), 0);
      if (!n) return;
      const span = el('span');
      const swatch = el('i');
      swatch.style.background = `var(${SEV_COLOR[s]})`;
      span.append(swatch, document.createTextNode(`${s.toLowerCase()} ${n}`));
      legend.appendChild(span);
    });

    if (motion.on && window.DrawSVGPlugin) {
      gsap.from(line, { drawSVG: '0%', duration: 1.1, ease: 'power2.out' });
      gsap.from(fill, { opacity: 0, duration: 1.2 });
      gsap.from(svg.querySelectorAll('circle'), { scale: 0, transformOrigin: 'center', duration: 0.4, stagger: 0.02, ease: 'back.out(2)' });
    }
  }

  async function loadSourceBars() {
    let data;
    try { data = await api('/api/facets' + (state.includeClosed ? '?include_closed=true' : '')); } catch { return; }
    const box = $('[data-source-bars]');
    box.innerHTML = '';
    const rows = (data.source || []).slice(0, 8);
    const max = Math.max(1, ...rows.map((r) => r.count));
    if (!rows.length) { box.appendChild(el('div', 'hit-meta', 'no evidence stored yet')); return; }
    rows.forEach((row) => {
      const wrap = el('div', 'bar-row');
      wrap.append(el('span', null, row.value), el('b', null, fmtInt(row.count)));
      const track = el('div', 'bar-track');
      const fill = el('div', 'bar-fill');
      track.appendChild(fill);
      wrap.appendChild(track);
      box.appendChild(wrap);
      const pct = (row.count / max) * 100;
      if (motion.on) gsap.to(fill, { width: pct + '%', duration: 0.8, ease: 'power2.out' });
      else fill.style.width = pct + '%';
    });
  }

  async function loadRuns() {
    let data;
    try { data = await api('/api/runs?limit=12'); } catch { return; }
    const box = $('[data-runs]');
    box.innerHTML = '';
    if (!data.runs.length) { box.appendChild(el('div', 'hit-meta', 'no runs yet')); return; }
    data.runs.forEach((run) => {
      const row = el('div', 'run-row');
      const dot = el('span', 'run-dot' + (run.errors.length ? ' bad' : ''));
      const mid = el('span', null, `#${run.id} · ${ago(run.finished || run.started)} · ${run.pages} docs`);
      const right = el('span', run.new_hits ? 'run-new' : null, run.new_hits ? `+${run.new_hits}` : '—');
      row.append(dot, mid, right);
      row.title = `${(run.sources || []).join(', ')}\n${run.seconds ?? '?'} s`
        + (run.errors.length ? `\n${run.errors.length} error(s)` : '');
      box.appendChild(row);
    });
  }

  /* ---------------------------------------------------------------- jobs (scan / search) */
  function renderLog(box, events) {
    events.forEach((e) => {
      const line = el('div', e.kind === 'error' ? 'err' : null);
      line.append(el('b', null, `${e.at.toFixed(1)}s `), document.createTextNode(e.text));
      box.appendChild(line);
    });
    box.scrollTop = box.scrollHeight;
  }

  function streamJob(job, logBox, onDone) {
    logBox.hidden = false;
    logBox.innerHTML = '';
    renderLog(logBox, job.events || []);
    const source = new EventSource(`/api/jobs/${job.id}/events?t=${encodeURIComponent(TOKEN)}`);
    source.onmessage = (ev) => {
      let snap;
      try { snap = JSON.parse(ev.data); } catch { return; }
      renderLog(logBox, snap.events || []);
      if (!snap.running) {
        source.close();
        onDone(snap);
      }
    };
    source.onerror = () => { source.close(); };
  }

  function findingCard(f) {
    const card = el('article', 'hit');
    card.dataset.sev = f.severity;
    const top = el('div', 'hit-top');
    const sev = el('span', 'sev', f.severity);
    sev.dataset.v = f.severity;
    top.append(sev, el('span', null, f.source), el('span', null, `score ${f.score}`));
    if (f.signals && f.signals.length) top.append(el('span', null, f.signals.join(' · ')));
    const title = el('h3', 'hit-title', f.title || f.url);
    const urlLine = el('div', 'hit-meta hit-url', f.url);
    const snippet = el('pre', 'snippet', f.snippet);
    snippet.addEventListener('click', () => snippet.classList.toggle('open'));
    card.append(top, title, urlLine, snippet);
    return card;
  }

  /* scan ----------------------------------------------------------- */
  const scanDialog = $('[data-scan-dialog]');
  $('[data-scan]').addEventListener('click', () => scanDialog.showModal());
  $('[data-scan-go]').addEventListener('click', async (ev) => {
    const btn = ev.currentTarget;
    btn.disabled = true;
    const results = $('[data-scan-results]');
    results.innerHTML = '';
    try {
      const job = await api('/api/scan', {
        method: 'POST',
        body: { use_tor: $('[data-scan-tor]').checked, notify: $('[data-scan-notify]').checked },
      });
      toast('scan started', 'good');
      streamJob(job, $('[data-scan-log]'), (snap) => {
        btn.disabled = false;
        if (snap.error) { toast(snap.error, 'bad'); return; }
        const r = snap.result || {};
        const fresh = (r.new_hits || []).concat(r.escalated_hits || []);
        results.appendChild(el('p', 'sub',
          `Run #${r.run_id}: ${r.documents} documents in ${r.seconds}s, `
          + `${(r.new_hits || []).length} new, ${(r.escalated_hits || []).length} escalated, `
          + `${(r.errors || []).length} error(s).`));
        fresh.forEach((hit) => results.appendChild(hitCard(hit, [])));
        toast(fresh.length ? `${fresh.length} new or escalated finding(s)` : 'scan finished, nothing new',
          fresh.length ? 'bad' : 'good');
        refreshAll();
      });
    } catch (err) {
      btn.disabled = false;
      toast(err.message, 'bad');
    }
  });

  /* deep search ---------------------------------------------------- */
  const deepDialog = $('[data-deep-dialog]');
  const deepSources = new Set();
  function buildSourcePicker(sources) {
    const box = $('[data-deep-sources]');
    if (!box || box.dataset.built) return;
    box.dataset.built = '1';
    sources.filter((s) => s.name !== 'seeds').forEach((s) => {
      if (s.enabled) deepSources.add(s.name);
      const chip = el('button', 'chip');
      chip.setAttribute('aria-pressed', String(s.enabled));
      chip.append(el('span', null, s.name));
      chip.title = s.description + (s.limitation ? ` — ${s.limitation}` : '');
      chip.addEventListener('click', () => {
        deepSources.has(s.name) ? deepSources.delete(s.name) : deepSources.add(s.name);
        chip.setAttribute('aria-pressed', String(deepSources.has(s.name)));
      });
      box.appendChild(chip);
    });
  }
  $('[data-deep]').addEventListener('click', () => {
    deepDialog.showModal();
    setTimeout(() => $('[data-deep-q]').focus(), 60);
  });
  async function runDeepSearch() {
    const query = $('[data-deep-q]').value.trim();
    if (!query) { toast('type something to search for', 'bad'); return; }
    const btn = $('[data-deep-go]');
    btn.disabled = true;
    const results = $('[data-deep-results]');
    results.innerHTML = '';
    try {
      const job = await api('/api/search', {
        method: 'POST',
        body: { query, term_type: $('[data-deep-type]').value, sources: Array.from(deepSources) },
      });
      streamJob(job, $('[data-deep-log]'), (snap) => {
        btn.disabled = false;
        if (snap.error) { toast(snap.error, 'bad'); return; }
        const r = snap.result || {};
        results.appendChild(el('p', 'sub',
          `${(r.findings || []).length} match(es) across ${r.documents} document(s) in ${r.seconds}s`
          + ` · treated as ${r.term_type}` + ((r.errors || []).length ? ` · ${r.errors.length} error(s)` : '')));
        (r.findings || []).forEach((f) => results.appendChild(findingCard(f)));
        if (!(r.findings || []).length) results.appendChild(el('div', 'empty', 'Nothing found for that keyword.'));
      });
    } catch (err) {
      btn.disabled = false;
      toast(err.message, 'bad');
    }
  }
  $('[data-deep-go]').addEventListener('click', runDeepSearch);
  $('[data-deep-q]').addEventListener('keydown', (e) => { if (e.key === 'Enter') runDeepSearch(); });

  /* ---------------------------------------------------------------- controls */
  const qInput = $('[data-q]');
  let debounce = 0;
  qInput.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => { state.q = qInput.value.trim(); loadHits(true); }, 180);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement !== qInput && !/input|textarea/i.test(document.activeElement.tagName)) {
      e.preventDefault();
      qInput.focus();
      qInput.select();
    }
    if (e.key === 'Escape' && document.activeElement === qInput) { qInput.value = ''; state.q = ''; loadHits(true); }
  });
  $('[data-order]').addEventListener('change', (e) => { state.order = e.target.value; loadHits(true); });
  $('[data-include-closed]').addEventListener('change', (e) => {
    state.includeClosed = e.target.checked;
    state.status.clear();
    loadFacets();
    loadSourceBars();
    loadHits(true);
  });
  $$('[data-sev-tile]').forEach((tile) => {
    tile.addEventListener('click', () => {
      const v = tile.dataset.sevTile;
      state.severity.has(v) ? state.severity.delete(v) : state.severity.add(v);
      syncTiles();
      $$('.chip-sev').forEach((c) => c.setAttribute('aria-pressed', String(state.severity.has(c.dataset.v))));
      loadHits(true);
      document.getElementById('hits').scrollIntoView({ behavior: motion.on ? 'smooth' : 'auto', block: 'start' });
    });
  });

  const menu = $('[data-menu]');
  $('[data-menu-toggle]').addEventListener('click', (e) => {
    const open = menu.hidden;
    menu.hidden = !open;
    e.currentTarget.setAttribute('aria-expanded', String(open));
  });
  document.addEventListener('click', (e) => {
    if (!menu.hidden && !e.target.closest('.menu')) {
      menu.hidden = true;
      $('[data-menu-toggle]').setAttribute('aria-expanded', 'false');
    }
  });
  $$('[data-export]').forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const fmt = link.dataset.export;
      const a = document.createElement('a');
      a.href = `/api/export?fmt=${fmt}&t=${encodeURIComponent(TOKEN)}`
        + (state.includeClosed ? '&include_closed=true' : '');
      a.download = `darkwatch-hits.${fmt}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    });
  });
  $('[data-open-report]').addEventListener('click', () => {
    window.open(`/api/report?t=${encodeURIComponent(TOKEN)}`, '_blank', 'noopener');
  });
  $('[data-rebuild]').addEventListener('click', async () => {
    try {
      const res = await api('/api/report/rebuild', { method: 'POST', body: {} });
      toast(`report rebuilt (${res.written.length} files)`, 'good');
    } catch (err) { toast(err.message, 'bad'); }
  });

  /* pause motion ---------------------------------------------------- */
  const pauseBtn = $('[data-pause]');
  const pauseLabel = $('[data-pause-label]');
  function syncPause() {
    pauseLabel.textContent = motion.paused ? 'Resume' : 'Pause';
    document.body.classList.toggle('paused', motion.paused);
    if (field && field.setPaused) field.setPaused(motion.paused);
  }
  pauseBtn.addEventListener('click', () => {
    motion.paused = !motion.paused;
    try { localStorage.setItem('dw-motion-paused', motion.paused ? '1' : '0'); } catch { /* ignore */ }
    syncPause();
  });
  if (reduceMotion) pauseBtn.hidden = true;

  /* pointer ring ---------------------------------------------------- */
  const ring = $('[data-cursor]');
  if (!reduceMotion && window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
    let rx = 0, ry = 0, tx = 0, ty = 0;
    window.addEventListener('pointermove', (e) => {
      tx = e.clientX; ty = e.clientY;
      ring.classList.add('on');
      const interactive = e.target.closest('button, a, input, select, summary, .hit, .tile');
      ring.classList.toggle('big', !!interactive);
    }, { passive: true });
    const loop = () => {
      rx += (tx - rx) * 0.18;
      ry += (ty - ry) * 0.18;
      ring.style.transform = `translate(${rx}px, ${ry}px)`;
      requestAnimationFrame(loop);
    };
    requestAnimationFrame(loop);
  }

  /* ---------------------------------------------------------------- boot */
  let field = null;
  if (window.initField) field = window.initField($('[data-field]'));
  syncPause();

  if (motion.on) {
    gsap.from('.hero .tag, .h1, .hero .sub', { y: 18, opacity: 0, duration: 0.7, stagger: 0.08, ease: 'power2.out' });
    gsap.from('.tile', { y: 20, opacity: 0, duration: 0.6, stagger: 0.05, delay: 0.15, ease: 'power2.out' });
    if (window.ScrollTrigger) {
      $$('.panel').forEach((panel) => {
        gsap.from(panel.querySelectorAll('.panel-head > *'), {
          y: 22, opacity: 0, duration: 0.6, stagger: 0.08, ease: 'power2.out',
          scrollTrigger: { trigger: panel, start: 'top 78%' },
        });
      });
      ScrollTrigger.create({
        trigger: '.hero', start: 'top top', end: 'bottom top', scrub: true,
        onUpdate: (self) => { if (field && field.setFade) field.setFade(1 - self.progress * 0.9); },
      });
    }
  }

  function refreshAll() {
    return Promise.all([loadSummary(), loadFacets(), loadHits(true), loadTimeline(), loadSourceBars(), loadRuns()]);
  }
  refreshAll();
  setInterval(loadSummary, 60000);
})();

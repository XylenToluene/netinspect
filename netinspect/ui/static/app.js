/* netinspect UI: загружает graph.json и рисует граф на SVG. */
(function () {
  'use strict';
  var DATA_URL = 'graph.json';

  function showError(msg) {
    document.getElementById('load-error-text').textContent = msg;
    document.getElementById('load-error').hidden = false;
  }

  function fillHeader(meta) {
    function set(id, v) { document.getElementById(id).textContent = String(v); }
    set('m-server', meta.server);
    set('m-generated', meta.generated);
    set('m-nodes', meta.nodes);
    set('m-edges', meta.edges);
    set('m-problems', meta.problems);
    document.getElementById('m-problems-wrap').className = 'badge ' + (meta.problems ? 'badge-danger' : 'badge-success');
    var warnings = meta.warnings || [];
    if (warnings.length) {
      document.getElementById('warnings-title').textContent = 'Предупреждения загрузки: ' + warnings.length;
      var ul = document.getElementById('warning-list');
      warnings.forEach(function (w) {
        var li = document.createElement('li');
        li.textContent = w;
        ul.appendChild(li);
      });
      document.getElementById('warnings').hidden = false;
    }
  }

  function load() {
    fetch(DATA_URL, { cache: 'no-store', credentials: 'same-origin' })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (data) {
        fillHeader(data.meta || {});
        start(data);
      })
      .catch(function (err) {
        var hint = location.protocol === 'file:'
          ? ' Страница открыта как файл — запустите python -m netinspect serve и откройте http://127.0.0.1:8081/graph.html.'
          : ' Сгенерируйте данные: python -m netinspect graph -A --web-dir web (каталог задаётся serve --graph-dir).';
        showError('Не удалось загрузить ' + DATA_URL + ': ' + err.message + '.' + hint);
      });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', load);
  else load();

  function start(DATA) {
    var SVGNS = 'http://www.w3.org/2000/svg';
    var NODE_W = 250, NODE_H = 60, COL_STEP = 340, ROW_STEP = 80, TOP = 54, LEFT = 30;

    var byKey = {};
    DATA.nodes.forEach(function (n) { byKey[n.key] = n; });
    var outEdges = {}, inEdges = {};
    DATA.nodes.forEach(function (n) { outEdges[n.key] = []; inEdges[n.key] = []; });
    DATA.edges.forEach(function (e) {
      if (outEdges[e.source]) outEdges[e.source].push(e);
      if (inEdges[e.target]) inEdges[e.target].push(e);
    });

    var svg = document.getElementById('canvas');
    var viewport = document.getElementById('viewport');
    var search = document.getElementById('search');
    var nsSelect = document.getElementById('ns');
    var kindsBox = document.getElementById('kinds');
    var panel = document.getElementById('panel');
    var state = { kinds: {}, ns: '', query: '', selected: null };
    var positions = {};
    var nodeEls = {};
    var edgeEls = [];

    function el(name, attrs, parent) {
      var e = document.createElementNS(SVGNS, name);
      if (attrs) Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); });
      if (parent) parent.appendChild(e);
      return e;
    }
    function h(tag, cls, text, parent) {
      var e = document.createElement(tag);
      if (cls) e.className = cls;
      if (text !== undefined && text !== null) e.textContent = text;
      if (parent) parent.appendChild(e);
      return e;
    }
    function cmp(a, b) { return a < b ? -1 : a > b ? 1 : 0; }
    function nodeTitle(n) { return n.kind === 'ExternalHost' ? n.name : n.namespace + '/' + n.name; }
    function truncate(s, max) { return s.length > max ? s.slice(0, max - 1) + '…' : s; }
    function badgeClass(b) {
      if (b.indexOf('✗') >= 0 || b === 'не найден' || b === 'нет endpoints' || b === '0 ready' || / not ready$/.test(b)) return 'badge badge-danger';
      if (b.indexOf('✓') >= 0 || / ready$/.test(b)) return 'badge badge-success';
      return 'badge';
    }
    function styleOf(kind) { return DATA.styles[kind] || { color: 'var(--kind-eps)', soft: 'var(--kind-eps-soft)', abbr: '?' }; }
    function kindTag(kind, parent) {
      var st = styleOf(kind);
      var t = h('span', 'kind-tag', st.abbr, parent);
      t.style.color = st.color; t.style.background = st.soft;
      t.setAttribute('aria-hidden', 'true');
      return t;
    }
    function svgIcon(name, parent) {
      var svgEl = document.createElementNS(SVGNS, 'svg');
      svgEl.setAttribute('class', 'icon'); svgEl.setAttribute('aria-hidden', 'true');
      var use = document.createElementNS(SVGNS, 'use'); use.setAttribute('href', '#i-' + name);
      svgEl.appendChild(use);
      if (parent) parent.appendChild(svgEl);
      return svgEl;
    }

    // ---------- фильтры ----------
    var kindsPresent = [];
    DATA.columns.forEach(function (c) {
      c.kinds.forEach(function (k) {
        if (DATA.nodes.some(function (n) { return n.kind === k; })) kindsPresent.push(k);
      });
    });
    var kindButtons = {};
    kindsPresent.forEach(function (k) {
      state.kinds[k] = true;
      var b = h('button', 'kind-toggle', null, kindsBox);
      b.type = 'button';
      b.setAttribute('aria-pressed', 'true');
      b.title = 'Показать или скрыть ' + k;
      var sw = h('span', 'sw', null, b);
      sw.style.background = styleOf(k).color;
      h('span', '', k, b);
      h('span', 'count', String(DATA.nodes.filter(function (n) { return n.kind === k; }).length), b);
      b.addEventListener('click', function () {
        state.kinds[k] = !state.kinds[k];
        b.setAttribute('aria-pressed', state.kinds[k] ? 'true' : 'false');
        redraw();
      });
      kindButtons[k] = b;
    });
    var namespaces = [];
    DATA.nodes.forEach(function (n) {
      if (n.kind !== 'ExternalHost' && namespaces.indexOf(n.namespace) < 0) namespaces.push(n.namespace);
    });
    namespaces.sort().forEach(function (ns) {
      var o = h('option', '', ns, nsSelect); o.value = ns;
    });
    nsSelect.addEventListener('change', function () { state.ns = nsSelect.value; redraw(); });
    search.addEventListener('input', function () { state.query = search.value.trim().toLowerCase(); applySearch(); });

    function visibleKeys() {
      var vis = {};
      DATA.nodes.forEach(function (n) {
        if (!state.kinds[n.kind]) return;
        if (n.kind === 'ExternalHost') return;
        if (state.ns && n.namespace !== state.ns) return;
        vis[n.key] = true;
      });
      // ExternalHost виден, если виден хотя бы один ссылающийся на него узел
      DATA.nodes.forEach(function (n) {
        if (n.kind !== 'ExternalHost' || !state.kinds[n.kind]) return;
        if (!state.ns || inEdges[n.key].some(function (e) { return vis[e.source]; })) vis[n.key] = true;
      });
      return vis;
    }

    // ---------- раскладка ----------
    function layout(vis) {
      var cols = DATA.columns.map(function () { return []; });
      DATA.nodes.forEach(function (n) { if (vis[n.key]) cols[Math.min(n.column, cols.length - 1)].push(n); });
      var order = {};
      cols.forEach(function (col, ci) {
        col.forEach(function (n, i) { n._d = i; });
        col.sort(function (a, b) {
          if (ci > 0) {
            var ba = bary(a, order, vis), bb = bary(b, order, vis);
            if (ba !== bb) return ba - bb;
          }
          return cmp(a.namespace, b.namespace) || cmp(a.name, b.name);
        });
        col.forEach(function (n, i) { order[n.key] = i; });
      });
      var maxLen = Math.max.apply(null, cols.map(function (c) { return c.length; }).concat([1]));
      positions = {};
      cols.forEach(function (col, ci) {
        var offset = (maxLen - col.length) * ROW_STEP / 2;
        col.forEach(function (n, i) {
          positions[n.key] = { x: LEFT + ci * COL_STEP, y: TOP + offset + i * ROW_STEP };
        });
      });
      return { cols: cols, height: TOP + maxLen * ROW_STEP };
    }
    function bary(n, order, vis) {
      var s = 0, c = 0;
      inEdges[n.key].forEach(function (e) {
        if (vis[e.source] && order[e.source] !== undefined) { s += order[e.source]; c++; }
      });
      return c ? s / c : 1e6 + n._d;
    }

    // ---------- отрисовка ----------
    function bez(x1, y1, x2, y2, t) {
      var dx = Math.max(60, (x2 - x1) / 2);
      var p = [[x1, y1], [x1 + dx, y1], [x2 - dx, y2], [x2, y2]];
      var u = 1 - t;
      return [
        u*u*u*p[0][0] + 3*u*u*t*p[1][0] + 3*u*t*t*p[2][0] + t*t*t*p[3][0],
        u*u*u*p[0][1] + 3*u*u*t*p[1][1] + 3*u*t*t*p[2][1] + t*t*t*p[3][1]
      ];
    }

    function tForX(x1, x2, x) {
      // параметр t кривой, при котором её x равен заданному (x(t) монотонна)
      var lo = 0, hi = 1;
      for (var i = 0; i < 30; i++) {
        var mid = (lo + hi) / 2;
        if (bez(x1, 0, x2, 0, mid)[0] < x) lo = mid; else hi = mid;
      }
      return (lo + hi) / 2;
    }

    function redraw() {
      while (viewport.firstChild) viewport.removeChild(viewport.firstChild);
      nodeEls = {}; edgeEls = [];
      var vis = visibleKeys();
      var lay = layout(vis);
      var bands = el('g', {}, viewport);
      DATA.columns.forEach(function (c, ci) {
        if (!lay.cols[ci].length) return;
        var x = LEFT + ci * COL_STEP;
        el('rect', { x: x - 14, y: 8, width: NODE_W + 28, height: lay.height + 4, rx: 14, 'class': 'col-band' }, bands);
        var t = el('text', { x: x, y: 34, 'class': 'col-title' }, bands);
        t.textContent = c.title;
        var cnt = el('text', { x: x + NODE_W, y: 34, 'class': 'col-count', 'text-anchor': 'end' }, bands);
        cnt.textContent = String(lay.cols[ci].length);
      });
      var gEdges = el('g', {}, viewport);
      var gNodes = el('g', {}, viewport);
      var gLabels = el('g', {}, viewport);
      var placed = [];  // рамки уже размещённых подписей — чтобы не накладывались
      DATA.edges.forEach(function (e) {
        var a = positions[e.source], b = positions[e.target];
        if (!a || !b) return;
        var x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2, x2 = b.x, y2 = b.y + NODE_H / 2;
        var dx = Math.max(60, (x2 - x1) / 2);
        var missing = byKey[e.target].missing || byKey[e.source].missing;
        var g = el('g', { 'class': 'edge' + (missing ? ' missing' : '') }, gEdges);
        el('path', {
          d: 'M' + x1 + ',' + y1 + ' C' + (x1 + dx) + ',' + y1 + ' ' + (x2 - dx) + ',' + y2 + ' ' + x2 + ',' + y2,
          'marker-end': missing ? 'url(#arrow-bad)' : 'url(#arrow)'
        }, g);
        var lg = null;
        if (e.label) {
          // подпись — в промежутке перед целевой колонкой, поверх узлов
          lg = el('g', { 'class': 'edge-label' + (missing ? ' missing' : '') }, gLabels);
          // правый край подписи — перед стрелкой, чтобы не закрывать целевой узел
          var p = bez(x1, y1, x2, y2, tForX(x1, x2, x2 - 14));
          var bg = el('rect', { rx: 5 }, lg);
          var t = el('text', { x: p[0], y: p[1] + 4, 'text-anchor': 'end' }, lg);
          t.textContent = truncate(e.label, 26);
          var full = el('title', {}, lg); full.textContent = e.label;
          var bb = t.getBBox();
          var box = { x: bb.x - 6, y: bb.y - 2, w: bb.width + 12, h: bb.height + 4 };
          for (var guard = 0; guard < 20 && placed.some(function (o) {
            return box.x < o.x + o.w && o.x < box.x + box.w && box.y < o.y + o.h && o.y < box.y + box.h;
          }); guard++) {
            box.y += box.h + 1;
          }
          t.setAttribute('y', p[1] + 4 + (box.y - (bb.y - 2)));
          t.setAttribute('x', p[0] - 6);
          box.x -= 6;
          placed.push(box);
          bg.setAttribute('x', box.x); bg.setAttribute('y', box.y);
          bg.setAttribute('width', box.w); bg.setAttribute('height', box.h);
        }
        edgeEls.push({ edge: e, el: g, label: lg, path: g.firstChild, missing: missing });
      });
      DATA.nodes.forEach(function (n) {
        var pos = positions[n.key];
        if (!pos) return;
        var st = styleOf(n.kind);
        var g = el('g', {
          'class': 'node' + (n.missing ? ' missing' : '') + (st.dashed ? ' external' : ''),
          transform: 'translate(' + pos.x + ',' + pos.y + ')',
          tabindex: '0', role: 'button',
          'aria-label': n.kind + ' ' + nodeTitle(n) + (n.missing ? ', не найден' : '') + (n.problems.length ? ', есть проблемы' : '')
        }, gNodes);
        var tt = el('title', {}, g);
        tt.textContent = n.key + (n.problems.length ? '\n⚠ ' + n.problems.join('\n⚠ ') : '');
        el('rect', { 'class': 'box', width: NODE_W, height: NODE_H, rx: 12 }, g);
        var ib = el('rect', { x: 10, y: 12, width: 36, height: 36, rx: 9, 'class': 'icon-bg' }, g);
        ib.style.fill = n.missing ? 'var(--danger-soft)' : st.soft;
        if (st.dashed) { ib.style.stroke = 'var(--border-strong)'; ib.style.strokeDasharray = '3 3'; }
        var ab = el('text', { x: 28, y: 34, 'class': 'abbr', 'text-anchor': 'middle' }, g);
        ab.textContent = st.abbr;
        ab.style.fill = n.missing ? 'var(--danger)' : st.color;
        el('text', { x: 58, y: 27, 'class': 'name' }, g).textContent = truncate(n.name, 24);
        var sub = n.missing ? ['не найден', n.namespace] : (n.kind === 'ExternalHost' ? ['внешний хост'] : [n.namespace]).concat(n.badges.slice(0, 2));
        el('text', { x: 58, y: 45, 'class': 'sub' }, g).textContent = truncate(sub.join(' · '), 30);
        if (n.missing || n.problems.length) {
          el('circle', { cx: NODE_W - 2, cy: 2, r: 9, 'class': 'bang-bg' }, g);
          el('text', { x: NODE_W - 2, y: 6, 'class': 'bang', 'text-anchor': 'middle' }, g).textContent = '!';
        }
        g.addEventListener('click', function (ev) { ev.stopPropagation(); select(n.key, false); });
        g.addEventListener('keydown', function (ev) {
          if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); select(n.key, false); }
        });
        nodeEls[n.key] = g;
      });
      applySearch();
      applySelection();
    }

    // ---------- поиск и выделение ----------
    function matches(n, q) {
      if (n.key.toLowerCase().indexOf(q) >= 0) return true;
      return n.hosts.some(function (hh) { return hh.indexOf(q) >= 0; });
    }
    function applySearch() {
      var q = state.query;
      Object.keys(nodeEls).forEach(function (k) {
        var m = q && matches(byKey[k], q);
        nodeEls[k].classList.toggle('match', !!m);
        nodeEls[k].classList.toggle('dim', !!q && !m);
      });
      edgeEls.forEach(function (x) {
        x.el.classList.toggle('dim', !!q);
        if (x.label) x.label.classList.toggle('dim', !!q);
      });
    }
    function applySelection() {
      Object.keys(nodeEls).forEach(function (k) { nodeEls[k].classList.toggle('selected', k === state.selected); });
      edgeEls.forEach(function (x) {
        var on = !!state.selected && (x.edge.source === state.selected || x.edge.target === state.selected);
        x.el.classList.toggle('hl', on);
        if (x.label) x.label.classList.toggle('hl', on);
        x.path.setAttribute('marker-end', on ? 'url(#arrow-hl)' : (x.missing ? 'url(#arrow-bad)' : 'url(#arrow)'));
        // подсвеченные рёбра — поверх остальных
        if (on) x.el.parentNode.appendChild(x.el);
      });
    }

    function select(key, center) {
      var n = byKey[key];
      if (!n) return;
      if (!positions[key]) {
        // узел скрыт фильтрами — показать все
        state.ns = ''; nsSelect.value = '';
        state.kinds[n.kind] = true;
        if (kindButtons[n.kind]) kindButtons[n.kind].setAttribute('aria-pressed', 'true');
        redraw();
      }
      state.selected = key;
      applySelection();
      showPanel(n);
      if (center) centerOn(key);
    }

    function section(body, title) {
      var t = h('div', 'section-title', null, body);
      h('span', '', title, t);
      return t;
    }

    function showPanel(n) {
      panel.classList.add('open');
      var st = styleOf(n.kind);
      var tag = document.getElementById('p-tag');
      tag.textContent = st.abbr;
      tag.style.color = n.missing ? 'var(--danger)' : st.color;
      tag.style.background = n.missing ? 'var(--danger-soft)' : st.soft;
      document.getElementById('p-kind').textContent = n.kind + (n.missing ? ' · не найден в кластере' : '');
      document.getElementById('p-name').textContent = n.name;
      document.getElementById('p-ns').textContent = n.kind === 'ExternalHost' ? 'внешний хост' : 'namespace ' + n.namespace;
      var body = document.getElementById('p-body');
      while (body.firstChild) body.removeChild(body.firstChild);
      if (n.problems.length) {
        section(body, 'Проблемы');
        var ul = h('ul', 'problems', null, body);
        n.problems.forEach(function (p) { h('li', '', p, ul); });
      }
      if (n.badges.length) {
        section(body, 'Свойства');
        var chips = h('div', 'chips', null, body);
        n.badges.forEach(function (b) { h('span', badgeClass(b), b, chips); });
      }
      if (n.hosts.length) {
        section(body, 'Хосты');
        var hc = h('div', 'chips', null, body);
        n.hosts.forEach(function (x) { h('span', 'badge mono', x, hc); });
      }
      relList(body, 'Входящие связи', inEdges[n.key], 'source');
      relList(body, 'Исходящие связи', outEdges[n.key], 'target');
      var mh = section(body, 'Манифест' + (n.format ? ' · ' + n.format.toUpperCase() : ''));
      if (n.manifest) {
        var btn = h('button', 'btn btn-sm', null, mh);
        btn.type = 'button';
        svgIcon('copy', btn);
        var lbl = h('span', '', 'Копировать', btn);
        var pre = h('pre', 'manifest', n.manifest, body);
        btn.addEventListener('click', function () { copy(n.manifest, lbl, pre); });
      } else {
        h('p', 'empty', 'Манифеста нет: ресурс не найден в кластере.', body);
      }
    }

    function relList(body, title, edges, field) {
      section(body, title + ' · ' + edges.length);
      if (!edges.length) { h('p', 'empty', 'нет', body); return; }
      var ul = h('ul', 'rel', null, body);
      edges.slice().sort(function (a, b) { return cmp(a[field], b[field]); }).forEach(function (e) {
        var other = byKey[e[field]];
        var li = h('li', '', null, ul);
        var b = h('button', '', null, li);
        b.type = 'button';
        kindTag(other.kind, b);
        h('span', 'rel-name' + (other.missing ? ' bad' : ''), nodeTitle(other), b);
        if (e.label) h('span', 'rel-lbl', e.label, b);
        b.title = other.key;
        b.addEventListener('click', function () { select(other.key, true); });
      });
    }

    function copy(text, btn, pre) {
      function done(ok) {
        btn.textContent = ok ? 'Скопировано' : 'Выделено — нажмите Ctrl+C';
        setTimeout(function () { btn.textContent = 'Копировать'; }, 1600);
      }
      function fallback() {
        var range = document.createRange();
        range.selectNodeContents(pre);
        var sel = window.getSelection();
        sel.removeAllRanges(); sel.addRange(range);
        var ok = false;
        try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
        done(ok);
      }
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(function () { done(true); }, fallback);
      } else {
        fallback();
      }
    }

    document.getElementById('p-close').addEventListener('click', closePanel);
    function closePanel() { panel.classList.remove('open'); state.selected = null; applySelection(); }

    // ---------- зум и перетаскивание (viewBox) ----------
    var vb = { x: 0, y: 0, w: 1000, h: 600 };
    function setVB() { svg.setAttribute('viewBox', vb.x + ' ' + vb.y + ' ' + vb.w + ' ' + vb.h); }
    function fit() {
      var bb;
      try { bb = viewport.getBBox(); } catch (e) { bb = null; }
      if (!bb || !bb.width) bb = { x: 0, y: 0, width: 1000, height: 600 };
      var pad = 30;
      var rect = svg.getBoundingClientRect();
      var aspect = rect.width && rect.height ? rect.width / rect.height : 1.6;
      var w = bb.width + pad * 2, hh = bb.height + pad * 2;
      if (w / hh < aspect) w = hh * aspect; else hh = w / aspect;
      vb = { x: bb.x + bb.width / 2 - w / 2, y: bb.y + bb.height / 2 - hh / 2, w: w, h: hh };
      setVB();
    }
    function centerOn(key) {
      var p = positions[key];
      if (!p) return;
      vb.x = p.x + NODE_W / 2 - vb.w / 2; vb.y = p.y + NODE_H / 2 - vb.h / 2;
      setVB();
      if (nodeEls[key]) nodeEls[key].focus();
    }
    function toSvg(cx, cy) {
      var rect = svg.getBoundingClientRect();
      var s = Math.max(vb.w / rect.width, vb.h / rect.height);
      var offX = (rect.width * s - vb.w) / 2, offY = (rect.height * s - vb.h) / 2;
      return { x: vb.x - offX + (cx - rect.left) * s, y: vb.y - offY + (cy - rect.top) * s, s: s };
    }
    svg.addEventListener('wheel', function (ev) {
      ev.preventDefault();
      var p = toSvg(ev.clientX, ev.clientY);
      var k = ev.deltaY < 0 ? 0.88 : 1 / 0.88;
      var nw = vb.w * k;
      if (nw < 200 || nw > 30000) return;
      vb.x = p.x - (p.x - vb.x) * k; vb.y = p.y - (p.y - vb.y) * k;
      vb.w = nw; vb.h = vb.h * k;
      setVB();
    }, { passive: false });
    var drag = null;
    svg.addEventListener('pointerdown', function (ev) {
      if (ev.button !== 0 || (ev.target.closest && ev.target.closest('.node'))) return;
      drag = { x: ev.clientX, y: ev.clientY, vx: vb.x, vy: vb.y, s: toSvg(ev.clientX, ev.clientY).s, moved: false };
      svg.setPointerCapture(ev.pointerId);
      svg.classList.add('dragging');
    });
    svg.addEventListener('pointermove', function (ev) {
      if (!drag) return;
      var dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
      if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
      vb.x = drag.vx - dx * drag.s; vb.y = drag.vy - dy * drag.s;
      setVB();
    });
    function endDrag(ev) {
      if (!drag) return;
      var moved = drag.moved;
      drag = null;
      svg.classList.remove('dragging');
      if (!moved && ev.type === 'pointerup') closePanel();
    }
    svg.addEventListener('pointerup', endDrag);
    svg.addEventListener('pointercancel', endDrag);

    document.getElementById('fit').addEventListener('click', fit);
    function zoomBy(k) {
      var cx = vb.x + vb.w / 2, cy = vb.y + vb.h / 2;
      var nw = vb.w * k;
      if (nw < 200 || nw > 30000) return;
      vb.w = nw; vb.h = vb.h * k;
      vb.x = cx - vb.w / 2; vb.y = cy - vb.h / 2;
      setVB();
    }
    document.getElementById('zoom-in').addEventListener('click', function () { zoomBy(0.8); });
    document.getElementById('zoom-out').addEventListener('click', function () { zoomBy(1.25); });
    document.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape') closePanel();
      if (ev.key === '/' && document.activeElement !== search) { ev.preventDefault(); search.focus(); }
    });

    // список проблем в шапке
    var probList = document.getElementById('problem-list');
    DATA.nodes.forEach(function (n) {
      n.problems.forEach(function (p) {
        var b = h('button', '', null, h('li', '', null, probList));
        b.type = 'button';
        h('span', 'who', abbrOf(n) + ' ' + nodeTitle(n), b);
        h('span', '', p, b);
        b.addEventListener('click', function () { select(n.key, true); });
      });
    });
    function abbrOf(n) { return styleOf(n.kind).abbr; }
    document.getElementById('problems-title').textContent = 'Проблемы · ' + probList.children.length;
    document.getElementById('problems').hidden = !probList.children.length;

    redraw();
    fit();
    window.addEventListener('resize', fit);
  }
})();

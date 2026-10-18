"""Самодостаточный HTML-отчёт с графом на inline SVG.

Никаких внешних ресурсов: CSS и JS встроены, граф рисуется собственным кодом.
Данные графа встраиваются как JSON в ``<script type="application/json">``.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from string import Template
from typing import Any

from netinspect.core.fetcher import yaml
from netinspect.core.model import Graph
from netinspect.graph.builder import KIND_COLUMN, node_sort_key
from netinspect.ui import theme

#: Колонки раскладки по направлению трафика.
COLUMNS: list[dict[str, Any]] = [
    {"title": "Gateway / Route", "kinds": ["Gateway", "Route"]},
    {"title": "VirtualService", "kinds": ["VirtualService"]},
    {"title": "DestinationRule", "kinds": ["DestinationRule"]},
    {"title": "Service / External", "kinds": ["Service", "ExternalHost"]},
    {"title": "EndpointSlice", "kinds": ["EndpointSlice"]},
]


def manifest_text(raw: dict[str, Any] | None) -> tuple[str, str]:
    """Текст манифеста и формат: YAML (если есть PyYAML) или JSON."""
    if raw is None:
        return "", ""
    if yaml is not None:
        try:
            return yaml.safe_dump(raw, sort_keys=False, allow_unicode=True, default_flow_style=False), "yaml"
        except yaml.YAMLError:  # pragma: no cover - не должно случаться для JSON-данных
            pass
    return json.dumps(raw, indent=2, ensure_ascii=False), "json"


def safe_json(data: Any) -> str:
    """JSON для встраивания в ``<script>``: ``<``, ``>``, ``&`` экранируются.

    В частности, ``</script>`` внутри манифестов не может закрыть тег.
    """
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return (
        text.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace(" ", "\\u2028")
        .replace(" ", "\\u2029")
    )


def graph_payload(graph: Graph) -> dict[str, Any]:
    """Данные для встраивания в отчёт."""
    nodes = []
    for node in sorted(graph.nodes.values(), key=lambda n: node_sort_key(n.kind, n.namespace, n.name)):
        text, fmt = manifest_text(node.resource.raw if node.resource else None)
        nodes.append(
            {
                "key": node.key,
                "kind": node.kind,
                "namespace": node.namespace,
                "name": node.name,
                "missing": node.missing,
                "badges": node.badges,
                "problems": node.problems,
                "hosts": node.hosts,
                "column": KIND_COLUMN.get(node.kind, len(COLUMNS) - 1),
                "manifest": text,
                "format": fmt,
            }
        )
    styles = {}
    for kind in KIND_COLUMN:
        st = theme.node_style(kind)
        styles[kind] = {
            "fill": f"var(--{st['fill']})",
            "stroke": f"var(--{st['stroke']})",
            "dashed": bool(st["dashed"]),
        }
    return {
        "nodes": nodes,
        "edges": [e.to_dict() for e in graph.edges],
        "columns": COLUMNS,
        "styles": styles,
    }


def render_html(
    graph: Graph,
    server: str,
    warnings: list[str] | None = None,
    generated_at: datetime | None = None,
    title: str = "netinspect",
) -> str:
    """Сформировать HTML-отчёт."""
    warnings = warnings or []
    generated = (generated_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    problems = len(graph.problem_nodes())
    if warnings:
        items = "".join(f"<li>{html.escape(w)}</li>" for w in warnings)
        warnings_html = (
            f'<details class="warn"><summary>Предупреждения загрузки: {len(warnings)}</summary>'
            f"<ul>{items}</ul></details>"
        )
    else:
        warnings_html = ""
    return _PAGE.substitute(
        title=html.escape(title),
        css_vars=theme.css_variables(),
        css=_CSS,
        server=html.escape(server),
        generated=html.escape(generated),
        n_nodes=len(graph.nodes),
        n_edges=len(graph.edges),
        n_problems=problems,
        problems_class="bad" if problems else "good",
        warnings_html=warnings_html,
        data=safe_json(graph_payload(graph)),
        js=_JS,
    )


_CSS = """
* { box-sizing: border-box; }
html, body { height: 100%; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.45 var(--font-sans);
  display: flex; flex-direction: column; min-height: 100vh;
}
a, .link { color: var(--accent); }
button, input, select { font: inherit; color: inherit; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

header.top {
  background: var(--blue-100); border-bottom: 1px solid var(--blue-300);
  padding: 12px 20px; display: flex; flex-wrap: wrap; gap: 8px 24px; align-items: baseline;
}
header.top h1 { margin: 0; font-size: 18px; letter-spacing: .3px; }
header.top h1 span { color: var(--blue-500); font-weight: 500; }
.meta { display: flex; flex-wrap: wrap; gap: 6px 18px; color: var(--muted); font-size: 13px; }
.meta b { color: var(--text); font-weight: 600; }
.meta .bad b { color: var(--danger); }
.meta .good b { color: var(--ok); }
details.warn, details.probs {
  flex-basis: 100%; font-size: 13px; background: var(--surface);
  border: 1px solid var(--beige-400); border-radius: 8px; padding: 6px 12px;
}
details.warn summary, details.probs summary { cursor: pointer; color: var(--muted); }
details.probs summary { color: var(--danger); }
details ul { margin: 6px 0 2px; padding-left: 20px; }
details.probs li { cursor: pointer; }
details.probs li:hover { background: var(--accent-soft); }

.toolbar {
  display: flex; flex-wrap: wrap; gap: 10px 16px; align-items: center;
  padding: 10px 20px; background: var(--surface); border-bottom: 1px solid var(--beige-400);
}
.toolbar input[type=search] {
  width: 280px; max-width: 100%; padding: 6px 10px; border-radius: 8px;
  border: 1px solid var(--beige-400); background: var(--white);
}
.toolbar select {
  padding: 5px 8px; border-radius: 8px; border: 1px solid var(--beige-400); background: var(--white);
}
.kinds { display: flex; flex-wrap: wrap; gap: 4px 12px; }
.kinds label { display: inline-flex; align-items: center; gap: 5px; cursor: pointer; font-size: 13px; }
.swatch { width: 12px; height: 12px; border-radius: 3px; border: 1px solid var(--beige-400); display: inline-block; }
.btn {
  padding: 5px 12px; border-radius: 8px; border: 1px solid var(--blue-300);
  background: var(--surface); cursor: pointer;
}
.btn:hover { background: var(--accent-soft); }
.btn.primary { background: var(--accent); border-color: var(--accent); color: var(--white); }
.btn.primary:hover { filter: brightness(1.1); background: var(--accent); }
.hint { color: var(--muted); font-size: 12px; margin-left: auto; }

main { flex: 1; display: flex; min-height: 0; position: relative; }
#canvas-wrap { flex: 1; position: relative; min-height: 480px; background: var(--blue-100); }
svg#canvas { width: 100%; height: 100%; display: block; cursor: grab; user-select: none; }
svg#canvas.dragging { cursor: grabbing; }
.col-title { font-size: 12px; font-weight: 600; fill: var(--blue-500); letter-spacing: .6px; text-transform: uppercase; }
.col-band { fill: var(--surface); opacity: .35; }

.edge path { fill: none; stroke: var(--blue-300); stroke-width: 1.6; }
.edge.missing path { stroke: var(--danger); stroke-dasharray: 5 4; }
.edge.hl path { stroke: var(--accent); stroke-width: 2.4; }
.edge text { font-size: 11px; fill: var(--muted); }
.edge rect { fill: var(--surface); opacity: .9; }
.edge.hl text { fill: var(--accent); }

.node { cursor: pointer; }
.node rect.box { stroke-width: 1.4; filter: drop-shadow(0 1px 2px rgba(47,58,69,.15)); }
.node .kind { font-size: 10.5px; fill: var(--muted); letter-spacing: .5px; text-transform: uppercase; }
.node .name { font-size: 13.5px; font-weight: 600; fill: var(--text); }
.node .sub { font-size: 11.5px; fill: var(--muted); }
.node .warn-icon { font-size: 14px; fill: var(--danger); font-weight: 700; }
.node.missing rect.box { stroke: var(--danger) !important; stroke-width: 2; stroke-dasharray: 6 4; }
.node.missing .name { fill: var(--danger); }
.node.match rect.box { fill: var(--accent-soft) !important; stroke: var(--accent) !important; }
.node.selected rect.box { stroke: var(--accent) !important; stroke-width: 3; }
.node:focus-visible { outline: none; }
.node:focus-visible rect.box { stroke: var(--accent) !important; stroke-width: 3; }
.dim { opacity: .28; }

aside#panel {
  width: 440px; max-width: 48vw; background: var(--surface); border-left: 1px solid var(--beige-400);
  box-shadow: -4px 0 12px rgba(47,58,69,.08); display: none; flex-direction: column; min-height: 0;
}
aside#panel.open { display: flex; }
.panel-head { padding: 14px 16px 10px; border-bottom: 1px solid var(--beige-200); position: relative; }
.panel-head .k { font-size: 11px; text-transform: uppercase; letter-spacing: .6px; color: var(--blue-500); font-weight: 600; }
.panel-head h2 { margin: 2px 0 0; font-size: 16px; word-break: break-all; }
.panel-head .ns { color: var(--muted); font-size: 13px; }
.panel-head .close {
  position: absolute; top: 10px; right: 10px; border: none; background: none; font-size: 20px;
  cursor: pointer; color: var(--muted); border-radius: 8px; width: 30px; height: 30px;
}
.panel-head .close:hover { background: var(--accent-soft); color: var(--accent); }
.panel-body { padding: 12px 16px 16px; overflow: auto; flex: 1; }
.panel-body h3 { font-size: 12px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); margin: 14px 0 6px; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip {
  font-size: 12px; padding: 2px 8px; border-radius: 10px; background: var(--beige-200);
  border: 1px solid var(--beige-400);
}
.chip.ok { color: var(--ok); border-color: var(--ok); background: var(--surface); }
.chip.bad { color: var(--danger); border-color: var(--danger); background: var(--accent-soft); }
ul.problems { margin: 0; padding-left: 18px; color: var(--danger); }
ul.rel { list-style: none; margin: 0; padding: 0; }
ul.rel li { margin: 2px 0; }
ul.rel button {
  border: none; background: none; padding: 3px 6px; border-radius: 6px; cursor: pointer;
  color: var(--accent); text-align: left; width: 100%;
}
ul.rel button:hover { background: var(--accent-soft); }
ul.rel .lbl { color: var(--muted); font-size: 12px; margin-left: 6px; }
.manifest-head { display: flex; align-items: center; justify-content: space-between; margin-top: 14px; }
.manifest-head h3 { margin: 0; }
pre.manifest {
  margin: 6px 0 0; padding: 10px 12px; background: var(--bg); border: 1px solid var(--beige-200);
  border-radius: 8px; font: 12px/1.5 var(--font-mono); overflow: auto; max-height: 55vh; white-space: pre;
}
.empty { color: var(--muted); font-style: italic; }
.legend { display: flex; gap: 12px; align-items: center; font-size: 12px; color: var(--muted); }
.legend .dash { width: 22px; height: 0; border-top: 2px dashed var(--danger); display: inline-block; }
"""

_JS = r"""
(function () {
  'use strict';
  var DATA = JSON.parse(document.getElementById('graph-data').textContent);
  var SVGNS = 'http://www.w3.org/2000/svg';
  var NODE_W = 240, NODE_H = 62, COL_STEP = 330, ROW_STEP = 84, TOP = 46, LEFT = 30;

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
    if (b.indexOf('✗') >= 0 || b === 'не найден' || b === 'нет endpoints' || b === '0 ready' || / not ready$/.test(b)) return 'chip bad';
    if (b.indexOf('✓') >= 0) return 'chip ok';
    return 'chip';
  }

  // ---------- фильтры ----------
  var kindsPresent = [];
  DATA.columns.forEach(function (c) {
    c.kinds.forEach(function (k) {
      if (DATA.nodes.some(function (n) { return n.kind === k; })) kindsPresent.push(k);
    });
  });
  kindsPresent.forEach(function (k) {
    state.kinds[k] = true;
    var lab = h('label', '', null, kindsBox);
    var cb = h('input', '', null, lab);
    cb.type = 'checkbox'; cb.checked = true;
    cb.addEventListener('change', function () { state.kinds[k] = cb.checked; redraw(); });
    var sw = h('span', 'swatch', null, lab);
    var st = DATA.styles[k] || {};
    sw.style.background = st.fill || '';
    sw.style.borderColor = st.stroke || '';
    if (st.dashed) sw.style.borderStyle = 'dashed';
    h('span', '', k, lab);
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
      el('rect', { x: x - 12, y: 6, width: NODE_W + 24, height: lay.height, rx: 10, 'class': 'col-band' }, bands);
      var t = el('text', { x: x, y: 26, 'class': 'col-title' }, bands);
      t.textContent = c.title;
    });
    var gEdges = el('g', {}, viewport);
    var gNodes = el('g', {}, viewport);
    var gLabels = el('g', {}, viewport);
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
        lg = el('g', { 'class': 'edge' + (missing ? ' missing' : '') }, gLabels);
        var p = bez(x1, y1, x2, y2, tForX(x1, x2, x2 - (COL_STEP - NODE_W) / 2));
        var bg = el('rect', { rx: 4 }, lg);
        var t = el('text', { x: p[0], y: p[1] + 4, 'text-anchor': 'middle' }, lg);
        t.textContent = truncate(e.label, 40);
        var bb = t.getBBox();
        bg.setAttribute('x', bb.x - 3); bg.setAttribute('y', bb.y - 1);
        bg.setAttribute('width', bb.width + 6); bg.setAttribute('height', bb.height + 2);
      }
      edgeEls.push({ edge: e, el: g, label: lg });
    });
    DATA.nodes.forEach(function (n) {
      var pos = positions[n.key];
      if (!pos) return;
      var st = DATA.styles[n.kind] || { fill: 'var(--surface)', stroke: 'var(--beige-400)' };
      var g = el('g', {
        'class': 'node' + (n.missing ? ' missing' : ''),
        transform: 'translate(' + pos.x + ',' + pos.y + ')',
        tabindex: '0', role: 'button', 'aria-label': n.kind + ' ' + nodeTitle(n)
      }, gNodes);
      var tt = el('title', {}, g);
      tt.textContent = n.key + (n.problems.length ? '\n⚠ ' + n.problems.join('\n⚠ ') : '');
      var r = el('rect', { 'class': 'box', width: NODE_W, height: NODE_H, rx: 10 }, g);
      r.style.fill = st.fill; r.style.stroke = st.stroke;
      if (st.dashed) r.style.strokeDasharray = '5 4';
      el('text', { x: 12, y: 17, 'class': 'kind' }, g).textContent = n.kind + (n.missing ? ' · не найден' : '');
      el('text', { x: 12, y: 36, 'class': 'name' }, g).textContent = truncate(n.name, 27);
      var sub = n.kind === 'ExternalHost' ? n.badges : [n.namespace].concat(n.badges);
      el('text', { x: 12, y: 53, 'class': 'sub' }, g).textContent = truncate(sub.join(' · '), 36);
      if (n.missing || n.problems.length) {
        el('text', { x: NODE_W - 22, y: 20, 'class': 'warn-icon' }, g).textContent = '⚠';
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
    });
  }

  function select(key, center) {
    var n = byKey[key];
    if (!n) return;
    if (!positions[key]) {
      // узел скрыт фильтрами — показать все
      state.ns = ''; nsSelect.value = '';
      state.kinds[n.kind] = true;
      Array.prototype.forEach.call(kindsBox.querySelectorAll('input'), function (cb, i) {
        if (kindsPresent[i] === n.kind) cb.checked = true;
      });
      redraw();
    }
    state.selected = key;
    applySelection();
    showPanel(n);
    if (center) centerOn(key);
  }

  function showPanel(n) {
    panel.classList.add('open');
    document.getElementById('p-kind').textContent = n.kind + (n.missing ? ' · не найден' : '');
    document.getElementById('p-name').textContent = n.name;
    document.getElementById('p-ns').textContent = n.kind === 'ExternalHost' ? 'внешний хост' : 'namespace: ' + n.namespace;
    var body = document.getElementById('p-body');
    while (body.firstChild) body.removeChild(body.firstChild);
    if (n.problems.length) {
      h('h3', '', 'Проблемы', body);
      var ul = h('ul', 'problems', null, body);
      n.problems.forEach(function (p) { h('li', '', p, ul); });
    }
    if (n.badges.length) {
      h('h3', '', 'Бейджи', body);
      var chips = h('div', 'chips', null, body);
      n.badges.forEach(function (b) { h('span', badgeClass(b), b, chips); });
    }
    if (n.hosts.length) {
      h('h3', '', 'Хосты', body);
      var hc = h('div', 'chips', null, body);
      n.hosts.forEach(function (x) { h('span', 'chip', x, hc); });
    }
    relList(body, 'Входящие', inEdges[n.key], 'source');
    relList(body, 'Исходящие', outEdges[n.key], 'target');
    var mh = h('div', 'manifest-head', null, body);
    h('h3', '', 'Манифест' + (n.format ? ' (' + n.format.toUpperCase() + ')' : ''), mh);
    if (n.manifest) {
      var btn = h('button', 'btn primary', 'Копировать', mh);
      btn.type = 'button';
      var pre = h('pre', 'manifest', n.manifest, body);
      btn.addEventListener('click', function () { copy(n.manifest, btn, pre); });
    } else {
      h('p', 'empty', 'Манифест отсутствует: ресурс не найден в кластере.', body);
    }
  }

  function relList(body, title, edges, field) {
    h('h3', '', title + ' (' + edges.length + ')', body);
    if (!edges.length) { h('p', 'empty', 'нет', body); return; }
    var ul = h('ul', 'rel', null, body);
    edges.slice().sort(function (a, b) { return cmp(a[field], b[field]); }).forEach(function (e) {
      var other = byKey[e[field]];
      var li = h('li', '', null, ul);
      var b = h('button', '', (other.missing ? '⚠ ' : '') + other.kind + ' ' + nodeTitle(other), li);
      b.type = 'button';
      if (e.label) h('span', 'lbl', e.label, b);
      b.addEventListener('click', function () { select(other.key, true); });
    });
  }

  function copy(text, btn, pre) {
    function done(ok) {
      btn.textContent = ok ? 'Скопировано' : 'Выделено — Ctrl+C';
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
  document.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape') closePanel();
    if (ev.key === '/' && document.activeElement !== search) { ev.preventDefault(); search.focus(); }
  });

  // список проблем в шапке
  var probList = document.getElementById('problem-list');
  DATA.nodes.forEach(function (n) {
    n.problems.forEach(function (p) {
      var li = h('li', '', n.kind + ' ' + nodeTitle(n) + ': ' + p, probList);
      li.tabIndex = 0;
      li.addEventListener('click', function () { select(n.key, true); });
      li.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') select(n.key, true); });
    });
  });
  if (!probList.children.length) document.getElementById('problems').style.display = 'none';

  redraw();
  fit();
  window.addEventListener('resize', fit);
})();
"""

_PAGE = Template(
    """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} — граф сетевых правил</title>
<style>
${css_vars}
${css}
</style>
</head>
<body>
<header class="top">
  <h1>netinspect <span>· граф сетевых правил</span></h1>
  <div class="meta">
    <span>Источник: <b>${server}</b></span>
    <span>Сгенерировано: <b>${generated}</b></span>
    <span>Узлов: <b>${n_nodes}</b></span>
    <span>Связей: <b>${n_edges}</b></span>
    <span class="${problems_class}">Узлов с проблемами: <b>${n_problems}</b></span>
  </div>
  <details class="probs" id="problems"><summary>Проблемы</summary><ul id="problem-list"></ul></details>
  ${warnings_html}
</header>
<div class="toolbar">
  <input type="search" id="search" placeholder="Поиск по имени или хосту  ( / )" aria-label="Поиск">
  <select id="ns" aria-label="Namespace"><option value="">Все namespace</option></select>
  <div class="kinds" id="kinds" aria-label="Типы"></div>
  <button type="button" class="btn" id="fit">Вписать</button>
  <span class="legend"><span class="dash"></span> битая ссылка</span>
  <span class="hint">колесо — зум, перетаскивание — сдвиг, клик — детали</span>
</div>
<main>
  <div id="canvas-wrap">
    <svg id="canvas" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Граф связей">
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0,0 L10,5 L0,10 z" style="fill: var(--blue-500)"></path>
        </marker>
        <marker id="arrow-bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0,0 L10,5 L0,10 z" style="fill: var(--danger)"></path>
        </marker>
      </defs>
      <g id="viewport"></g>
    </svg>
  </div>
  <aside id="panel" aria-live="polite">
    <div class="panel-head">
      <div class="k" id="p-kind"></div>
      <h2 id="p-name"></h2>
      <div class="ns" id="p-ns"></div>
      <button type="button" class="close" id="p-close" aria-label="Закрыть">×</button>
    </div>
    <div class="panel-body" id="p-body"></div>
  </aside>
</main>
<script type="application/json" id="graph-data">${data}</script>
<script>
${js}
</script>
</body>
</html>
"""
)

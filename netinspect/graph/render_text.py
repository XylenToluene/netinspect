"""Отображение графа деревом в консоли (ANSI-цвета из палитры)."""

from __future__ import annotations

from netinspect.core.model import Edge, Graph, Node
from netinspect.graph.builder import node_sort_key
from netinspect.ui.theme import Ansi

SEEN_MARK = "(см. выше)"


def _sort_key(node: Node) -> tuple[int, int, str, str]:
    return node_sort_key(node.kind, node.namespace, node.name)


def _format_badge(badge: str, ansi: Ansi) -> str:
    text = f"[{badge}]"
    if "✗" in badge or badge in ("не найден", "нет endpoints", "0 ready") or badge.endswith("not ready"):
        return ansi.error(text)
    if "✓" in badge:
        return ansi.ok(text)
    return ansi.badge(text)


def format_node(node: Node, ansi: Ansi, edge_label: str = "", compact: bool = False) -> str:
    """Одна строка узла: тип, ns/name, бейджи, подпись ребра.

    ``compact=True`` — без бейджей (для повторно встреченных узлов).
    """
    title = f"{node.kind} {node.namespace}/{node.name}"
    if node.kind == "ExternalHost":
        title = f"ExternalHost {node.name}"
    head = ansi.error("⚠ " + title) if node.missing else ansi.node(title)
    parts = [head]
    if not compact:
        parts.extend(_format_badge(b, ansi) for b in node.badges)
    if not node.missing and node.problems:
        parts.append(ansi.error("⚠"))
    line = "  ".join(parts)
    if edge_label:
        line += "  " + ansi.muted(f"({edge_label})")
    return line


def render_tree(graph: Graph, ansi: Ansi | None = None) -> str:
    """Отрисовать граф деревом. Корни — узлы без входящих рёбер.

    Повторно встреченные узлы помечаются «(см. выше)» и не разворачиваются.
    """
    ansi = ansi or Ansi(enabled=False)
    out: list[str] = []
    seen: set[str] = set()
    children: dict[str, list[Edge]] = {k: [] for k in graph.nodes}
    has_parent: set[str] = set()
    for edge in graph.edges:
        if edge.source in children and edge.target in graph.nodes:
            children[edge.source].append(edge)
            has_parent.add(edge.target)
    for key in children:
        children[key].sort(key=lambda e: _sort_key(graph.nodes[e.target]))

    def walk(key: str, prefix: str, connector: str, label: str) -> None:
        node = graph.nodes[key]
        if key in seen:
            line = format_node(node, ansi, label, compact=True)
            out.append(f"{prefix}{connector}{line}  {ansi.muted(SEEN_MARK)}")
            return
        line = format_node(node, ansi, label)
        seen.add(key)
        out.append(f"{prefix}{connector}{line}")
        kids = children[key]
        if connector == "":
            child_prefix = prefix
        else:
            child_prefix = prefix + ("    " if connector.startswith("└") else "│   ")
        for i, edge in enumerate(kids):
            last = i == len(kids) - 1
            walk(edge.target, child_prefix, "└── " if last else "├── ", edge.label)

    roots = sorted((n for k, n in graph.nodes.items() if k not in has_parent), key=_sort_key)
    for root in roots:
        walk(root.key, "", "", "")
    # узлы, недостижимые от корней (например, в цикле)
    for node in sorted(graph.nodes.values(), key=_sort_key):
        if node.key not in seen:
            walk(node.key, "", "", "")
    return "\n".join(out)


def render_problems(graph: Graph, ansi: Ansi | None = None) -> str:
    """Список проблем по узлам."""
    ansi = ansi or Ansi(enabled=False)
    lines: list[str] = []
    for node in sorted(graph.problem_nodes(), key=_sort_key):
        for problem in node.problems:
            lines.append(f"  {ansi.error('⚠')} {node.kind} {node.namespace}/{node.name}: {problem}")
    return "\n".join(lines)


def render_summary(graph: Graph, warnings: list[str], ansi: Ansi | None = None) -> str:
    """Итог: число узлов, рёбер, проблем; предупреждения загрузки."""
    ansi = ansi or Ansi(enabled=False)
    problems = graph.problem_nodes()
    lines = [""]
    if problems:
        lines.append(ansi.error(f"Проблемы ({len(problems)}):"))
        lines.append(render_problems(graph, ansi))
    if warnings:
        lines.append(ansi.badge(f"Предупреждения загрузки ({len(warnings)}):"))
        lines.extend(f"  - {w}" for w in warnings)
    counts = f"Узлов: {len(graph.nodes)}, связей: {len(graph.edges)}, узлов с проблемами: {len(problems)}"
    lines.append(ansi.error(counts) if problems else ansi.ok(counts))
    return "\n".join(lines)

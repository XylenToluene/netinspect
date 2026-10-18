"""Экспорт веб-интерфейса: статические файлы UI + данные графа в ``graph.json``.

Каталог раздаётся nginx (см. ``deploy/nginx/netinspect.conf``)::

    <out_dir>/
      index.html   — разметка (из netinspect/ui/static)
      style.css    — стили
      app.js       — отрисовка графа на SVG
      theme.css    — CSS-переменные палитры, генерируется из ui/theme.py
      graph.json   — данные графа и метаданные отчёта
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Any

from netinspect.core.fetcher import yaml
from netinspect.core.model import Graph
from netinspect.graph.builder import KIND_COLUMN, node_sort_key
from netinspect.ui import theme

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ui", "static")
STATIC_FILES = ("index.html", "style.css", "app.js")
DATA_FILE = "graph.json"
THEME_FILE = "theme.css"

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


def graph_payload(
    graph: Graph,
    server: str,
    warnings: list[str] | None = None,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Содержимое ``graph.json``: метаданные, узлы, рёбра, колонки и стили узлов."""
    generated = (generated_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M:%S %Z").strip()
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
        "meta": {
            "server": server,
            "generated": generated,
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "problems": len(graph.problem_nodes()),
            "warnings": list(warnings or []),
        },
        "nodes": nodes,
        "edges": [e.to_dict() for e in graph.edges],
        "columns": COLUMNS,
        "styles": styles,
    }


def theme_css() -> str:
    """Содержимое ``theme.css``: CSS-переменные палитры."""
    return "/* Сгенерировано netinspect из ui/theme.py — не редактировать вручную. */\n" + theme.css_variables() + "\n"


def _atomic_write(path: str, text: str) -> None:
    """Записать файл атомарно, чтобы nginx не отдал полузаписанный JSON."""
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=os.path.basename(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def export_web(
    graph: Graph,
    out_dir: str,
    server: str,
    warnings: list[str] | None = None,
    generated_at: datetime | None = None,
) -> list[str]:
    """Выгрузить веб-интерфейс в ``out_dir``. Возвращает пути записанных файлов."""
    os.makedirs(out_dir, exist_ok=True)
    written: list[str] = []
    for name in STATIC_FILES:
        dst = os.path.join(out_dir, name)
        shutil.copyfile(os.path.join(STATIC_DIR, name), dst)
        os.chmod(dst, 0o644)
        written.append(dst)
    theme_path = os.path.join(out_dir, THEME_FILE)
    _atomic_write(theme_path, theme_css())
    written.append(theme_path)
    data = graph_payload(graph, server, warnings, generated_at)
    data_path = os.path.join(out_dir, DATA_FILE)
    _atomic_write(data_path, json.dumps(data, ensure_ascii=False, separators=(",", ":")))
    written.append(data_path)
    return written

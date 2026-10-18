"""Выделение подграфа от точек входа."""

from __future__ import annotations

from collections import deque
from typing import Iterable

from netinspect.core.hosts import hosts_intersect
from netinspect.core.model import Graph, make_key
from netinspect.core.resources import resolve_kind

#: Типы, по хостам которых ищется точка входа ``--host``.
HOST_ENTRY_KINDS = ("Gateway", "VirtualService", "Route")


def _walk(graph: Graph, starts: Iterable[str], forward: bool) -> set[str]:
    """BFS только в одном направлении (по трафику или против него)."""
    seen: set[str] = set()
    queue = deque(k for k in starts if k in graph.nodes)
    while queue:
        key = queue.popleft()
        if key in seen:
            continue
        seen.add(key)
        edges = graph.out_edges(key) if forward else graph.in_edges(key)
        for edge in edges:
            nxt = edge.target if forward else edge.source
            if nxt not in seen:
                queue.append(nxt)
    return seen


def subgraph(graph: Graph, start_keys: Iterable[str], leaf_keys: Iterable[str] = ()) -> Graph:
    """Подграф, достижимый от ``start_keys`` в обе стороны.

    Обход в ширину идёт отдельно вниз (по направлению трафика) и вверх
    (против него) — без «разворотов», иначе от одного VirtualService через общий
    Gateway в подграф попали бы все его соседи. ``leaf_keys`` включаются
    в подграф, но не разворачиваются (например, Gateway, совпавший по хосту).
    """
    starts = [k for k in start_keys if k in graph.nodes]
    keep = _walk(graph, starts, forward=True) | _walk(graph, starts, forward=False)
    keep |= {k for k in leaf_keys if k in graph.nodes}
    result = Graph()
    for key, node in graph.nodes.items():
        if key in keep:
            result.nodes[key] = node
    result.edges = [e for e in graph.edges if e.source in keep and e.target in keep]
    return result


def find_by_host(graph: Graph, host: str) -> list[str]:
    """Ключи Gateway, VirtualService и Route, у которых хост совпадает с ``host``."""
    return [
        node.key
        for node in graph.nodes.values()
        if node.kind in HOST_ENTRY_KINDS and any(hosts_intersect(h, host) for h in node.hosts)
    ]


def host_subgraph(graph: Graph, host: str) -> Graph:
    """Подграф для хоста: VS и Route разворачиваются, Gateway — только добавляются."""
    keys = find_by_host(graph, host)
    starts = [k for k in keys if graph.nodes[k].kind != "Gateway"]
    leaves = [k for k in keys if graph.nodes[k].kind == "Gateway"]
    return subgraph(graph, starts, leaves)


def parse_resource_ref(ref: str) -> str:
    """Разобрать ``vs/prod/reviews`` (или ``VirtualService/prod/reviews``) в ключ узла.

    ``ValueError`` при неверном формате или неизвестном типе.
    """
    parts = ref.strip().split("/")
    if len(parts) != 3 or not all(parts):
        raise ValueError(f"ожидается KIND/NAMESPACE/NAME, например vs/prod/reviews: {ref!r}")
    kind, ns, name = parts
    return make_key(resolve_kind(kind), ns, name)

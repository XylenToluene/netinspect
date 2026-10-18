"""Модели данных: ресурсы кластера и граф связей."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def make_key(kind: str, namespace: str, name: str) -> str:
    """Ключ узла/ресурса: ``Kind/ns/name``."""
    return f"{kind}/{namespace}/{name}"


@dataclass(slots=True)
class Resource:
    """Объект Kubernetes, очищенный от служебных полей."""

    kind: str
    namespace: str
    name: str
    spec: dict[str, Any]
    raw: dict[str, Any]

    @property
    def key(self) -> str:
        """Ключ ``Kind/ns/name``."""
        return make_key(self.kind, self.namespace, self.name)

    @property
    def labels(self) -> dict[str, str]:
        """Метки ресурса."""
        return (self.raw.get("metadata") or {}).get("labels") or {}

    @classmethod
    def from_manifest(cls, obj: dict[str, Any], default_namespace: str = "default") -> "Resource":
        """Создать ресурс из манифеста (dict)."""
        meta = obj.get("metadata") or {}
        spec = obj.get("spec")
        if not isinstance(spec, dict):
            spec = {}
        return cls(
            kind=str(obj.get("kind") or ""),
            namespace=str(meta.get("namespace") or default_namespace),
            name=str(meta.get("name") or ""),
            spec=spec,
            raw=obj,
        )


@dataclass(slots=True)
class Node:
    """Узел графа. ``missing=True`` — ссылка на несуществующий ресурс."""

    key: str
    kind: str
    namespace: str
    name: str
    resource: Resource | None = None
    missing: bool = False
    badges: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    #: Хосты, которые обслуживает узел (Gateway, VirtualService, Route, ExternalHost).
    hosts: list[str] = field(default_factory=list)

    @property
    def has_problems(self) -> bool:
        """Есть ли у узла проблемы (битая ссылка или предупреждения)."""
        return self.missing or bool(self.problems)

    def add_badge(self, badge: str) -> None:
        """Добавить бейдж без дублей."""
        if badge not in self.badges:
            self.badges.append(badge)

    def add_problem(self, problem: str) -> None:
        """Добавить описание проблемы без дублей."""
        if problem not in self.problems:
            self.problems.append(problem)

    def to_dict(self) -> dict[str, Any]:
        """Сериализация в JSON-совместимый dict."""
        return {
            "key": self.key,
            "kind": self.kind,
            "namespace": self.namespace,
            "name": self.name,
            "missing": self.missing,
            "badges": list(self.badges),
            "problems": list(self.problems),
            "hosts": list(self.hosts),
            "manifest": self.resource.raw if self.resource else None,
        }


#: Виды связей: трафик идёт по ссылке / ресурс входит в другой (DR → subset) /
#: политика применяется к объекту (EnvoyFilter → Gateway, Service, subset).
EDGE_TRAFFIC = "traffic"
EDGE_CONTAINS = "contains"
EDGE_POLICY = "policy"


@dataclass(slots=True, frozen=True)
class Edge:
    """Направленное ребро графа (по направлению трафика)."""

    source: str
    target: str
    label: str = ""
    kind: str = EDGE_TRAFFIC

    def to_dict(self) -> dict[str, str]:
        """Сериализация в dict."""
        return {"source": self.source, "target": self.target, "label": self.label, "kind": self.kind}


@dataclass(slots=True)
class Graph:
    """Граф связей сетевых ресурсов."""

    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def add_node(self, node: Node) -> Node:
        """Добавить узел; если узел с таким ключом есть — вернуть существующий."""
        existing = self.nodes.get(node.key)
        if existing is not None:
            return existing
        self.nodes[node.key] = node
        return node

    def add_edge(self, source: str, target: str, label: str = "", kind: str = EDGE_TRAFFIC) -> Edge:
        """Добавить ребро (без дублей)."""
        edge = Edge(source, target, label, kind)
        if edge not in self.edges:
            self.edges.append(edge)
        return edge

    def out_edges(self, key: str) -> list[Edge]:
        """Исходящие рёбра узла."""
        return [e for e in self.edges if e.source == key]

    def in_edges(self, key: str) -> list[Edge]:
        """Входящие рёбра узла."""
        return [e for e in self.edges if e.target == key]

    def problem_nodes(self) -> list[Node]:
        """Узлы с проблемами."""
        return [n for n in self.nodes.values() if n.has_problems]

    def to_dict(self) -> dict[str, Any]:
        """Сериализация в JSON-совместимый dict."""
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }

"""Построение графа связей сетевых ресурсов.

Направление рёбер — по движению трафика::

    Gateway → VirtualService → DestinationRule
                             → Service / ExternalHost → EndpointSlice
    Route → Service

Каждый тип связывается отдельным «линкером»; новый тип ресурса добавляется
новым методом ``_link_<kind>`` и записью в ``GraphBuilder.LINKERS``.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from netinspect.core.hosts import (
    DEFAULT_DOMAIN,
    is_cluster_host,
    match_host,
    normalize,
    split_ns_host,
    split_service_fqdn,
    to_fqdn,
)
from netinspect.core.model import Graph, Node, Resource, make_key

SERVICE_NAME_LABEL = "kubernetes.io/service-name"
EXTERNAL_NS = "-"
ROUTE_SECTIONS = ("http", "tcp", "tls")

#: Порядок колонок (по направлению трафика) — общий для рендеров.
KIND_COLUMN: dict[str, int] = {
    "Gateway": 0,
    "Route": 0,
    "VirtualService": 1,
    "DestinationRule": 2,
    "Service": 3,
    "ExternalHost": 3,
    "EndpointSlice": 4,
}


_KIND_SEQ = list(KIND_COLUMN)


def kind_order(kind: str) -> int:
    """Номер колонки для типа узла (неизвестные — в конец)."""
    return KIND_COLUMN.get(kind, len(KIND_COLUMN))


def node_sort_key(kind: str, namespace: str, name: str) -> tuple[int, int, str, str]:
    """Ключ сортировки узлов: колонка, тип (Gateway раньше Route), namespace, имя."""
    rank = _KIND_SEQ.index(kind) if kind in KIND_COLUMN else len(_KIND_SEQ)
    return kind_order(kind), rank, namespace, name


@dataclass(slots=True)
class _Destination:
    """Одна ссылка route[].destination из VirtualService."""

    host: str
    fqdn: str
    subset: str | None
    port: Any
    weight: Any
    section: str


@dataclass(slots=True)
class _EdgeLabels:
    """Подписи рёбер, накапливаемые до финализации (несколько route → одно ребро)."""

    parts: dict[tuple[str, str], list[str]] = field(default_factory=lambda: defaultdict(list))

    def add(self, source: str, target: str, part: str = "") -> None:
        bucket = self.parts[(source, target)]
        if part and part not in bucket:
            bucket.append(part)


class GraphBuilder:
    """Строит :class:`Graph` из списка ресурсов."""

    def __init__(self, resources: Iterable[Resource], domain: str = DEFAULT_DOMAIN) -> None:
        self.domain = normalize(domain) or DEFAULT_DOMAIN
        self.resources = list(resources)
        self.graph = Graph()
        self._labels = _EdgeLabels()
        self._by_kind: dict[str, list[Resource]] = defaultdict(list)
        for res in self.resources:
            self._by_kind[res.kind].append(res)
        self._services: dict[str, Resource] = {
            make_key("Service", r.namespace, r.name): r for r in self._by_kind["Service"]
        }
        self._slices: dict[tuple[str, str], list[Resource]] = defaultdict(list)
        for es in self._by_kind["EndpointSlice"]:
            svc_name = es.labels.get(SERVICE_NAME_LABEL)
            if svc_name:
                self._slices[(es.namespace, svc_name)].append(es)

    LINKERS: tuple[tuple[str, str], ...] = (
        ("Gateway", "_link_gateway"),
        ("VirtualService", "_link_virtualservice"),
        ("DestinationRule", "_link_destinationrule"),
        ("Route", "_link_route"),
        ("Service", "_link_service"),
    )

    # --- общие помощники ----------------------------------------------

    def build(self) -> Graph:
        """Построить граф."""
        for res in sorted(self.resources, key=lambda r: node_sort_key(r.kind, r.namespace, r.name)):
            self.graph.add_node(Node(res.key, res.kind, res.namespace, res.name, resource=res))
        for kind, method in self.LINKERS:
            linker: Callable[[Resource], None] = getattr(self, method)
            for res in self._by_kind.get(kind, []):
                linker(res)
        for (source, target), parts in self._labels.parts.items():
            self.graph.add_edge(source, target, ", ".join(parts))
        return self.graph

    def _node(self, res: Resource) -> Node:
        return self.graph.nodes[res.key]

    def _ensure_missing(self, kind: str, namespace: str, name: str, referrer: str) -> Node:
        """Узел для несуществующего ресурса (ключ по ожидаемому имени)."""
        key = make_key(kind, namespace, name)
        node = self.graph.nodes.get(key)
        if node is None:
            node = self.graph.add_node(Node(key, kind, namespace, name, missing=True))
            node.add_badge("не найден")
        if node.missing:
            node.add_problem(f"{kind} {namespace}/{name} не найден (ссылка из {referrer})")
        return node

    def _link(self, source: str, target: str, label: str = "") -> None:
        self._labels.add(source, target, label)

    # --- Gateway ---------------------------------------------------------

    def _link_gateway(self, gw: Resource) -> None:
        node = self._node(gw)
        for server in gw.spec.get("servers") or []:
            if not isinstance(server, dict):
                continue
            port = (server.get("port") or {}).get("number")
            for raw_host in server.get("hosts") or []:
                _ns, host = split_ns_host(str(raw_host))
                host = normalize(host)
                if host not in node.hosts:
                    node.hosts.append(host)
                node.add_badge(f"{host}:{port}" if port else host)
            if (server.get("tls") or {}).get("mode"):
                node.add_badge(f"tls {server['tls']['mode']}")

    # --- VirtualService -------------------------------------------------

    def _link_virtualservice(self, vs: Resource) -> None:
        node = self._node(vs)
        for host in vs.spec.get("hosts") or []:
            h = normalize(str(host))
            if h not in node.hosts:
                node.hosts.append(h)
            node.add_badge(h)
        gateways = vs.spec.get("gateways")
        if not gateways:
            node.add_badge("mesh")  # по умолчанию VS применяется к mesh
        for ref in gateways or []:
            ref = str(ref).strip()
            if ref == "mesh":
                node.add_badge("mesh")
                continue
            ns, name = ref.split("/", 1) if "/" in ref else (vs.namespace, ref)
            key = make_key("Gateway", ns, name)
            if key not in self.graph.nodes or self.graph.nodes[key].missing:
                self._ensure_missing("Gateway", ns, name, f"VirtualService {vs.namespace}/{vs.name}")
            self._link(key, vs.key)
        for dest in self._destinations(vs):
            self._link_destination(vs, dest)

    def _destinations(self, vs: Resource) -> list[_Destination]:
        result: list[_Destination] = []
        for section in ROUTE_SECTIONS:
            for rule in vs.spec.get(section) or []:
                if not isinstance(rule, dict):
                    continue
                for route in rule.get("route") or []:
                    dest = (route or {}).get("destination") or {}
                    host = dest.get("host")
                    if not host:
                        continue
                    result.append(
                        _Destination(
                            host=str(host),
                            fqdn=to_fqdn(str(host), vs.namespace, self.domain),
                            subset=dest.get("subset"),
                            port=(dest.get("port") or {}).get("number"),
                            weight=route.get("weight"),
                            section=section,
                        )
                    )
        return result

    def _link_destination(self, vs: Resource, dest: _Destination) -> None:
        referrer = f"VirtualService {vs.namespace}/{vs.name}"
        label_parts = []
        if dest.subset:
            label_parts.append(dest.subset)
        if dest.port:
            label_parts.append(f":{dest.port}")
        if dest.weight is not None:
            label_parts.append(f"{dest.weight}%")
        if dest.section != "http":
            label_parts.append(dest.section)
        label = " ".join(label_parts)

        target_key = self._target_for_host(dest.fqdn, referrer)
        self._link(vs.key, target_key, label)

        drs = self._find_destination_rules(dest.fqdn)
        for dr in drs:
            mark = ""
            if dest.subset:
                ok = self._check_subset(dr, dest.subset, referrer)
                mark = f"{dest.subset} {'✓' if ok else '✗'}"
            self._link(vs.key, dr.key, mark)
        if dest.subset and not drs:
            split = split_service_fqdn(dest.fqdn, self.domain)
            ns, name = split if split else (vs.namespace, dest.host.split(".")[0])
            node = self._ensure_missing("DestinationRule", ns, name, referrer)
            node.add_problem(f"subset {dest.subset} указан, но DestinationRule для {dest.fqdn} нет")
            node.add_badge(f"subset {dest.subset} ✗")
            self._link(vs.key, node.key, f"{dest.subset} ✗")

    def _target_for_host(self, fqdn: str, referrer: str) -> str:
        """Ключ узла Service (существующего или missing) либо ExternalHost."""
        if is_cluster_host(fqdn, self.domain):
            split = split_service_fqdn(fqdn, self.domain)
            if split:
                ns, name = split
                key = make_key("Service", ns, name)
                if key in self._services:
                    return key
                return self._ensure_missing("Service", ns, name, referrer).key
        key = make_key("ExternalHost", EXTERNAL_NS, fqdn)
        node = self.graph.nodes.get(key)
        if node is None:
            node = self.graph.add_node(Node(key, "ExternalHost", EXTERNAL_NS, fqdn))
            node.hosts.append(fqdn)
            node.add_badge("external")
        return key

    def _find_destination_rules(self, fqdn: str) -> list[Resource]:
        """DR, чей host совпадает с FQDN; точные совпадения приоритетнее wildcard."""
        exact: list[Resource] = []
        wild: list[Resource] = []
        for dr in self._by_kind.get("DestinationRule", []):
            host = dr.spec.get("host")
            if not host:
                continue
            dr_fqdn = to_fqdn(str(host), dr.namespace, self.domain)
            if dr_fqdn == fqdn:
                exact.append(dr)
            elif "*" in dr_fqdn and match_host(dr_fqdn, fqdn):
                wild.append(dr)
        return exact or wild

    def _check_subset(self, dr: Resource, subset: str, referrer: str) -> bool:
        """Проверить subset в DR; добавить бейдж ✓/✗. Вернуть True, если subset есть."""
        node = self._node(dr)
        names = {str((s or {}).get("name")) for s in dr.spec.get("subsets") or []}
        if subset in names:
            node.add_badge(f"subset {subset} ✓")
            return True
        node.add_badge(f"subset {subset} ✗")
        node.add_problem(f"subset {subset} отсутствует в DestinationRule (ссылка из {referrer})")
        return False

    # --- DestinationRule ------------------------------------------------

    def _link_destinationrule(self, dr: Resource) -> None:
        node = self._node(dr)
        host = dr.spec.get("host")
        if host:
            fqdn = to_fqdn(str(host), dr.namespace, self.domain)
            node.hosts.append(fqdn)
            node.add_badge(f"host {fqdn}")
        else:
            node.add_problem("не задан spec.host")

    # --- Route (OpenShift) ----------------------------------------------

    def _link_route(self, route: Resource) -> None:
        node = self._node(route)
        host = route.spec.get("host")
        if host:
            h = normalize(str(host))
            node.hosts.append(h)
            node.add_badge(h + (route.spec.get("path") or ""))
        tls = route.spec.get("tls") or {}
        if tls.get("termination"):
            node.add_badge(f"tls {tls['termination']}")
        referrer = f"Route {route.namespace}/{route.name}"
        port = (route.spec.get("port") or {}).get("targetPort")
        backends = [route.spec.get("to") or {}] + list(route.spec.get("alternateBackends") or [])
        for backend in backends:
            if not isinstance(backend, dict) or not backend.get("name"):
                continue
            if backend.get("kind", "Service") != "Service":
                continue
            key = make_key("Service", route.namespace, str(backend["name"]))
            if key not in self._services:
                key = self._ensure_missing("Service", route.namespace, str(backend["name"]), referrer).key
            parts = []
            if port is not None:
                parts.append(f":{port}")
            if backend.get("weight") is not None:
                parts.append(f"w{backend['weight']}")
            self._link(route.key, key, " ".join(parts))

    # --- Service → EndpointSlice ----------------------------------------

    def _link_service(self, svc: Resource) -> None:
        node = self._node(svc)
        ports = [
            f"{p.get('port')}/{p.get('protocol', 'TCP')}"
            for p in svc.spec.get("ports") or []
            if isinstance(p, dict)
        ]
        if ports:
            node.add_badge(" ".join(ports))
        if svc.spec.get("type") == "ExternalName":
            node.add_badge(f"ExternalName → {svc.spec.get('externalName')}")
            return
        slices = self._slices.get((svc.namespace, svc.name), [])
        if not slices:
            node.add_badge("нет endpoints")
            node.add_problem("у Service нет EndpointSlice")
            return
        total_ready = 0
        for es in slices:
            ready = _ready_count(es.raw)
            total_ready += ready
            es_node = self._node(es)
            es_node.add_badge(f"{ready} ready")
            not_ready = len(es.raw.get("endpoints") or []) - ready
            if not_ready:
                es_node.add_badge(f"{not_ready} not ready")
            self._link(svc.key, es.key)
        if total_ready == 0:
            node.add_badge("0 ready")
            node.add_problem("нет ни одного ready endpoint")


def _ready_count(slice_obj: dict[str, Any]) -> int:
    """Число endpoints с ``conditions.ready`` (отсутствие условия трактуется как ready)."""
    count = 0
    for ep in slice_obj.get("endpoints") or []:
        ready = ((ep or {}).get("conditions") or {}).get("ready")
        if ready is None or ready is True:
            count += 1
    return count


def build_graph(resources: Iterable[Resource], domain: str = DEFAULT_DOMAIN) -> Graph:
    """Построить граф связей из ресурсов."""
    return GraphBuilder(resources, domain).build()

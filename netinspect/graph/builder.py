"""Построение графа связей сетевых ресурсов.

Направление рёбер — по движению трафика::

    Gateway → VirtualService → Subset (подмножество DestinationRule) → Service / ServiceEntry / ExternalHost → EndpointSlice
                             → DestinationRule (если subset не указан)
    Route → Service
    DestinationRule ─содержит→ Subset
    EnvoyFilter ─применяется→ Gateway / Service / Subset

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
from netinspect.core.model import (
    EDGE_CONTAINS,
    EDGE_POLICY,
    EDGE_TRAFFIC,
    Graph,
    Node,
    Resource,
    make_key,
)

SERVICE_NAME_LABEL = "kubernetes.io/service-name"
EXTERNAL_NS = "-"
ROUTE_SECTIONS = ("http", "tcp", "tls")
#: Корневой namespace Istio: EnvoyFilter без selector здесь действует на весь mesh.
ROOT_NAMESPACES = frozenset({"istio-system"})
SUBSET_KIND = "Subset"

#: Порядок колонок (по направлению трафика) — общий для рендеров.
KIND_COLUMN: dict[str, int] = {
    "EnvoyFilter": 0,
    "Gateway": 1,
    "Route": 1,
    "VirtualService": 2,
    "DestinationRule": 3,
    SUBSET_KIND: 4,
    "Service": 5,
    "ServiceEntry": 5,
    "ExternalHost": 5,
    "EndpointSlice": 6,
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
    kinds: dict[tuple[str, str], str] = field(default_factory=dict)

    def add(self, source: str, target: str, part: str = "", kind: str = EDGE_TRAFFIC) -> None:
        bucket = self.parts[(source, target)]
        self.kinds.setdefault((source, target), kind)
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
        #: Хосты ServiceEntry: (нормализованный хост, ресурс).
        self._se_hosts: list[tuple[str, Resource]] = [
            (normalize(str(h)), se)
            for se in self._by_kind["ServiceEntry"]
            for h in se.spec.get("hosts") or []
            if str(h).strip()
        ]
        #: Использованные маршрутами VirtualService subset-узлы.
        self._used_subsets: set[str] = set()

    #: Порядок важен: subset-узлы и ServiceEntry должны существовать до разбора VirtualService.
    LINKERS: tuple[tuple[str, str], ...] = (
        ("Gateway", "_link_gateway"),
        ("ServiceEntry", "_link_serviceentry"),
        ("DestinationRule", "_link_destinationrule"),
        ("VirtualService", "_link_virtualservice"),
        ("Route", "_link_route"),
        ("Service", "_link_service"),
        ("EnvoyFilter", "_link_envoyfilter"),
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
        self._finalize()
        for (source, target), parts in self._labels.parts.items():
            kind = self._labels.kinds.get((source, target), EDGE_TRAFFIC)
            self.graph.add_edge(source, target, ", ".join(parts), kind)
        return self.graph

    def _finalize(self) -> None:
        """Проверки, которым нужен весь граф: неиспользуемые subset."""
        for node in self.graph.nodes.values():
            if node.kind == SUBSET_KIND and not node.missing and node.key not in self._used_subsets:
                node.add_badge("не используется")

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

    def _link(self, source: str, target: str, label: str = "", kind: str = EDGE_TRAFFIC) -> None:
        self._labels.add(source, target, label, kind)

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
        """Связать VirtualService с назначением маршрута.

        - subset указан и найден в DR: VS → Subset → Service/ServiceEntry (DR связан с subset);
        - subset указан, но в DR его нет: VS → DR (с пометкой ✗) и VS → Service;
        - subset не указан: VS → Service и VS → DR (политики DR применяются к хосту).
        """
        referrer = f"VirtualService {vs.namespace}/{vs.name}"
        label_parts = []
        if dest.port:
            label_parts.append(f":{dest.port}")
        if dest.weight is not None:
            label_parts.append(f"{dest.weight}%")
        if dest.section != "http":
            label_parts.append(dest.section)
        label = " ".join(label_parts)

        target_key = self._target_for_host(dest.fqdn, referrer)
        drs = self._find_destination_rules(dest.fqdn)

        if not dest.subset:
            self._link(vs.key, target_key, label)
            for dr in drs:
                self._link(vs.key, dr.key)
            return

        routed = False
        for dr in drs:
            if self._check_subset(dr, dest.subset, referrer):
                subset_key = self._subset_key(dr, dest.subset)
                self._used_subsets.add(subset_key)
                self._link(vs.key, subset_key, label)
                self._link(subset_key, target_key)
                routed = True
            else:
                self._link(vs.key, dr.key, f"{dest.subset} ✗")
        if not routed:
            self._link(vs.key, target_key, " ".join([dest.subset, label]).strip())
        if not drs:
            split = split_service_fqdn(dest.fqdn, self.domain)
            ns, name = split if split else (vs.namespace, dest.host.split(".")[0])
            node = self._ensure_missing("DestinationRule", ns, name, referrer)
            node.add_problem(f"subset {dest.subset} указан, но DestinationRule для {dest.fqdn} нет")
            node.add_badge(f"subset {dest.subset} ✗")
            self._link(vs.key, node.key, f"{dest.subset} ✗")

    def _find_service_entry(self, fqdn: str) -> Resource | None:
        """ServiceEntry, объявляющий хост: точное совпадение приоритетнее wildcard."""
        wildcard: Resource | None = None
        for host, se in self._se_hosts:
            if host == fqdn:
                return se
            if wildcard is None and "*" in host and match_host(host, fqdn):
                wildcard = se
        return wildcard

    def _target_for_host(self, fqdn: str, referrer: str) -> str:
        """Ключ узла назначения: Service, ServiceEntry, заглушка «не найден» или ExternalHost."""
        cluster = is_cluster_host(fqdn, self.domain)
        split = split_service_fqdn(fqdn, self.domain) if cluster else None
        if split:
            key = make_key("Service", split[0], split[1])
            if key in self._services:
                return key
        se = self._find_service_entry(fqdn)
        if se is not None:
            return se.key
        if split:
            return self._ensure_missing("Service", split[0], split[1], referrer).key
        key = make_key("ExternalHost", EXTERNAL_NS, fqdn)
        node = self.graph.nodes.get(key)
        if node is None:
            node = self.graph.add_node(Node(key, "ExternalHost", EXTERNAL_NS, fqdn))
            node.hosts.append(fqdn)
            node.add_badge("external")
            node.add_badge("нет ServiceEntry")
        return key

    def _existing_target(self, fqdn: str) -> str | None:
        """Существующий Service или ServiceEntry для хоста (без создания узлов)."""
        split = split_service_fqdn(fqdn, self.domain) if is_cluster_host(fqdn, self.domain) else None
        if split:
            key = make_key("Service", split[0], split[1])
            if key in self._services:
                return key
        se = self._find_service_entry(fqdn)
        return se.key if se is not None else None

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

    # --- DestinationRule и subsets --------------------------------------

    @staticmethod
    def _subset_key(dr: Resource, subset: str) -> str:
        return make_key(SUBSET_KIND, dr.namespace, f"{dr.name}:{subset}")

    def _link_destinationrule(self, dr: Resource) -> None:
        node = self._node(dr)
        host = dr.spec.get("host")
        fqdn = to_fqdn(str(host), dr.namespace, self.domain) if host else ""
        target: str | None = None
        if not host:
            node.add_problem("не задан spec.host")
        else:
            node.hosts.append(fqdn)
            node.add_badge(f"host {fqdn}")
            if "*" not in fqdn:
                target = self._existing_target(fqdn)
                if target is None and is_cluster_host(fqdn, self.domain):
                    node.add_problem(f"host {fqdn}: Service или ServiceEntry с таким именем не найден")
        tls_mode = ((dr.spec.get("trafficPolicy") or {}).get("tls") or {}).get("mode")
        if tls_mode:
            node.add_badge(f"tls {tls_mode}")
        seen: set[str] = set()
        for subset in dr.spec.get("subsets") or []:
            if not isinstance(subset, dict) or not subset.get("name"):
                node.add_problem("subset без имени")
                continue
            name = str(subset["name"])
            if name in seen:
                node.add_problem(f"subset {name} объявлен дважды")
                continue
            seen.add(name)
            self._add_subset_node(dr, subset, target)

    def _add_subset_node(self, dr: Resource, subset: dict[str, Any], target: str | None) -> None:
        """Узел-subset: метки подов, своя trafficPolicy; связи DR → subset → сервис."""
        name = str(subset["name"])
        key = self._subset_key(dr, name)
        res = Resource(kind=SUBSET_KIND, namespace=dr.namespace, name=f"{dr.name}:{name}", spec=subset, raw=subset)
        sub_node = self.graph.add_node(Node(key, SUBSET_KIND, dr.namespace, res.name, resource=res))
        labels = subset.get("labels") or {}
        if labels:
            for k, v in labels.items():
                sub_node.add_badge(f"{k}={v}")
        else:
            sub_node.add_badge("без меток: все поды")
        if subset.get("trafficPolicy"):
            sub_node.add_badge("своя trafficPolicy")
        self._link(dr.key, key, name, EDGE_CONTAINS)
        if target:
            self._link(key, target)

    # --- ServiceEntry ---------------------------------------------------

    def _link_serviceentry(self, se: Resource) -> None:
        node = self._node(se)
        hosts = [normalize(str(h)) for h in se.spec.get("hosts") or [] if str(h).strip()]
        for h in hosts:
            node.hosts.append(h)
            node.add_badge(h)
        if not hosts:
            node.add_problem("не заданы hosts")
        ports = [p for p in se.spec.get("ports") or [] if isinstance(p, dict)]
        for p in ports:
            node.add_badge(f"{p.get('number')}/{p.get('protocol', 'TCP')}")
        if not ports:
            node.add_problem("не заданы ports")
        location = se.spec.get("location") or "MESH_EXTERNAL"
        node.add_badge("внешний" if location == "MESH_EXTERNAL" else "внутренний")
        resolution = str(se.spec.get("resolution") or "NONE")
        node.add_badge(f"resolution {resolution}")
        endpoints = se.spec.get("endpoints") or []
        if endpoints:
            node.add_badge(f"{len(endpoints)} endpoints")
        has_selector = bool(se.spec.get("workloadSelector"))
        if resolution == "STATIC" and not endpoints and not has_selector:
            node.add_problem("resolution STATIC, но не заданы endpoints (или workloadSelector)")
        if resolution in ("DNS", "DNS_ROUND_ROBIN") and not endpoints:
            for h in hosts:
                if "*" in h:
                    node.add_problem(f"resolution {resolution} не работает с wildcard-хостом {h} без endpoints")

    # --- EnvoyFilter ----------------------------------------------------

    def _link_envoyfilter(self, ef: Resource) -> None:
        node = self._node(ef)
        for patch in ef.spec.get("configPatches") or []:
            if not isinstance(patch, dict):
                continue
            apply_to = patch.get("applyTo") or "?"
            context = (patch.get("match") or {}).get("context") or "ANY"
            operation = (patch.get("patch") or {}).get("operation") or ""
            node.add_badge(f"{apply_to} @ {context}" + (f" ({operation})" if operation else ""))
        if not ef.spec.get("configPatches"):
            node.add_problem("нет configPatches — фильтр ничего не меняет")
        if ef.spec.get("priority") is not None:
            node.add_badge(f"priority {ef.spec['priority']}")
        if ef.spec.get("targetRefs"):
            node.add_badge("targetRefs")
            return
        selector = (ef.spec.get("workloadSelector") or {}).get("labels") or {}
        selector = {str(k): str(v) for k, v in selector.items()}
        if not selector:
            node.add_badge("весь mesh" if ef.namespace in ROOT_NAMESPACES else f"весь namespace {ef.namespace}")
            return
        for k, v in selector.items():
            node.add_badge(f"{k}={v}")
        any_ns = ef.namespace in ROOT_NAMESPACES
        matched = 0
        # Gateway: поды шлюза обычно в другом namespace, поэтому сверяем только метки
        for gw in self._by_kind.get("Gateway", []):
            gw_sel = {str(k): str(v) for k, v in (gw.spec.get("selector") or {}).items()}
            if gw_sel and _subset_of(selector, gw_sel):
                self._link(ef.key, gw.key, "фильтр", EDGE_POLICY)
                matched += 1
        for svc in self._by_kind.get("Service", []):
            if not any_ns and svc.namespace != ef.namespace:
                continue
            svc_sel = {str(k): str(v) for k, v in (svc.spec.get("selector") or {}).items()}
            if not svc_sel:
                continue
            if _subset_of(selector, svc_sel):
                self._link(ef.key, svc.key, "фильтр", EDGE_POLICY)
                matched += 1
                continue
            # метки сверх selector сервиса — ищем subset, чьи поды их несут
            for sub_key, sub_labels in self._subsets_of_service(svc.key):
                if _subset_of(selector, {**svc_sel, **sub_labels}):
                    self._link(ef.key, sub_key, "фильтр", EDGE_POLICY)
                    matched += 1
        if not matched:
            node.add_problem(
                "workloadSelector "
                + ", ".join(f"{k}={v}" for k, v in selector.items())
                + " не совпадает ни с одним Gateway, Service или subset"
            )

    def _subsets_of_service(self, svc_key: str) -> list[tuple[str, dict[str, str]]]:
        """Subset-узлы, ведущие в сервис, с их метками."""
        result = []
        for (source, target), _parts in self._labels.parts.items():
            if target == svc_key and source.startswith(SUBSET_KIND + "/"):
                sub = self.graph.nodes[source]
                labels = (sub.resource.spec.get("labels") if sub.resource else None) or {}
                result.append((source, {str(k): str(v) for k, v in labels.items()}))
        return result

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


def _subset_of(small: dict[str, str], big: dict[str, str]) -> bool:
    """Все метки ``small`` есть в ``big`` с теми же значениями."""
    return all(big.get(k) == v for k, v in small.items())


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

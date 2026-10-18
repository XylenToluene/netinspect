"""Реестр типов ресурсов. Новый тип добавляется одной записью в ``REGISTRY``."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ResourceType:
    """Описание типа ресурса Kubernetes."""

    kind: str
    group: str
    versions: tuple[str, ...]
    plural: str
    short_names: tuple[str, ...] = ()
    #: Тип загружается, только если его API группа есть в кластере.
    optional: bool = False

    @property
    def is_core(self) -> bool:
        """Ресурс core API (``/api/v1``)."""
        return self.group == ""

    def path(self, version: str, namespace: str | None = None) -> str:
        """Путь списка ресурсов в API: по namespace или по всем."""
        base = f"/api/{version}" if self.is_core else f"/apis/{self.group}/{version}"
        if namespace:
            return f"{base}/namespaces/{namespace}/{self.plural}"
        return f"{base}/{self.plural}"


REGISTRY: tuple[ResourceType, ...] = (
    ResourceType("Gateway", "networking.istio.io", ("v1", "v1beta1"), "gateways", ("gw",)),
    ResourceType("VirtualService", "networking.istio.io", ("v1", "v1beta1"), "virtualservices", ("vs",)),
    ResourceType("DestinationRule", "networking.istio.io", ("v1", "v1beta1"), "destinationrules", ("dr",)),
    ResourceType("Service", "", ("v1",), "services", ("svc",)),
    ResourceType("EndpointSlice", "discovery.k8s.io", ("v1",), "endpointslices", ("eps", "endpointslice")),
    ResourceType("Route", "route.openshift.io", ("v1",), "routes", ("route", "rt"), optional=True),
)

#: Ресурсы, которые не загружаются никогда.
FORBIDDEN_KINDS: frozenset[str] = frozenset({"Secret"})


def all_kinds() -> list[str]:
    """Все kind'ы реестра в порядке объявления."""
    return [rt.kind for rt in REGISTRY]


def get_type(kind: str) -> ResourceType:
    """Найти тип по kind; ``KeyError``, если нет."""
    for rt in REGISTRY:
        if rt.kind == kind:
            return rt
    raise KeyError(kind)


def resolve_kind(name: str) -> str:
    """Разрешить имя типа (kind, plural, короткое имя; без учёта регистра) в kind.

    ``ValueError``, если тип неизвестен.
    """
    n = name.strip().lower()
    for rt in REGISTRY:
        candidates = {rt.kind.lower(), rt.plural, rt.plural.rstrip("s"), *rt.short_names}
        if n in candidates:
            return rt.kind
    known = ", ".join(f"{rt.kind} ({'/'.join(rt.short_names)})" for rt in REGISTRY)
    raise ValueError(f"неизвестный тип ресурса: {name}. Известные: {known}")

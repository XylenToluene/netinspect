"""Нормализация хостов Istio/Kubernetes и сопоставление с wildcard.

Правила Istio для коротких имён: хост интерпретируется относительно namespace
ресурса, в котором он указан (VirtualService, DestinationRule).
"""

from __future__ import annotations

DEFAULT_DOMAIN = "cluster.local"


def normalize(host: str) -> str:
    """Привести хост к нижнему регистру, убрать пробелы и завершающую точку."""
    return host.strip().lower().rstrip(".")


def to_fqdn(host: str, namespace: str, domain: str = DEFAULT_DOMAIN) -> str:
    """Развернуть короткое имя сервиса в FQDN.

    - ``reviews`` → ``reviews.<namespace>.svc.<domain>``
    - ``reviews.prod`` → ``reviews.prod.svc.<domain>``
    - ``reviews.prod.svc`` → ``reviews.prod.svc.<domain>``
    - полный FQDN, внешние хосты и wildcard не меняются (кроме регистра и точки).
    """
    h = normalize(host)
    dom = normalize(domain)
    if not h or h == "*":
        return h
    if h.endswith(".svc." + dom):
        return h
    if "*" in h:
        return h
    parts = h.split(".")
    if len(parts) == 1:
        return f"{h}.{normalize(namespace)}.svc.{dom}"
    if len(parts) == 2:
        return f"{h}.svc.{dom}"
    if len(parts) == 3 and parts[2] == "svc":
        return f"{h}.{dom}"
    return h


def is_cluster_host(fqdn: str, domain: str = DEFAULT_DOMAIN) -> bool:
    """True, если хост (в FQDN) относится к сервисам кластера ``*.svc.<domain>``."""
    return normalize(fqdn).endswith(".svc." + normalize(domain))


def split_service_fqdn(fqdn: str, domain: str = DEFAULT_DOMAIN) -> tuple[str, str] | None:
    """Разобрать ``name.ns.svc.<domain>`` в ``(namespace, name)``; иначе ``None``."""
    h = normalize(fqdn)
    suffix = ".svc." + normalize(domain)
    if not h.endswith(suffix):
        return None
    head = h[: -len(suffix)]
    parts = head.split(".")
    if len(parts) != 2 or not all(parts):
        return None
    name, ns = parts
    return ns, name


def service_fqdn(name: str, namespace: str, domain: str = DEFAULT_DOMAIN) -> str:
    """FQDN сервиса: ``name.namespace.svc.<domain>``."""
    return f"{normalize(name)}.{normalize(namespace)}.svc.{normalize(domain)}"


def split_ns_host(value: str) -> tuple[str | None, str]:
    """Разобрать хост Gateway в формате ``ns/host``.

    Возвращает ``(namespace | None, host)``; ``./host`` и ``*/host`` дают
    namespace ``"."`` и ``"*"`` соответственно.
    """
    if "/" in value:
        ns, host = value.split("/", 1)
        return ns.strip() or None, host
    return None, value


def match_host(pattern: str, host: str) -> bool:
    """Сопоставить хост с шаблоном.

    - ``*`` совпадает с любым хостом;
    - ``*.example.com`` совпадает с ``a.example.com`` и ``a.b.example.com``,
      но не с ``example.com``;
    - иначе — точное совпадение без учёта регистра и завершающей точки.

    Если ``host`` сам является wildcard (``*.example.com``), он считается
    совпадающим, когда его домен покрывается шаблоном.
    """
    p = normalize(pattern)
    h = normalize(host)
    if not p or not h:
        return False
    if p == "*":
        return True
    if p.startswith("*."):
        suffix = p[1:]  # ".example.com"
        if h.startswith("*."):
            return h == p or h[1:].endswith(suffix)
        return h.endswith(suffix) and len(h) > len(suffix)
    if h.startswith("*."):
        # хост-шаблон против конкретного имени: обратное сопоставление
        return match_host(h, p)
    return p == h


def hosts_intersect(a: str, b: str) -> bool:
    """True, если два хоста (каждый может быть wildcard) пересекаются."""
    return match_host(a, b) or match_host(b, a)

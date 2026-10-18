"""Discovery API: доступные версии Istio, признак OpenShift."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from netinspect.core.client import ApiClient
from netinspect.core.errors import ApiError, AuthError, NotFoundError
from netinspect.core.resources import REGISTRY, ResourceType

log = logging.getLogger(__name__)


@dataclass(slots=True)
class ClusterInfo:
    """Результат discovery: выбранная версия для каждой API группы."""

    #: group → выбранная версия (для групп, которые есть в кластере).
    group_versions: dict[str, str] = field(default_factory=dict)
    #: group → все версии, объявленные сервером.
    served: dict[str, list[str]] = field(default_factory=dict)
    is_openshift: bool = False

    def version_for(self, rt: ResourceType) -> str | None:
        """Версия для типа ресурса или ``None``, если API нет в кластере."""
        if rt.is_core:
            return rt.versions[0]
        return self.group_versions.get(rt.group)

    @property
    def istio_version(self) -> str | None:
        """Выбранная версия ``networking.istio.io``."""
        return self.group_versions.get("networking.istio.io")


def _served_versions(client: ApiClient, group: str) -> list[str] | None:
    try:
        data = client.get(f"/apis/{group}")
    except NotFoundError:
        return None
    return [v.get("version") for v in data.get("versions") or [] if v.get("version")]


def discover(client: ApiClient) -> ClusterInfo:
    """Выполнить discovery для всех групп реестра."""
    info = ClusterInfo()
    groups: dict[str, tuple[str, ...]] = {}
    for rt in REGISTRY:
        if not rt.is_core:
            groups.setdefault(rt.group, rt.versions)
    for group, preferred in groups.items():
        try:
            served = _served_versions(client, group)
        except ApiError as exc:
            log.warning("discovery %s: %s", group, exc)
            continue
        if served is None:
            log.info("API группа %s отсутствует в кластере", group)
            continue
        info.served[group] = served
        chosen = next((v for v in preferred if v in served), None)
        if chosen:
            info.group_versions[group] = chosen
        else:
            log.warning("для %s нет поддерживаемой версии (сервер: %s)", group, served)
    info.is_openshift = "route.openshift.io" in info.served
    return info


#: Группы API, ресурсы которых показываются при проверке подключения.
#: Istio определяется по суффиксу группы, поэтому новые CRD Istio подхватываются сами.
ISTIO_GROUP_SUFFIX = ".istio.io"
EXTRA_GROUPS: dict[str, tuple[str, ...]] = {
    "": ("services",),
    "discovery.k8s.io": ("endpointslices",),
    "route.openshift.io": ("routes",),
}


@dataclass(slots=True)
class ApiResource:
    """Тип ресурса, найденный через discovery API кластера."""

    group: str
    version: str
    kind: str
    plural: str
    namespaced: bool
    verbs: list[str] = field(default_factory=list)

    @property
    def is_istio(self) -> bool:
        """Ресурс Istio (группа ``*.istio.io``)."""
        return self.group.endswith(ISTIO_GROUP_SUFFIX)

    @property
    def group_version(self) -> str:
        """``group/version`` или ``version`` для core API."""
        return f"{self.group}/{self.version}" if self.group else self.version


def _resources_at(client: ApiClient, path: str, group: str, version: str) -> list[ApiResource]:
    data = client.get(path)
    result = []
    for item in data.get("resources") or []:
        name = str(item.get("name") or "")
        if not name or "/" in name:  # подресурсы вида virtualservices/status
            continue
        result.append(
            ApiResource(
                group=group,
                version=version,
                kind=str(item.get("kind") or name),
                plural=name,
                namespaced=bool(item.get("namespaced")),
                verbs=[str(v) for v in item.get("verbs") or []],
            )
        )
    return result


def discover_api_resources(client: ApiClient) -> tuple[list[ApiResource], list[str]]:
    """Найти в кластере все ресурсы Istio (``*.istio.io``) и базовые сетевые ресурсы.

    Берётся предпочтительная версия каждой группы. Возвращает ``(ресурсы, предупреждения)``;
    недоступная группа не прерывает discovery.
    """
    warnings: list[str] = []
    resources: list[ApiResource] = []
    groups = client.get("/apis").get("groups") or []
    targets: list[tuple[str, str]] = [("", "v1")]
    for g in groups:
        name = str(g.get("name") or "")
        if name.endswith(ISTIO_GROUP_SUFFIX) or name in EXTRA_GROUPS:
            preferred = (g.get("preferredVersion") or {}).get("version")
            if not preferred and g.get("versions"):
                preferred = g["versions"][0].get("version")
            if preferred:
                targets.append((name, str(preferred)))
    for group, version in targets:
        path = f"/api/{version}" if not group else f"/apis/{group}/{version}"
        try:
            found = _resources_at(client, path, group, version)
        except AuthError:
            raise
        except ApiError as exc:
            warnings.append(f"{group or 'core'}/{version}: {exc}")
            continue
        wanted = EXTRA_GROUPS.get(group)
        resources.extend(r for r in found if wanted is None or r.plural in wanted)
    resources.sort(key=lambda r: (not r.is_istio, r.group, r.kind))
    return resources, warnings

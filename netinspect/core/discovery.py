"""Discovery API: доступные версии Istio, признак OpenShift."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from netinspect.core.client import ApiClient
from netinspect.core.errors import ApiError, NotFoundError
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

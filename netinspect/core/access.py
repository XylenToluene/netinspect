"""Проверка прав: whoami, версия кластера, SelfSubjectAccessReview."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from netinspect.core.client import ApiClient
from netinspect.core.discovery import ApiResource, discover_api_resources
from netinspect.core.errors import ApiError, NotFoundError
from netinspect.core.resources import REGISTRY, ResourceType

SSAR_PATH = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"


@dataclass(slots=True)
class AccessResult:
    """Результат проверки права ``verb`` на тип ресурса."""

    kind: str
    resource: str
    namespace: str | None
    allowed: bool
    reason: str = ""


def cluster_version(client: ApiClient) -> str:
    """Версия кластера из ``/version`` (``gitVersion``)."""
    data = client.get("/version")
    return str(data.get("gitVersion") or f"{data.get('major', '?')}.{data.get('minor', '?')}")


def whoami(client: ApiClient) -> str | None:
    """Имя пользователя OpenShift или ``None``, если это не OpenShift (404)."""
    try:
        data = client.get("/apis/user.openshift.io/v1/users/~")
    except NotFoundError:
        return None
    return (data.get("metadata") or {}).get("name")


def can_i(
    client: ApiClient,
    rt: ResourceType | ApiResource,
    verb: str = "list",
    namespace: str | None = None,
) -> AccessResult:
    """Проверить право через SelfSubjectAccessReview."""
    attrs: dict[str, str] = {"verb": verb, "group": rt.group, "resource": rt.plural}
    if namespace:
        attrs["namespace"] = namespace
    body = {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SelfSubjectAccessReview",
        "spec": {"resourceAttributes": attrs},
    }
    try:
        resp = client.post(SSAR_PATH, body)
    except ApiError as exc:
        if exc.status in (401,):
            raise
        return AccessResult(rt.kind, rt.plural, namespace, False, str(exc))
    status = resp.get("status") or {}
    return AccessResult(
        rt.kind,
        rt.plural,
        namespace,
        bool(status.get("allowed")),
        str(status.get("reason") or status.get("evaluationError") or ""),
    )


def check_access(
    client: ApiClient, namespace: str | None = None, verb: str = "list"
) -> list[AccessResult]:
    """Проверить ``verb`` на все типы реестра."""
    return [can_i(client, rt, verb, namespace) for rt in REGISTRY]


#: Параллельных SelfSubjectAccessReview при проверке подключения.
_SSAR_WORKERS = 8


@dataclass(slots=True)
class ConnectionReport:
    """Результат проверки подключения: кластер, пользователь, доступные ресурсы и права."""

    server: str
    version: str
    user: str | None
    openshift: bool
    namespace: str | None
    resources: list[tuple[ApiResource, AccessResult]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def istio_groups(self) -> list[str]:
        """Найденные API группы Istio с версиями."""
        seen: list[str] = []
        for res, _ in self.resources:
            if res.is_istio and res.group_version not in seen:
                seen.append(res.group_version)
        return seen

    def to_dict(self) -> dict[str, Any]:
        """Сериализация для JSON API. Токен сюда не попадает."""
        return {
            "server": self.server,
            "version": self.version,
            "user": self.user,
            "openshift": self.openshift,
            "namespace": self.namespace,
            "istio": bool(self.istio_groups),
            "istioGroups": self.istio_groups,
            "resources": [
                {
                    "group": res.group,
                    "version": res.version,
                    "kind": res.kind,
                    "plural": res.plural,
                    "namespaced": res.namespaced,
                    "istio": res.is_istio,
                    "canList": acc.allowed,
                    "reason": acc.reason,
                }
                for res, acc in self.resources
            ],
            "warnings": list(self.warnings),
        }


def connection_report(client: ApiClient, namespace: str | None = None) -> ConnectionReport:
    """Проверить подключение: версия, пользователь, ресурсы Istio и сетевые ресурсы, права на ``list``.

    Ресурсы Istio берутся из discovery кластера, а не из фиксированного списка.
    ``AuthError``/``TLSError`` и сетевые ошибки пробрасываются — подключения нет.
    """
    version = cluster_version(client)  # первый запрос: проверка доступности и токена
    user = whoami(client)
    resources, warnings = discover_api_resources(client)
    listable = [r for r in resources if not r.verbs or "list" in r.verbs]
    with ThreadPoolExecutor(max_workers=_SSAR_WORKERS) as pool:
        access = list(pool.map(lambda r: can_i(client, r, "list", namespace), listable))
    openshift = user is not None or any(r.group == "route.openshift.io" for r in resources)
    report = ConnectionReport(
        server=client.server,
        version=version,
        user=user,
        openshift=openshift,
        namespace=namespace,
        resources=list(zip(listable, access)),
        warnings=warnings,
    )
    if not report.istio_groups:
        report.warnings.append("API Istio (*.istio.io) в кластере не найдены")
    return report

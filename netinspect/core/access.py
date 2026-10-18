"""Проверка прав: whoami, версия кластера, SelfSubjectAccessReview."""

from __future__ import annotations

from dataclasses import dataclass

from netinspect.core.client import ApiClient
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


def can_i(client: ApiClient, rt: ResourceType, verb: str = "list", namespace: str | None = None) -> AccessResult:
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

"""Фейковый API Kubernetes/OpenShift с Istio для тестов (локальный HTTP, без сети).

Запуск вручную: ``python -m tests.fake_cluster 18443`` (токен ``good-token``).
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

GOOD_TOKEN = "sha256~good-token-0001"

ISTIO_RESOURCES: dict[str, tuple[str, list[tuple[str, str]]]] = {
    "networking.istio.io": (
        "v1",
        [
            ("Gateway", "gateways"),
            ("VirtualService", "virtualservices"),
            ("DestinationRule", "destinationrules"),
            ("ServiceEntry", "serviceentries"),
            ("Sidecar", "sidecars"),
            ("WorkloadEntry", "workloadentries"),
            ("EnvoyFilter", "envoyfilters"),
        ],
    ),
    "security.istio.io": (
        "v1",
        [
            ("AuthorizationPolicy", "authorizationpolicies"),
            ("PeerAuthentication", "peerauthentications"),
            ("RequestAuthentication", "requestauthentications"),
        ],
    ),
    "telemetry.istio.io": ("v1", [("Telemetry", "telemetries")]),
}
OTHER_GROUPS: dict[str, tuple[str, list[tuple[str, str]]]] = {
    "discovery.k8s.io": ("v1", [("EndpointSlice", "endpointslices")]),
    "route.openshift.io": ("v1", [("Route", "routes")]),
    "apps": ("v1", [("Deployment", "deployments")]),
}
CORE: list[tuple[str, str]] = [("Service", "services"), ("Pod", "pods"), ("Secret", "secrets")]

#: Ресурсы, на которые у пользователя нет прав list.
DENIED = {"envoyfilters", "secrets"}


def _resource_list(gv: str, items: list[tuple[str, str]]) -> dict[str, Any]:
    resources = []
    for kind, plural in items:
        resources.append({"name": plural, "kind": kind, "namespaced": True, "verbs": ["get", "list", "watch"]})
        resources.append({"name": plural + "/status", "kind": kind, "namespaced": True, "verbs": ["get"]})
    return {"kind": "APIResourceList", "groupVersion": gv, "resources": resources}


class _Handler(BaseHTTPRequestHandler):
    server: "FakeCluster"

    def log_message(self, *args: Any) -> None:
        pass

    def _send(self, code: int, obj: dict[str, Any]) -> None:
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        self.server.seen_auth.append(self.headers.get("Authorization", ""))
        if self.headers.get("Authorization") != "Bearer " + GOOD_TOKEN:
            self._send(401, {"kind": "Status", "message": "Unauthorized", "code": 401})
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        if not self._authorized():
            return
        path = self.path.split("?")[0]
        groups = {**ISTIO_RESOURCES, **OTHER_GROUPS}
        if path == "/version":
            return self._send(200, {"major": "1", "minor": "29", "gitVersion": "v1.29.7+ocp"})
        if path == "/apis/user.openshift.io/v1/users/~":
            return self._send(200, {"metadata": {"name": "jdoe"}})
        if path == "/apis":
            return self._send(200, {
                "kind": "APIGroupList",
                "groups": [
                    {"name": g, "versions": [{"groupVersion": f"{g}/{v}", "version": v}],
                     "preferredVersion": {"groupVersion": f"{g}/{v}", "version": v}}
                    for g, (v, _) in groups.items()
                ],
            })
        if path == "/api/v1":
            return self._send(200, _resource_list("v1", CORE))
        for g, (v, items) in groups.items():
            if path == f"/apis/{g}/{v}":
                return self._send(200, _resource_list(f"{g}/{v}", items))
            if path == f"/apis/{g}":
                return self._send(200, {"name": g, "versions": [{"version": v}]})
        return self._send(404, {"kind": "Status", "code": 404})

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorized():
            return
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
        if self.path.startswith("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"):
            res = body["spec"]["resourceAttributes"]["resource"]
            allowed = res not in DENIED
            return self._send(201, {"status": {"allowed": allowed, "reason": "" if allowed else "RBAC: access denied"}})
        return self._send(404, {"kind": "Status", "code": 404})


class FakeCluster(ThreadingHTTPServer):
    """Фейковый API в фоновом потоке: ``with FakeCluster() as c: c.url``."""

    daemon_threads = True

    def __init__(self, port: int = 0) -> None:
        super().__init__(("127.0.0.1", port), _Handler)
        self.seen_auth: list[str] = []
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"

    def __enter__(self) -> "FakeCluster":
        self._thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.shutdown()
        self.server_close()


if __name__ == "__main__":
    srv = FakeCluster(int(sys.argv[1]) if len(sys.argv) > 1 else 18443)
    print(f"fake cluster: {srv.url}  token: {GOOD_TOKEN}", flush=True)
    srv.serve_forever()

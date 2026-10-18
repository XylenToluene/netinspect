import io
import json
import ssl
import unittest
import urllib.error
from typing import Any
from unittest import mock

from netinspect.core.access import check_access, cluster_version, whoami
from netinspect.core.client import ApiClient
from netinspect.core.config import ConnectionConfig, build_config, mask_token, resolve_token
from netinspect.core.discovery import discover
from netinspect.core.errors import (
    ApiError,
    AuthError,
    ConfigError,
    ForbiddenError,
    NotFoundError,
    TLSError,
)
from netinspect.core.fetcher import ClusterSource
from netinspect.core.resources import get_type

TOKEN = "sha256~SuperSecretTokenValue1234"
SERVER = "https://api.cluster.example:6443"


class FakeResponse:
    def __init__(self, body: Any) -> None:
        self._data = json.dumps(body).encode()

    def read(self) -> bytes:
        return self._data

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


def http_error(url: str, code: int, body: str = "") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, code, "err", {}, io.BytesIO(body.encode()))  # type: ignore[arg-type]


class FakeOpener:
    """Подмена OpenerDirector.open: маршрутизация по пути запроса."""

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.requests: list[Any] = []

    def __call__(self, req: Any, timeout: float | None = None) -> FakeResponse:
        self.requests.append(req)
        path = req.full_url[len(SERVER):]
        key = path.split("?")[0]
        value = self.routes.get(path, self.routes.get(key))
        if callable(value):
            value = value(req)
        if isinstance(value, BaseException):
            raise value
        if value is None:
            raise http_error(req.full_url, 404)
        return FakeResponse(value)


def make_client(routes: dict[str, Any]) -> tuple[ApiClient, FakeOpener]:
    client = ApiClient(ConnectionConfig(server=SERVER, token=TOKEN))
    opener = FakeOpener(routes)
    client._opener.open = opener  # type: ignore[method-assign]
    return client, opener


class ConfigTest(unittest.TestCase):
    def test_repr_masks_token(self) -> None:
        cfg = ConnectionConfig(server=SERVER, token=TOKEN)
        text = repr(cfg) + str(cfg)
        self.assertNotIn(TOKEN, text)
        self.assertIn("****1234", text)

    def test_mask_short(self) -> None:
        self.assertEqual(mask_token("abc"), "****")
        self.assertEqual(mask_token(None), "<none>")

    def test_server_normalized(self) -> None:
        cfg = ConnectionConfig(server="api.example:6443/", token="t")
        self.assertEqual(cfg.server, "https://api.example:6443")

    def test_token_order(self) -> None:
        env = {"MY_TOKEN": "a", "NETINSPECT_TOKEN": "b"}
        self.assertEqual(resolve_token("MY_TOKEN", env), "a")
        self.assertEqual(resolve_token(None, env), "b")
        self.assertEqual(resolve_token(None, {}, prompt=lambda _p: "c"), "c")
        with self.assertRaises(ConfigError):
            resolve_token("NOPE", env)
        with self.assertRaises(ConfigError):
            resolve_token(None, {}, prompt=lambda _p: "  ")

    def test_build_config_from_env(self) -> None:
        cfg = build_config(None, env={"NETINSPECT_SERVER": SERVER, "NETINSPECT_TOKEN": TOKEN})
        self.assertEqual(cfg.server, SERVER)
        with self.assertRaises(ConfigError):
            build_config(None, env={"NETINSPECT_TOKEN": TOKEN})
        with self.assertRaises(ConfigError):
            build_config(SERVER, ca_file="/nonexistent/ca.crt", env={"NETINSPECT_TOKEN": TOKEN})


class ClientTest(unittest.TestCase):
    def test_headers(self) -> None:
        client, opener = make_client({"/version": {"gitVersion": "v1.29.0"}})
        self.assertEqual(client.get("/version"), {"gitVersion": "v1.29.0"})
        req = opener.requests[0]
        self.assertEqual(req.get_header("Accept"), "application/json")
        self.assertEqual(req.unredirected_hdrs.get("Authorization"), "Bearer " + TOKEN)
        self.assertNotIn(TOKEN, repr(client))

    def test_post_body(self) -> None:
        client, opener = make_client({"/x": {"ok": True}})
        client.post("/x", {"a": 1})
        req = opener.requests[0]
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(json.loads(req.data), {"a": 1})

    def test_pagination(self) -> None:
        pages = {
            None: {"items": [{"n": 1}, {"n": 2}], "metadata": {"continue": "tok2"}},
            "tok2": {"items": [{"n": 3}], "metadata": {"continue": ""}},
        }

        def handler(req: Any) -> Any:
            query = req.full_url.split("?", 1)[1]
            self.assertIn("limit=500", query)
            cont = None
            for part in query.split("&"):
                if part.startswith("continue="):
                    cont = part.split("=", 1)[1]
            return pages[cont]

        client, opener = make_client({"/api/v1/services": handler})
        items = client.list_all("/api/v1/services")
        self.assertEqual([i["n"] for i in items], [1, 2, 3])
        self.assertEqual(len(opener.requests), 2)

    def _assert_raises(self, exc: BaseException, expected: type, hint: str | None = None) -> None:
        client, _ = make_client({"/p": exc})
        with self.assertRaises(expected) as ctx:
            client.get("/p")
        message = str(ctx.exception)
        self.assertNotIn(TOKEN, message)
        self.assertIsNone(ctx.exception.__cause__)
        if hint:
            self.assertIn(hint, message)

    def test_401(self) -> None:
        self._assert_raises(http_error(SERVER + "/p", 401), AuthError, "oc whoami -t")

    def test_403(self) -> None:
        body = json.dumps({"message": f"forbidden for token {TOKEN}"})
        self._assert_raises(http_error(SERVER + "/p", 403, body), ForbiddenError, "/p")

    def test_404(self) -> None:
        self._assert_raises(http_error(SERVER + "/p", 404), NotFoundError)

    def test_500(self) -> None:
        self._assert_raises(http_error(SERVER + "/p", 500, "boom"), ApiError, "500")

    def test_tls(self) -> None:
        err = urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed"))
        self._assert_raises(err, TLSError, "--ca-file")
        self._assert_raises(ssl.SSLError("bad"), TLSError, "--ca-file")

    def test_connection_refused(self) -> None:
        self._assert_raises(urllib.error.URLError(ConnectionRefusedError("refused")), ApiError)

    def test_urlopen_is_used_via_opener(self) -> None:
        # проверка подмены urlopen-уровня: запросы не уходят в сеть
        client = ApiClient(ConnectionConfig(server=SERVER, token=TOKEN))
        with mock.patch.object(client._opener, "open", return_value=FakeResponse({"a": 1})) as m:
            self.assertEqual(client.get("/a", {"x": "1"}), {"a": 1})
            self.assertTrue(m.call_args[0][0].full_url.endswith("/a?x=1"))

    def test_insecure_context(self) -> None:
        client = ApiClient(ConnectionConfig(server=SERVER, token=TOKEN, insecure=True))
        self.assertEqual(client._ssl_context.verify_mode, ssl.CERT_NONE)


class AccessAndDiscoveryTest(unittest.TestCase):
    def test_version_and_whoami(self) -> None:
        client, _ = make_client(
            {"/version": {"gitVersion": "v1.29.4"}, "/apis/user.openshift.io/v1/users/~": {"metadata": {"name": "alice"}}}
        )
        self.assertEqual(cluster_version(client), "v1.29.4")
        self.assertEqual(whoami(client), "alice")

    def test_whoami_not_openshift(self) -> None:
        client, _ = make_client({})
        self.assertIsNone(whoami(client))

    def test_ssar(self) -> None:
        def handler(req: Any) -> Any:
            attrs = json.loads(req.data)["spec"]["resourceAttributes"]
            self.assertEqual(attrs["verb"], "list")
            self.assertEqual(attrs["namespace"], "prod")
            return {"status": {"allowed": attrs["resource"] != "routes"}}

        client, _ = make_client({"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews": handler})
        results = {r.kind: r.allowed for r in check_access(client, "prod")}
        self.assertTrue(results["VirtualService"])
        self.assertFalse(results["Route"])

    def test_discovery(self) -> None:
        client, _ = make_client(
            {
                "/apis/networking.istio.io": {"versions": [{"version": "v1beta1"}, {"version": "v1alpha3"}]},
                "/apis/discovery.k8s.io": {"versions": [{"version": "v1"}]},
            }
        )
        info = discover(client)
        self.assertEqual(info.istio_version, "v1beta1")
        self.assertFalse(info.is_openshift)
        self.assertIsNone(info.version_for(get_type("Route")))
        self.assertEqual(info.version_for(get_type("Service")), "v1")


class ClusterSourceTest(unittest.TestCase):
    def test_load_with_forbidden_kind(self) -> None:
        vs = {
            "metadata": {
                "name": "reviews",
                "namespace": "prod",
                "managedFields": [{"manager": "x"}],
                "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}"},
            },
            "spec": {"hosts": ["reviews"]},
        }
        routes = {
            "/apis/networking.istio.io": {"versions": [{"version": "v1"}]},
            "/apis/discovery.k8s.io": {"versions": [{"version": "v1"}]},
            "/apis/route.openshift.io": {"versions": [{"version": "v1"}]},
            "/apis/networking.istio.io/v1/namespaces/prod/virtualservices": {"items": [vs]},
            "/apis/networking.istio.io/v1/namespaces/prod/gateways": http_error(SERVER, 403),
            "/api/v1/namespaces/prod/services": {"items": []},
        }
        client, opener = make_client(routes)
        source = ClusterSource(client)
        res = source.load(["Gateway", "VirtualService", "Service", "Secret"], ["prod"])
        self.assertEqual([r.key for r in res], ["VirtualService/prod/reviews"])
        self.assertNotIn("managedFields", res[0].raw["metadata"])
        self.assertNotIn("annotations", res[0].raw["metadata"])
        self.assertTrue(any("Gateway" in w and "прав" in w for w in source.warnings))
        self.assertFalse(any("secrets" in r.full_url for r in opener.requests))

    def test_auth_error_propagates(self) -> None:
        routes = {
            "/apis/networking.istio.io": {"versions": [{"version": "v1"}]},
            "/apis/networking.istio.io/v1/gateways": http_error(SERVER, 401),
        }
        client, _ = make_client(routes)
        with self.assertRaises(AuthError):
            ClusterSource(client).load(["Gateway"], None)


if __name__ == "__main__":
    unittest.main()

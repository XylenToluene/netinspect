import http.client
import io
import json
import logging
import os
import ssl
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from typing import Any
from unittest import mock

from netinspect.core.access import connection_report
from netinspect.core.client import ApiClient
from netinspect.core.config import ConnectionConfig
from netinspect.core.errors import ConfigError
from netinspect.server.app import COOKIE_NAME, is_loopback, make_server, parse_connect_request
from netinspect.server.sessions import SessionStore
from tests.fake_cluster import GOOD_TOKEN, FakeCluster

# локальные запросы не должны уходить в прокси окружения
_NO_PROXY = {"NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"}


class ConnectionReportTest(unittest.TestCase):
    def test_dynamic_istio_discovery(self) -> None:
        with mock.patch.dict(os.environ, _NO_PROXY), FakeCluster() as cluster:
            client = ApiClient(ConnectionConfig(server=cluster.url, token=GOOD_TOKEN))
            report = connection_report(client, "prod")
        kinds = {res.kind: acc.allowed for res, acc in report.resources}
        # Istio: не только VS/GW/DR — всё, что есть в кластере
        for kind in ("Gateway", "VirtualService", "DestinationRule", "ServiceEntry", "Sidecar",
                     "AuthorizationPolicy", "PeerAuthentication", "Telemetry"):
            self.assertIn(kind, kinds)
        self.assertFalse(kinds["EnvoyFilter"])
        # базовые сетевые ресурсы — да, прочие core/apps — нет
        self.assertTrue(kinds["Service"])
        self.assertIn("EndpointSlice", kinds)
        self.assertIn("Route", kinds)
        for kind in ("Pod", "Secret", "Deployment"):
            self.assertNotIn(kind, kinds)
        self.assertEqual(report.user, "jdoe")
        self.assertTrue(report.openshift)
        self.assertEqual(
            report.istio_groups,
            ["networking.istio.io/v1", "security.istio.io/v1", "telemetry.istio.io/v1"],
        )
        data = report.to_dict()
        self.assertTrue(data["istio"])
        self.assertNotIn(GOOD_TOKEN, json.dumps(data))
        # Istio-ресурсы идут первыми
        self.assertTrue(data["resources"][0]["istio"])


class ParseRequestTest(unittest.TestCase):
    def test_ok(self) -> None:
        cfg = parse_connect_request({"server": "api.x:6443", "token": "Bearer abc"})
        self.assertEqual(cfg.server, "https://api.x:6443")
        self.assertEqual(cfg.token, "abc")

    def test_errors(self) -> None:
        bad = [
            {"token": "t"},
            {"server": "https://a"},
            {"server": "https://a", "token": 123},
            {"server": "https://a b", "token": "t"},
            {"server": "https://a", "token": "two words"},
        ]
        for body in bad:
            with self.assertRaises(ConfigError, msg=body):
                parse_connect_request(body)

    def test_tls_fields_ignored(self) -> None:
        # старые поля TLS/namespace больше ни на что не влияют: проверка сертификата не отключается
        cfg = parse_connect_request(
            {"server": "https://a", "token": "t", "insecure": True, "caCert": "x", "namespace": "prod"}
        )
        client = ApiClient(cfg)
        self.assertEqual(client._ssl_context.verify_mode, ssl.CERT_REQUIRED)


class SessionStoreTest(unittest.TestCase):
    def test_ttl_and_eviction(self) -> None:
        now = [0.0]
        store = SessionStore(ttl=10, max_sessions=2, clock=lambda: now[0])
        client = mock.Mock()
        a = store.create(client, {})
        now[0] = 1
        b = store.create(client, {})
        now[0] = 2
        c = store.create(client, {})  # вытесняет самую старую (a)
        self.assertIsNone(store.get(a.id))
        self.assertIsNotNone(store.get(b.id))
        now[0] = 20
        self.assertIsNone(store.get(c.id))
        self.assertEqual(len(store), 0)
        self.assertNotIn(b.id, repr(b))


class ServerTest(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.dict(os.environ, _NO_PROXY)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.cluster = FakeCluster().__enter__()
        self.addCleanup(self.cluster.__exit__)
        self.httpd = make_server("127.0.0.1", 0)
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.cookie: str | None = None
        # перехват логов бэкенда — токена там быть не должно
        self.log = io.StringIO()
        handler = logging.StreamHandler(self.log)
        logger = logging.getLogger("netinspect")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.DEBUG)
        self.addCleanup(lambda: (logger.removeHandler(handler), logger.setLevel(old_level)))

    def call(self, method: str, path: str, body: Any = None, headers: dict[str, str] | None = None,
             raw: bytes | None = None) -> tuple[int, dict[str, Any], Any]:
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method)
        hdrs = {"Content-Type": "application/json", "X-Netinspect": "1"} if data is not None else {}
        hdrs.update(headers or {})
        for k, v in hdrs.items():
            req.add_header(k, v)
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        try:
            with self.opener.open(req, timeout=10) as resp:
                status, payload, resp_headers = resp.status, json.loads(resp.read()), resp.headers
        except urllib.error.HTTPError as exc:
            status, payload, resp_headers = exc.code, json.loads(exc.read()), exc.headers
        set_cookie = resp_headers.get("Set-Cookie")
        if set_cookie:
            value = set_cookie.split(";", 1)[0]
            self.cookie = None if value == f"{COOKIE_NAME}=" else value
        return status, payload, resp_headers

    def connect_body(self, **over: Any) -> dict[str, Any]:
        body = {"server": self.cluster.url, "token": GOOD_TOKEN}
        body.update(over)
        return body

    def test_health_and_no_session(self) -> None:
        self.assertEqual(self.call("GET", "/api/health")[1]["status"], "ok")
        status, data, headers = self.call("GET", "/api/session")
        self.assertEqual(status, 200)
        self.assertFalse(data["connected"])
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_connect_session_disconnect(self) -> None:
        status, data, headers = self.call("POST", "/api/connect", self.connect_body())
        self.assertEqual(status, 200, data)
        self.assertTrue(data["ok"])
        self.assertEqual(data["report"]["user"], "jdoe")
        cookie_header = headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie_header)
        self.assertIn("SameSite=Strict", cookie_header)
        self.assertNotIn(GOOD_TOKEN, json.dumps(data) + cookie_header)

        status, data, _ = self.call("GET", "/api/session")
        self.assertTrue(data["connected"])
        self.assertEqual(data["report"]["server"], self.cluster.url)

        self.call("POST", "/api/disconnect", {})
        self.assertIsNone(self.cookie)
        self.assertFalse(self.call("GET", "/api/session")[1]["connected"])
        self.assertNotIn(GOOD_TOKEN, self.log.getvalue())

    def test_reconnect_replaces_session(self) -> None:
        self.call("POST", "/api/connect", self.connect_body())
        first = self.cookie
        self.call("POST", "/api/connect", self.connect_body())
        self.assertNotEqual(first, self.cookie)
        self.assertEqual(len(self.httpd.store), 1)

    def test_bad_token(self) -> None:
        bad = "sha256~WRONG-secret-777"
        status, data, headers = self.call("POST", "/api/connect", self.connect_body(token=bad))
        self.assertEqual(status, 401)
        self.assertEqual(data["kind"], "auth")
        self.assertIn("oc whoami -t", data["error"])
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn(bad, json.dumps(data) + self.log.getvalue())
        self.assertEqual(len(self.httpd.store), 0)

    def test_unreachable(self) -> None:
        status, data, _ = self.call("POST", "/api/connect", self.connect_body(server="http://127.0.0.1:9"))
        self.assertEqual(status, 502)
        self.assertEqual(data["kind"], "network")

    def test_input_errors(self) -> None:
        status, data, _ = self.call("POST", "/api/connect", {"server": "", "token": ""})
        self.assertEqual((status, data["kind"]), (400, "input"))
        status, data, _ = self.call("POST", "/api/connect", raw=b"{oops")
        self.assertEqual((status, data["kind"]), (400, "input"))
        status, _, _ = self.call("POST", "/api/connect", raw=b"[]")
        self.assertEqual(status, 400)

    def test_csrf_and_content_type(self) -> None:
        status, data, _ = self.call("POST", "/api/connect", self.connect_body(), headers={"X-Netinspect": "0"})
        self.assertEqual((status, data["kind"]), (403, "csrf"))
        status, _, _ = self.call("POST", "/api/connect", self.connect_body(), headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 415)
        self.assertEqual(len(self.httpd.store), 0)

    def test_body_limit(self) -> None:
        # объявляем большое тело, но не шлём его: сервер обязан отказать, не читая
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=10)
        self.addCleanup(conn.close)
        conn.putrequest("POST", "/api/connect")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("X-Netinspect", "1")
        conn.putheader("Content-Length", str(10 * 1024 * 1024))
        conn.endheaders()
        resp = conn.getresponse()
        self.assertEqual(resp.status, 413)
        self.assertEqual(json.loads(resp.read())["kind"], "input")

    def test_unknown_route(self) -> None:
        self.assertEqual(self.call("GET", "/api/nope")[0], 404)
        self.assertEqual(self.call("GET", "/api/connect")[0], 404)

    def test_forged_cookie(self) -> None:
        self.cookie = f"{COOKIE_NAME}=forged"
        self.assertFalse(self.call("GET", "/api/session")[1]["connected"])


class StaticTest(unittest.TestCase):
    """Режим без nginx: бэкенд сам раздаёт интерфейс."""

    def start(self, **kwargs: Any) -> str:
        httpd = make_server("127.0.0.1", 0, **kwargs)
        threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return f"127.0.0.1:{httpd.server_address[1]}"

    def get(self, host: str, path: str, method: str = "GET") -> tuple[int, dict[str, str], bytes]:
        conn = http.client.HTTPConnection(host, timeout=10)
        self.addCleanup(conn.close)
        conn.request(method, path)
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read()

    def test_index_and_assets(self) -> None:
        host = self.start()
        status, headers, body = self.get(host, "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn("connect.js", body.decode())
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        for path, ctype in (("/style.css", "text/css"), ("/connect.js", "application/javascript"),
                            ("/graph.html", "text/html"), ("/theme.css", "text/css")):
            status, headers, _ = self.get(host, path)
            self.assertEqual((status, headers["Content-Type"].split(";")[0]), (200, ctype), path)
        status, headers, body = self.get(host, "/", "HEAD")
        self.assertEqual((status, body), (200, b""))
        status, headers, body = self.get(host, "/fonts/inter-latin-wght-normal.woff2")
        self.assertEqual((status, headers["Content-Type"]), (200, "font/woff2"))
        self.assertIn("max-age", headers["Cache-Control"])
        self.assertIn("font-src 'self'", headers["Content-Security-Policy"])

    def test_no_traversal(self) -> None:
        host = self.start()
        for path in ("/../README.md", "/%2e%2e/netinspect/cli.py", "/..%2fcli.py", "/sub/index.html",
                     "/.hidden.js", "/__init__.py", "/%5c..%5ccli.py", "/fonts/../app.js.woff2",
                     "/fonts/LICENSE-Inter.txt", "/fonts/sub/x.woff2", "/fonts/.woff2"):
            self.assertEqual(self.get(host, path)[0], 404, path)

    def test_graph_json_from_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "graph.json"), "w") as fh:
                fh.write('{"nodes": []}')
            host = self.start(graph_dir=tmp)
            status, headers, body = self.get(host, "/graph.json")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {"nodes": []})
        self.assertEqual(self.get(self.start(), "/graph.json")[0], 404)

    def test_api_only(self) -> None:
        host = self.start(static_dir=None)
        self.assertEqual(self.get(host, "/")[0], 404)
        self.assertEqual(self.get(host, "/api/health")[0], 200)


class HelpersTest(unittest.TestCase):
    def test_is_loopback(self) -> None:
        self.assertTrue(is_loopback("127.0.0.1"))
        self.assertTrue(is_loopback("::1"))
        self.assertTrue(is_loopback("localhost"))
        self.assertFalse(is_loopback("0.0.0.0"))
        self.assertFalse(is_loopback("10.1.2.3"))


if __name__ == "__main__":
    unittest.main()

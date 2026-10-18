"""JSON API веб-интерфейса. Работает за nginx (``location /api/``).

Если nginx нет, тот же процесс раздаёт и интерфейс (``/`` → ``index.html`` и
файлы из ``netinspect/ui/static``, ``/graph.json`` — из каталога выгрузки графа).

Эндпоинты:

- ``GET  /api/health``     — проверка, что бэкенд жив;
- ``GET  /api/session``    — текущее подключение (по cookie);
- ``POST /api/connect``    — проверить подключение к кластеру и открыть сессию;
- ``POST /api/disconnect`` — закрыть сессию.

POST-запросы принимаются только с ``Content-Type: application/json`` и заголовком
``X-Netinspect: 1`` — простая защита от CSRF (кросс-доменный запрос с таким
заголовком невозможен без CORS, а CORS бэкенд не разрешает).
"""

from __future__ import annotations

import http.cookies
import ipaddress
import json
import logging
import os
import re
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from netinspect.core.access import connection_report
from netinspect.core.client import ApiClient
from netinspect.core.config import DEFAULT_TIMEOUT, ConnectionConfig
from netinspect.core.errors import (
    ApiError,
    AuthError,
    ConfigError,
    ForbiddenError,
    NotFoundError,
    TLSError,
)
from netinspect.server.sessions import SessionStore

#: Статика интерфейса (index.html, connect.js, ...), раздаётся, если нет nginx.
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ui", "static")
STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
}
#: Те же заголовки безопасности, что в deploy/nginx/netinspect-common.inc.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

log = logging.getLogger(__name__)

COOKIE_NAME = "netinspect_session"
CSRF_HEADER = "X-Netinspect"
MAX_BODY = 512 * 1024  # CA-бандл может быть большим
_NAMESPACE_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")


class ApiFailure(Exception):
    """Ошибка, которая отдаётся клиенту как JSON ``{ok: false, error, kind}``."""

    def __init__(self, status: HTTPStatus, kind: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.kind = kind
        self.message = message


def _failure_from(exc: Exception) -> ApiFailure:
    """Перевести исключение ядра в ответ API. Тексты ошибок ядра не содержат токена."""
    if isinstance(exc, ConfigError):
        return ApiFailure(HTTPStatus.BAD_REQUEST, "input", str(exc))
    if isinstance(exc, AuthError):
        return ApiFailure(HTTPStatus.UNAUTHORIZED, "auth", str(exc))
    if isinstance(exc, TLSError):
        return ApiFailure(HTTPStatus.BAD_GATEWAY, "tls", str(exc))
    if isinstance(exc, ForbiddenError):
        return ApiFailure(HTTPStatus.FORBIDDEN, "forbidden", str(exc))
    if isinstance(exc, NotFoundError):
        return ApiFailure(
            HTTPStatus.BAD_GATEWAY,
            "network",
            f"{exc}. Похоже, адрес указывает не на API Kubernetes/OpenShift (нужен https://api...:6443)",
        )
    if isinstance(exc, ApiError):
        return ApiFailure(HTTPStatus.BAD_GATEWAY, "network", str(exc))
    return ApiFailure(HTTPStatus.INTERNAL_SERVER_ERROR, "internal", "внутренняя ошибка сервера")


def parse_connect_request(body: dict[str, Any]) -> tuple[ConnectionConfig, str | None]:
    """Проверить тело ``POST /api/connect`` и собрать конфигурацию подключения."""

    def text(name: str) -> str:
        value = body.get(name)
        if value is None:
            return ""
        if not isinstance(value, str):
            raise ConfigError(f"поле {name} должно быть строкой")
        return value.strip()

    server = text("server")
    token = text("token")
    if not server:
        raise ConfigError("укажите адрес API кластера, например https://api.cluster.example:6443")
    if not token:
        raise ConfigError("укажите токен (oc whoami -t)")
    ca_cert = text("caCert") or None
    if ca_cert and "BEGIN CERTIFICATE" not in ca_cert:
        raise ConfigError("CA-сертификат должен быть в формате PEM (-----BEGIN CERTIFICATE-----)")
    insecure = body.get("insecure", False)
    if not isinstance(insecure, bool):
        raise ConfigError("поле insecure должно быть true/false")
    namespace = text("namespace") or None
    if namespace and not _NAMESPACE_RE.match(namespace):
        raise ConfigError(f"некорректное имя namespace: {namespace!r}")
    config = ConnectionConfig(
        server=server,
        token=token,
        ca_data=None if insecure else ca_cert,
        insecure=insecure,
        timeout=DEFAULT_TIMEOUT,
    )
    return config, namespace


class NetinspectServer(ThreadingHTTPServer):
    """HTTP-сервер бэкенда с хранилищем сессий."""

    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        store: SessionStore | None = None,
        static_dir: str | None = STATIC_DIR,
        graph_dir: str | None = None,
    ) -> None:
        super().__init__(address, ApiHandler)
        self.store = store or SessionStore()
        #: Каталог статики; ``None`` — только API (интерфейс раздаёт nginx).
        self.static_dir = static_dir
        #: Каталог с graph.json (``graph --web-dir``).
        self.graph_dir = graph_dir


class ApiHandler(BaseHTTPRequestHandler):
    """Обработчик JSON API."""

    server: NetinspectServer
    server_version = "netinspect"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # --- маршрутизация ----------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - имя задано http.server
        if not self.path.startswith("/api/"):
            self._static()
            return
        self._dispatch({"/api/health": self._health, "/api/session": self._session})

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch({"/api/connect": self._connect, "/api/disconnect": self._disconnect}, post=True)

    def _dispatch(self, routes: dict[str, Any], post: bool = False) -> None:
        path = self.path.split("?", 1)[0]
        handler = routes.get(path)
        try:
            if handler is None:
                raise ApiFailure(HTTPStatus.NOT_FOUND, "not_found", f"нет такого метода API: {path}")
            body = self._read_json() if post else {}
            handler(body)
        except ApiFailure as exc:
            self._send(exc.status, {"ok": False, "kind": exc.kind, "error": exc.message})
        except Exception:  # noqa: BLE001 - последний рубеж: не отдаём трассировку клиенту
            log.exception("необработанная ошибка в %s %s", self.command, path)
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "kind": "internal", "error": "внутренняя ошибка сервера"})

    # --- обработчики ------------------------------------------------------

    def _health(self, _body: dict[str, Any]) -> None:
        self._send(HTTPStatus.OK, {"ok": True, "status": "ok"})

    def _session(self, _body: dict[str, Any]) -> None:
        session = self.server.store.get(self._session_id())
        if session is None:
            self._send(HTTPStatus.OK, {"ok": True, "connected": False})
        else:
            self._send(HTTPStatus.OK, {"ok": True, **session.public()})

    def _connect(self, body: dict[str, Any]) -> None:
        try:
            config, namespace = parse_connect_request(body)
            client = ApiClient(config)
            report = connection_report(client, namespace)
        except ApiFailure:
            raise
        except Exception as exc:  # noqa: BLE001 - ошибки ядра переводятся в ответ
            failure = _failure_from(exc)
            if failure.kind == "internal":
                log.exception("ошибка при проверке подключения")
            else:
                log.info("подключение не удалось: %s", failure.kind)
            raise failure from None
        store = self.server.store
        store.delete(self._session_id())
        session = store.create(client, report.to_dict())
        log.info("подключение к %s: пользователь %s", report.server, report.user or "n/a")
        self._send(HTTPStatus.OK, {"ok": True, **session.public()}, cookie=session.id)

    def _disconnect(self, _body: dict[str, Any]) -> None:
        self.server.store.delete(self._session_id())
        self._send(HTTPStatus.OK, {"ok": True, "connected": False}, cookie="")

    # --- статика (режим без nginx) -----------------------------------------

    def _static_file(self, path: str) -> str | None:
        """Путь к файлу статики. Отдаются только файлы, лежащие прямо в каталоге (без подкаталогов)."""
        name = path.lstrip("/") or "index.html"
        if "/" in name or "\\" in name or name.startswith("."):
            return None
        if name == "graph.json":
            base = self.server.graph_dir
        else:
            base = self.server.static_dir
        if not base or os.path.splitext(name)[1] not in STATIC_TYPES:
            return None
        full = os.path.join(base, name)
        return full if os.path.isfile(full) else None

    def _static(self) -> None:
        path = urllib.parse.unquote(self.path.split("?", 1)[0])
        full = self._static_file(path) if self.server.static_dir else None
        if full is None:
            body = "404 — не найдено".encode("utf-8")
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._security_headers()
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            return
        with open(full, "rb") as fh:
            data = fh.read()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", STATIC_TYPES[os.path.splitext(full)[1]])
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _security_headers(self) -> None:
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)

    # --- ввод/вывод -------------------------------------------------------

    def _read_json(self) -> dict[str, Any]:
        if self.headers.get(CSRF_HEADER) != "1":
            raise ApiFailure(HTTPStatus.FORBIDDEN, "csrf", f"нет заголовка {CSRF_HEADER}")
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            raise ApiFailure(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "input", "ожидается application/json")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            raise ApiFailure(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "input", "слишком большой запрос")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiFailure(HTTPStatus.BAD_REQUEST, "input", "некорректный JSON") from None
        if not isinstance(data, dict):
            raise ApiFailure(HTTPStatus.BAD_REQUEST, "input", "ожидается JSON-объект")
        return data

    def _session_id(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(raw)
        except http.cookies.CookieError:
            return None
        morsel = jar.get(COOKIE_NAME)
        return morsel.value if morsel else None

    def _send(self, status: HTTPStatus, payload: dict[str, Any], cookie: str | None = None) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        if cookie is not None:
            secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""
            max_age = "" if cookie else "; Max-Age=0"
            self.send_header(
                "Set-Cookie",
                f"{COOKIE_NAME}={cookie}; Path=/api; HttpOnly; SameSite=Strict{max_age}{secure}",
            )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - сигнатура http.server
        # requestline содержит только метод и путь; тела запросов (с токеном) не логируются
        log.info("%s %s", self.address_string(), format % args)


def is_loopback(host: str) -> bool:
    """True для адресов только локальной машины."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_server(
    host: str = "127.0.0.1",
    port: int = 8081,
    store: SessionStore | None = None,
    static_dir: str | None = STATIC_DIR,
    graph_dir: str | None = None,
) -> NetinspectServer:
    """Создать сервер (не запуская его). ``static_dir=None`` — только API, интерфейс раздаёт nginx."""
    return NetinspectServer((host, port), store, static_dir, graph_dir)

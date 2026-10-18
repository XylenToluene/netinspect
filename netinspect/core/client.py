"""HTTP-клиент API Kubernetes/OpenShift на стандартной библиотеке."""

from __future__ import annotations

import json
import logging
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from netinspect.core.config import ConnectionConfig
from netinspect.core.errors import (
    ApiError,
    AuthError,
    ForbiddenError,
    NotFoundError,
    TLSError,
)

log = logging.getLogger(__name__)

PAGE_LIMIT = 500
_MAX_BODY_IN_ERROR = 300


class ApiClient:
    """Клиент API кластера с авторизацией по Bearer-токену.

    Токен хранится только в конфигурации и подставляется в заголовок запроса;
    в логи, ``repr`` и тексты исключений он не попадает.
    """

    def __init__(self, config: ConnectionConfig) -> None:
        self._config = config
        self._ssl_context = self._make_ssl_context(config)
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.HTTPSHandler(context=self._ssl_context)
        ]
        if config.proxy:
            handlers.append(urllib.request.ProxyHandler({"http": config.proxy, "https": config.proxy}))
        self._opener = urllib.request.build_opener(*handlers)

    def __repr__(self) -> str:
        return f"ApiClient(server={self._config.server!r})"

    @property
    def server(self) -> str:
        """Адрес API сервера."""
        return self._config.server

    @staticmethod
    def _make_ssl_context(config: ConnectionConfig) -> ssl.SSLContext:
        """Проверка сертификата API по системному хранилищу доверенных CA."""
        return ssl.create_default_context()

    # --- публичное API -------------------------------------------------

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET запрос, возвращает разобранный JSON."""
        return self._request("GET", path, params=params)

    def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST запрос с JSON-телом, возвращает разобранный JSON."""
        return self._request("POST", path, body=body)

    def list_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Загрузить все элементы списка с пагинацией (``limit`` + ``continue``)."""
        items: list[dict[str, Any]] = []
        token: str | None = None
        while True:
            query: dict[str, Any] = dict(params or {})
            query["limit"] = PAGE_LIMIT
            if token:
                query["continue"] = token
            page = self.get(path, query)
            items.extend(page.get("items") or [])
            token = (page.get("metadata") or {}).get("continue") or None
            if not token:
                return items

    # --- внутреннее ----------------------------------------------------

    def _url(self, path: str, params: dict[str, Any] | None) -> str:
        if not path.startswith("/"):
            path = "/" + path
        url = self._config.server + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return url

    def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = self._url(path, params)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "netinspect")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        # add_unredirected_header: заголовок не переносится при редиректе на другой хост
        req.add_unredirected_header("Authorization", "Bearer " + self._config.token)
        log.debug("%s %s", method, path)
        try:
            with self._opener.open(req, timeout=self._config.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise self._map_http_error(exc, path) from None
        except ssl.SSLError as exc:
            raise self._tls_error(exc, path) from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLError):
                raise self._tls_error(exc.reason, path) from None
            raise ApiError(
                f"не удалось подключиться к {self._config.server}: {exc.reason}", path=path
            ) from None
        except (TimeoutError, OSError) as exc:
            raise ApiError(f"сетевая ошибка при запросе {path}: {exc}", path=path) from None
        if not raw:
            return {}
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(f"ответ на {path} не является JSON", path=path) from None
        return result if isinstance(result, dict) else {"items": result}

    def _tls_error(self, exc: ssl.SSLError, path: str) -> TLSError:
        return TLSError(
            f"ошибка TLS при подключении к {self._config.server}: {exc}. "
            "Сертификат API проверяется по системному хранилищу доверенных CA — "
            "добавьте CA кластера в систему (см. README, раздел «TLS-сертификат кластера»)",
            path=path,
        )

    def _map_http_error(self, exc: urllib.error.HTTPError, path: str) -> ApiError:
        status = exc.code
        detail = self._error_detail(exc)
        if status == 401:
            return AuthError(
                "401 Unauthorized: токен невалиден или истёк, получите новый: oc whoami -t",
                status=status,
                path=path,
            )
        if status == 403:
            return ForbiddenError(
                f"403 Forbidden: нет прав на {path}" + (f" ({detail})" if detail else ""),
                status=status,
                path=path,
            )
        if status == 404:
            return NotFoundError(f"404 Not Found: {path}", status=status, path=path)
        return ApiError(
            f"HTTP {status} на {path}" + (f": {detail}" if detail else ""), status=status, path=path
        )

    def _error_detail(self, exc: urllib.error.HTTPError) -> str:
        try:
            raw = exc.read()
        except Exception:  # noqa: BLE001 - тело ошибки не обязательно
            return ""
        if not raw:
            return ""
        text = raw.decode("utf-8", errors="replace")
        try:
            obj = json.loads(text)
            if isinstance(obj, dict) and obj.get("message"):
                text = str(obj["message"])
        except json.JSONDecodeError:
            pass
        text = text.replace(self._config.token, "****")
        return text[:_MAX_BODY_IN_ERROR]


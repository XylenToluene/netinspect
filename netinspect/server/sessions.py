"""Сессии подключения к кластеру. Хранятся только в памяти процесса.

Токен живёт внутри ``ApiClient`` сессии и наружу (в ответы API, логи) не выдаётся.
Браузер получает только случайный идентификатор сессии в HttpOnly-cookie.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from netinspect.core.client import ApiClient

DEFAULT_TTL = 8 * 3600.0
DEFAULT_MAX_SESSIONS = 100


@dataclass(slots=True)
class Session:
    """Подключение пользователя к кластеру."""

    id: str = field(repr=False)
    client: ApiClient
    report: dict[str, Any]
    created: float
    last_used: float
    connected_at: str

    def public(self) -> dict[str, Any]:
        """Данные сессии для браузера (без токена и идентификатора)."""
        return {"connected": True, "connectedAt": self.connected_at, "report": self.report}


class SessionStore:
    """Потокобезопасное хранилище сессий с истечением по неактивности."""

    def __init__(
        self,
        ttl: float = DEFAULT_TTL,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl
        self._max = max_sessions
        self._clock = clock
        self._lock = threading.Lock()
        self._items: dict[str, Session] = {}

    def __len__(self) -> int:
        with self._lock:
            self._expire()
            return len(self._items)

    def _expire(self) -> None:
        now = self._clock()
        for sid in [s.id for s in self._items.values() if now - s.last_used > self._ttl]:
            del self._items[sid]

    def create(self, client: ApiClient, report: dict[str, Any]) -> Session:
        """Создать сессию; при переполнении вытесняется самая давно неиспользуемая."""
        now = self._clock()
        session = Session(
            id=secrets.token_urlsafe(32),
            client=client,
            report=report,
            created=now,
            last_used=now,
            connected_at=time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        )
        with self._lock:
            self._expire()
            while len(self._items) >= self._max:
                oldest = min(self._items.values(), key=lambda s: s.last_used)
                del self._items[oldest.id]
            self._items[session.id] = session
        return session

    def get(self, sid: str | None) -> Session | None:
        """Найти живую сессию и продлить её."""
        if not sid:
            return None
        with self._lock:
            self._expire()
            session = self._items.get(sid)
            if session is not None:
                session.last_used = self._clock()
            return session

    def delete(self, sid: str | None) -> None:
        """Удалить сессию (если есть)."""
        if not sid:
            return
        with self._lock:
            self._items.pop(sid, None)

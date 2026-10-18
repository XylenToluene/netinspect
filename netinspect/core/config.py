"""Параметры подключения к API кластера."""

from __future__ import annotations

import getpass
import os
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Mapping

from netinspect.core.errors import ConfigError

ENV_TOKEN = "NETINSPECT_TOKEN"
ENV_SERVER = "NETINSPECT_SERVER"
DEFAULT_TIMEOUT = 15.0


def mask_token(token: str | None) -> str:
    """Замаскировать токен: ``****`` + последние 4 символа (короткие — целиком ``****``)."""
    if not token:
        return "<none>"
    if len(token) <= 8:
        return "****"
    return "****" + token[-4:]


@dataclass(slots=True)
class ConnectionConfig:
    """Параметры подключения. Токен не попадает в ``repr``."""

    server: str
    token: str = field(repr=False)
    timeout: float = DEFAULT_TIMEOUT
    proxy: str | None = None

    def __post_init__(self) -> None:
        self.server = self.server.strip().rstrip("/")
        if not self.server:
            raise ConfigError("не задан адрес API: --server или NETINSPECT_SERVER")
        if not self.server.startswith(("https://", "http://")):
            self.server = "https://" + self.server
        parsed = urllib.parse.urlsplit(self.server)
        if not parsed.hostname or any(ch.isspace() for ch in self.server) or parsed.query or parsed.fragment:
            raise ConfigError(f"некорректный адрес API: {self.server!r}, ожидается https://api.cluster.example:6443")
        token = (self.token or "").strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        if not token:
            raise ConfigError("пустой токен")
        if any(ch.isspace() for ch in token):
            raise ConfigError("токен не должен содержать пробелов и переводов строки")
        self.token = token

    def __repr__(self) -> str:
        return (
            f"ConnectionConfig(server={self.server!r}, token={mask_token(self.token)!r}, "
            f"timeout={self.timeout!r}, proxy={self.proxy!r})"
        )

    __str__ = __repr__


def resolve_token(
    token_env: str | None = None,
    env: Mapping[str, str] | None = None,
    prompt: Callable[[str], str] | None = None,
) -> str:
    """Получить токен: переменная ``token_env`` → ``NETINSPECT_TOKEN`` → ввод через getpass."""
    env = os.environ if env is None else env
    if token_env:
        value = env.get(token_env)
        if not value:
            raise ConfigError(f"переменная окружения {token_env} не задана или пуста")
        return value
    value = env.get(ENV_TOKEN)
    if value:
        return value
    ask = prompt or getpass.getpass
    try:
        value = ask("Token (oc whoami -t): ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise ConfigError("токен не введён") from exc
    if not value or not value.strip():
        raise ConfigError("токен не введён")
    return value


def build_config(
    server: str | None,
    token_env: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    proxy: str | None = None,
    env: Mapping[str, str] | None = None,
    prompt: Callable[[str], str] | None = None,
) -> ConnectionConfig:
    """Собрать конфигурацию из аргументов и переменных окружения."""
    env = os.environ if env is None else env
    server = server or env.get(ENV_SERVER)
    if not server:
        raise ConfigError("не задан адрес API: --server или NETINSPECT_SERVER")
    token = resolve_token(token_env, env, prompt)
    return ConnectionConfig(
        server=server, token=token, timeout=timeout, proxy=proxy
    )

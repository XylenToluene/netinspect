"""Исключения netinspect. Сообщения не содержат токена."""

from __future__ import annotations


class NetinspectError(Exception):
    """Базовое исключение netinspect."""


class ConfigError(NetinspectError):
    """Неполная или некорректная конфигурация подключения."""


class ApiError(NetinspectError):
    """Ошибка обращения к API кластера."""

    def __init__(self, message: str, status: int | None = None, path: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.path = path


class AuthError(ApiError):
    """401: токен невалиден или истёк."""


class ForbiddenError(ApiError):
    """403: недостаточно прав на ресурс."""


class NotFoundError(ApiError):
    """404: ресурс или API не найден."""


class TLSError(ApiError):
    """Ошибка TLS (сертификат сервера не прошёл проверку и т.п.)."""


class SourceError(NetinspectError):
    """Ошибка чтения манифестов из каталога."""

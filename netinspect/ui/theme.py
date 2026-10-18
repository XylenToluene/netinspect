"""Палитра netinspect — единый источник цветов для HTML-отчёта и консоли.

Пастельная голубая и бежевая гамма с дозированным бордовым акцентом.
Новые цвета вне палитры не вводятся: всё оформление ссылается на эти токены.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TextIO

#: CSS-токены (имя без ``--``) → значение.
PALETTE: dict[str, str] = {
    "bg": "#F7F2EA",
    "surface": "#FFFDF9",
    "blue-100": "#E3EFF8",
    "blue-300": "#A9CCE3",
    "blue-500": "#6F9FC4",
    "beige-200": "#EFE4D3",
    "beige-400": "#D8C3A5",
    "accent": "#7B1E3A",
    "accent-soft": "#F3E1E6",
    "text": "#2F3A45",
    "muted": "#6B7680",
    "danger": "#7B1E3A",
    "ok": "#5E8C6A",
    "white": "#FFFFFF",
}

#: Оформление узлов по типу: заливка и рамка (имена токенов) + пунктир.
NODE_STYLES: dict[str, dict[str, str | bool]] = {
    "Gateway": {"fill": "blue-300", "stroke": "blue-500", "dashed": False},
    "Route": {"fill": "blue-300", "stroke": "blue-500", "dashed": False},
    "VirtualService": {"fill": "blue-100", "stroke": "blue-300", "dashed": False},
    "DestinationRule": {"fill": "beige-200", "stroke": "beige-400", "dashed": False},
    "Service": {"fill": "beige-400", "stroke": "beige-400", "dashed": False},
    "EndpointSlice": {"fill": "surface", "stroke": "beige-400", "dashed": False},
    "ExternalHost": {"fill": "white", "stroke": "blue-500", "dashed": True},
}

DEFAULT_NODE_STYLE: dict[str, str | bool] = {"fill": "surface", "stroke": "beige-400", "dashed": False}

FONT_SANS = 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'
FONT_MONO = "ui-monospace, Consolas, monospace"

#: ANSI 256 цвета для консоли.
ANSI_BLUE = 110     # заголовки узлов
ANSI_BEIGE = 180    # бейджи
ANSI_ACCENT = 124   # ошибки / битые ссылки
ANSI_OK = 108       # приглушённый зелёный (✓)
ANSI_MUTED = 245    # служебный текст


def css_variables() -> str:
    """Вернуть блок ``:root { --token: value; ... }`` для встраивания в HTML."""
    lines = [f"  --{name}: {value};" for name, value in PALETTE.items()]
    lines.append(f"  --font-sans: {FONT_SANS};")
    lines.append(f"  --font-mono: {FONT_MONO};")
    return ":root {\n" + "\n".join(lines) + "\n}"


def node_style(kind: str) -> dict[str, str | bool]:
    """Стиль узла заданного типа (имена токенов палитры)."""
    return NODE_STYLES.get(kind, DEFAULT_NODE_STYLE)


def color_enabled(stream: TextIO, force_off: bool = False) -> bool:
    """Решить, использовать ли ANSI-цвета для потока.

    Цвета отключаются флагом, переменной ``NO_COLOR`` или если поток — не терминал.
    """
    if force_off or os.environ.get("NO_COLOR"):
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


@dataclass(frozen=True, slots=True)
class Ansi:
    """Раскраска текста ANSI 256; при ``enabled=False`` возвращает текст как есть."""

    enabled: bool = True

    def _wrap(self, code: int, text: str, bold: bool = False) -> str:
        if not self.enabled:
            return text
        prefix = "\033[1;" if bold else "\033["
        return f"{prefix}38;5;{code}m{text}\033[0m"

    def node(self, text: str) -> str:
        """Заголовок узла (голубой)."""
        return self._wrap(ANSI_BLUE, text, bold=True)

    def badge(self, text: str) -> str:
        """Бейдж (бежевый)."""
        return self._wrap(ANSI_BEIGE, text)

    def error(self, text: str) -> str:
        """Ошибка / проблема (бордовый)."""
        return self._wrap(ANSI_ACCENT, text, bold=True)

    def ok(self, text: str) -> str:
        """Успех (приглушённый зелёный)."""
        return self._wrap(ANSI_OK, text)

    def muted(self, text: str) -> str:
        """Служебный текст (серый)."""
        return self._wrap(ANSI_MUTED, text)

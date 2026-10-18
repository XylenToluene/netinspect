"""Дизайн-токены netinspect — единый источник цветов и шрифтов для веб-интерфейса и консоли.

Принципы (по мотивам Radix Colors, Linear, Kiali):

- нейтральная холодная шкала «slate» + один акцент «iris» (индиго-фиолетовый);
- у каждого токена своя роль: фон → поверхность → состояние → рамка → текст;
- цвета типов узлов — соседние оттенки одного сектора круга (cyan, sky, iris, violet, teal),
  поэтому они гармонируют и не спорят с акцентом;
- красный и янтарный — только для проблем (битые ссылки, нет прав, предупреждения);
- светлая и тёмная темы с одинаковыми именами токенов; контраст текста — WCAG AA
  (проверяется тестом ``tests/test_theme.py``).

Значения основаны на шкалах Radix Colors (MIT).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TextIO

#: Светлая тема: CSS-токен (имя без ``--``) → значение.
LIGHT: dict[str, str] = {
    # поверхности
    "bg": "#FBFBFC",
    "sidebar": "#F3F3F6",
    "surface": "#FFFFFF",
    "surface-2": "#F9F9FB",
    "surface-3": "#F0F0F3",
    "canvas": "#F7F7F9",
    "canvas-dot": "#D9D9E0",
    # рамки
    "border": "#E0E1E6",
    "border-strong": "#CDCED6",
    "border-input": "#B9BBC6",
    # текст
    "text": "#1C2024",
    "text-muted": "#60646C",
    "text-subtle": "#80838D",
    # акцент
    "accent": "#5B5BD6",
    "accent-hover": "#5151CD",
    "accent-text": "#4F4BBE",
    "accent-soft": "#F0F1FE",
    "accent-soft-2": "#E6E7FF",
    "accent-border": "#B8BAF8",
    "on-accent": "#FFFFFF",
    # статусы
    "success": "#2A7E3B",
    "success-soft": "#E9F6E9",
    "success-border": "#B2DDB5",
    "success-solid": "#46A758",
    "warning": "#915400",
    "warning-soft": "#FFF7DB",
    "warning-border": "#F3D673",
    "warning-solid": "#F5B83D",
    "danger": "#CE2C31",
    "danger-solid": "#C4262C",
    "danger-soft": "#FEEBEC",
    "danger-border": "#F4A9AA",
    # типы узлов графа: цвет иконки/акцента и мягкий фон
    "kind-gateway": "#0A6B84",
    "kind-gateway-soft": "#DEF7F9",
    "kind-route": "#00749E",
    "kind-route-soft": "#E1F6FD",
    "kind-vs": "#4F4BBE",
    "kind-vs-soft": "#F0F1FE",
    "kind-dr": "#6550B9",
    "kind-dr-soft": "#F4F0FE",
    "kind-svc": "#00796A",
    "kind-svc-soft": "#E0F8F3",
    "kind-eps": "#60646C",
    "kind-eps-soft": "#F0F0F3",
    "kind-ext": "#60646C",
    "kind-ext-soft": "#FFFFFF",
    # тени и фокус
    "shadow-sm": "0 1px 2px rgba(16, 24, 40, 0.05)",
    "shadow-md": "0 1px 3px rgba(16, 24, 40, 0.06), 0 6px 16px -4px rgba(16, 24, 40, 0.08)",
    "shadow-lg": "0 12px 32px -8px rgba(16, 24, 40, 0.18), 0 2px 6px rgba(16, 24, 40, 0.06)",
    "focus-ring": "0 0 0 3px rgba(91, 91, 214, 0.28)",
}

#: Тёмная тема: те же имена токенов.
DARK: dict[str, str] = {
    "bg": "#111113",
    "sidebar": "#0C0C0E",
    "surface": "#18191B",
    "surface-2": "#1C1D20",
    "surface-3": "#232427",
    "canvas": "#121315",
    "canvas-dot": "#2B2D31",
    "border": "#2E3135",
    "border-strong": "#43484E",
    "border-input": "#5A6169",
    "text": "#EDEEF0",
    "text-muted": "#B0B4BA",
    "text-subtle": "#8B8F98",
    "accent": "#5B5BD6",
    "accent-hover": "#4F4FC9",
    "accent-text": "#B1A9FF",
    "accent-soft": "#1F2045",
    "accent-soft-2": "#262A65",
    "accent-border": "#4A4A95",
    "on-accent": "#FFFFFF",
    "success": "#71D083",
    "success-soft": "#16261A",
    "success-border": "#2D5736",
    "success-solid": "#46A758",
    "warning": "#FFCA16",
    "warning-soft": "#2A1C06",
    "warning-border": "#5C3D05",
    "warning-solid": "#E2A336",
    "danger": "#FF9592",
    "danger-solid": "#C4262C",
    "danger-soft": "#341016",
    "danger-border": "#72232D",
    "kind-gateway": "#4CCCE6",
    "kind-gateway-soft": "#082C36",
    "kind-route": "#75C7F0",
    "kind-route-soft": "#0D2847",
    "kind-vs": "#B1A9FF",
    "kind-vs-soft": "#1F2045",
    "kind-dr": "#BAA7FF",
    "kind-dr-soft": "#291F43",
    "kind-svc": "#0BD8B6",
    "kind-svc-soft": "#0D2D2A",
    "kind-eps": "#B0B4BA",
    "kind-eps-soft": "#232427",
    "kind-ext": "#B0B4BA",
    "kind-ext-soft": "#18191B",
    "shadow-sm": "0 1px 2px rgba(0, 0, 0, 0.4)",
    "shadow-md": "0 1px 3px rgba(0, 0, 0, 0.45), 0 6px 16px -4px rgba(0, 0, 0, 0.5)",
    "shadow-lg": "0 16px 40px -8px rgba(0, 0, 0, 0.65), 0 2px 6px rgba(0, 0, 0, 0.4)",
    "focus-ring": "0 0 0 3px rgba(110, 106, 222, 0.45)",
}

#: Обратная совместимость: основная (светлая) палитра.
PALETTE = LIGHT

#: Пары «текст на фоне», которые должны проходить WCAG AA (4.5:1) в обеих темах.
TEXT_PAIRS: tuple[tuple[str, str], ...] = (
    ("text", "bg"), ("text", "surface"), ("text", "sidebar"),
    ("text-muted", "bg"), ("text-muted", "surface"), ("text-muted", "sidebar"), ("text-muted", "surface-2"),
    ("accent-text", "surface"), ("accent-text", "accent-soft"),
    ("on-accent", "accent"), ("on-accent", "accent-hover"), ("on-accent", "danger-solid"),
    ("success", "success-soft"), ("success", "surface"),
    ("warning", "warning-soft"), ("warning", "surface"),
    ("danger", "danger-soft"), ("danger", "surface"),
    ("kind-gateway", "kind-gateway-soft"), ("kind-route", "kind-route-soft"), ("kind-vs", "kind-vs-soft"),
    ("kind-dr", "kind-dr-soft"), ("kind-svc", "kind-svc-soft"), ("kind-eps", "kind-eps-soft"),
    ("kind-ext", "kind-ext-soft"),
)

#: Оформление узлов графа: токен цвета, токен фона иконки, аббревиатура, пунктир.
NODE_STYLES: dict[str, dict[str, str | bool]] = {
    "Gateway": {"color": "kind-gateway", "soft": "kind-gateway-soft", "abbr": "GW", "dashed": False},
    "Route": {"color": "kind-route", "soft": "kind-route-soft", "abbr": "RT", "dashed": False},
    "VirtualService": {"color": "kind-vs", "soft": "kind-vs-soft", "abbr": "VS", "dashed": False},
    "DestinationRule": {"color": "kind-dr", "soft": "kind-dr-soft", "abbr": "DR", "dashed": False},
    "Service": {"color": "kind-svc", "soft": "kind-svc-soft", "abbr": "SVC", "dashed": False},
    "EndpointSlice": {"color": "kind-eps", "soft": "kind-eps-soft", "abbr": "EPS", "dashed": False},
    "ExternalHost": {"color": "kind-ext", "soft": "kind-ext-soft", "abbr": "EXT", "dashed": True},
}

DEFAULT_NODE_STYLE: dict[str, str | bool] = {"color": "kind-eps", "soft": "kind-eps-soft", "abbr": "?", "dashed": False}

#: Inter — интерфейс, JetBrains Mono — данные (хосты, YAML, версии). Файлы шрифтов лежат
#: в ui/static/fonts (OFL 1.1); если не загрузились — системные шрифты.
FONT_SANS = '"Inter Variable", Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'
FONT_MONO = '"JetBrains Mono Variable", "JetBrains Mono", ui-monospace, SFMono-Regular, Consolas, monospace'

#: ANSI 256 цвета консоли — в тон веб-палитре (iris / teal / red).
ANSI_NODE = 147     # заголовки узлов — светлый iris
ANSI_BADGE = 116    # бейджи — мягкий cyan/teal
ANSI_ERROR = 203    # ошибки и битые ссылки — красный
ANSI_OK = 114       # успех — зелёный
ANSI_MUTED = 245    # служебный текст


def _block(selector: str, tokens: dict[str, str], scheme: str, extra: list[str] | None = None) -> str:
    lines = [f"  --{name}: {value};" for name, value in tokens.items()]
    lines.extend(extra or [])
    lines.append(f"  color-scheme: {scheme};")
    return selector + " {\n" + "\n".join(lines) + "\n}"


def css_variables() -> str:
    """CSS-переменные обеих тем.

    По умолчанию тема следует системной (``prefers-color-scheme``); атрибут
    ``data-theme="light|dark"`` на ``<html>`` закрепляет выбор пользователя.
    """
    fonts = [f"  --font-sans: {FONT_SANS};", f"  --font-mono: {FONT_MONO};"]
    dark_auto = _block(':root:not([data-theme="light"])', DARK, "dark")
    return "\n".join(
        [
            _block(":root", LIGHT, "light", fonts),
            "@media (prefers-color-scheme: dark) {",
            "\n".join("  " + line if line else line for line in dark_auto.splitlines()),
            "}",
            _block(':root[data-theme="dark"]', DARK, "dark"),
        ]
    )


def node_style(kind: str) -> dict[str, str | bool]:
    """Стиль узла заданного типа (имена токенов)."""
    return NODE_STYLES.get(kind, DEFAULT_NODE_STYLE)


def _channel(c: float) -> float:
    c /= 255
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def contrast_ratio(fg: str, bg: str) -> float:
    """Контраст WCAG 2.x двух цветов ``#RRGGBB``."""

    def lum(hex_color: str) -> float:
        h = hex_color.lstrip("#")
        r, g, b = (int(h[i : i + 2], 16) for i in (0, 2, 4))
        return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)

    a, b = sorted((lum(fg), lum(bg)), reverse=True)
    return (a + 0.05) / (b + 0.05)


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
        """Заголовок узла."""
        return self._wrap(ANSI_NODE, text, bold=True)

    def badge(self, text: str) -> str:
        """Бейдж."""
        return self._wrap(ANSI_BADGE, text)

    def error(self, text: str) -> str:
        """Ошибка / проблема."""
        return self._wrap(ANSI_ERROR, text, bold=True)

    def ok(self, text: str) -> str:
        """Успех."""
        return self._wrap(ANSI_OK, text)

    def muted(self, text: str) -> str:
        """Служебный текст."""
        return self._wrap(ANSI_MUTED, text)

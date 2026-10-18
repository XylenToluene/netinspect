"""Загрузка ресурсов из кластера или из каталога файлов.

Оба источника реализуют общий интерфейс :class:`Source`.
"""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Iterable, Iterator

from netinspect.core.client import ApiClient
from netinspect.core.discovery import ClusterInfo, discover
from netinspect.core.errors import ApiError, AuthError, ForbiddenError, SourceError, TLSError
from netinspect.core.model import Resource
from netinspect.core.resources import FORBIDDEN_KINDS, REGISTRY, get_type

try:  # PyYAML — опционально
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - зависит от окружения
    yaml = None

log = logging.getLogger(__name__)

LAST_APPLIED = "kubectl.kubernetes.io/last-applied-configuration"


def yaml_available() -> bool:
    """Установлен ли PyYAML."""
    return yaml is not None


def clean_manifest(obj: dict[str, Any]) -> dict[str, Any]:
    """Удалить ``managedFields`` и аннотацию last-applied-configuration (in place)."""
    meta = obj.get("metadata")
    if isinstance(meta, dict):
        meta.pop("managedFields", None)
        ann = meta.get("annotations")
        if isinstance(ann, dict):
            ann.pop(LAST_APPLIED, None)
            if not ann:
                meta.pop("annotations", None)
    return obj


class Source(ABC):
    """Источник ресурсов."""

    def __init__(self) -> None:
        #: Нефатальные предупреждения (недоступные типы, нечитаемые файлы).
        self.warnings: list[str] = []

    @abstractmethod
    def load(self, kinds: Iterable[str], namespaces: list[str] | None) -> list[Resource]:
        """Загрузить ресурсы заданных типов. ``namespaces=None`` — все namespace."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Описание источника для отчёта (адрес сервера или каталог)."""


class ClusterSource(Source):
    """Ресурсы из API кластера."""

    def __init__(self, client: ApiClient, info: ClusterInfo | None = None) -> None:
        super().__init__()
        self._client = client
        self._info = info

    @property
    def info(self) -> ClusterInfo:
        """Результат discovery (выполняется лениво, кэшируется)."""
        if self._info is None:
            self._info = discover(self._client)
        return self._info

    @property
    def description(self) -> str:
        return self._client.server

    def load(self, kinds: Iterable[str], namespaces: list[str] | None) -> list[Resource]:
        result: list[Resource] = []
        for kind in kinds:
            if kind in FORBIDDEN_KINDS:
                continue
            rt = get_type(kind)
            version = self.info.version_for(rt)
            if version is None:
                if not rt.optional:
                    self.warnings.append(f"{kind}: API {rt.group} недоступен в кластере")
                continue
            for ns in namespaces or [None]:
                path = rt.path(version, ns)
                try:
                    items = self._client.list_all(path)
                except (AuthError, TLSError):
                    raise
                except ForbiddenError:
                    where = f"в namespace {ns}" if ns else "во всех namespace"
                    self.warnings.append(f"{kind}: нет прав на list {where}")
                    continue
                except ApiError as exc:
                    self.warnings.append(f"{kind}: {exc}")
                    continue
                for item in items:
                    item.setdefault("kind", kind)
                    result.append(Resource.from_manifest(clean_manifest(item)))
        return result


class DirectorySource(Source):
    """Ресурсы из каталога файлов ``.json`` / ``.yaml`` / ``.yml``."""

    def __init__(self, path: str, default_namespace: str = "default") -> None:
        super().__init__()
        if not os.path.isdir(path):
            raise SourceError(f"каталог не найден: {path}")
        self._path = path
        self._default_ns = default_namespace

    @property
    def description(self) -> str:
        return f"dir:{os.path.abspath(self._path)}"

    def _files(self) -> list[str]:
        files: list[str] = []
        for root, _dirs, names in os.walk(self._path):
            for name in names:
                if name.lower().endswith((".json", ".yaml", ".yml")):
                    files.append(os.path.join(root, name))
        return sorted(files)

    def _read(self, path: str) -> list[Any]:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        if path.lower().endswith(".json"):
            return [json.loads(text)]
        if yaml is None:
            raise SourceError(
                f"{path}: для чтения YAML нужен PyYAML (pip install PyYAML) "
                "или сконвертируйте манифесты в JSON"
            )
        return [doc for doc in yaml.safe_load_all(text) if doc is not None]

    @staticmethod
    def _flatten(docs: Iterable[Any]) -> Iterator[dict[str, Any]]:
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            if doc.get("kind") == "List" or (doc.get("kind", "").endswith("List") and "items" in doc):
                yield from DirectorySource._flatten(doc.get("items") or [])
            else:
                yield doc

    def load(self, kinds: Iterable[str], namespaces: list[str] | None) -> list[Resource]:
        wanted = set(kinds) - FORBIDDEN_KINDS
        ns_filter = set(namespaces) if namespaces else None
        result: list[Resource] = []
        yaml_skipped = 0
        for path in self._files():
            try:
                docs = self._read(path)
            except SourceError as exc:
                if yaml is None:
                    yaml_skipped += 1
                    log.debug("%s", exc)
                    continue
                raise
            except (OSError, ValueError) as exc:
                self.warnings.append(f"{path}: не удалось прочитать: {exc}")
                continue
            for obj in self._flatten(docs):
                if obj.get("kind") not in wanted:
                    continue
                res = Resource.from_manifest(clean_manifest(obj), self._default_ns)
                if ns_filter is not None and res.namespace not in ns_filter:
                    continue
                result.append(res)
        if yaml_skipped:
            self.warnings.append(
                f"пропущено YAML-файлов: {yaml_skipped} — установите PyYAML или используйте JSON"
            )
        return result


def default_kinds(include_routes: bool = True) -> list[str]:
    """Типы, загружаемые по умолчанию для построения графа."""
    return [rt.kind for rt in REGISTRY if include_routes or rt.kind != "Route"]

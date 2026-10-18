"""Командная строка netinspect: ``connect``, ``get``, ``graph``."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import NoReturn, Sequence, TextIO

from netinspect import __version__
from netinspect.core.access import check_access, cluster_version, whoami
from netinspect.core.client import ApiClient
from netinspect.core.config import DEFAULT_TIMEOUT, ENV_CA, ENV_SERVER, ENV_TOKEN, build_config
from netinspect.core.discovery import discover
from netinspect.core.errors import NetinspectError
from netinspect.core.fetcher import ClusterSource, DirectorySource, Source, default_kinds, yaml
from netinspect.core.hosts import DEFAULT_DOMAIN, normalize, to_fqdn
from netinspect.core.model import Resource
from netinspect.core.resources import resolve_kind
from netinspect.graph.builder import build_graph
from netinspect.graph.render_web import export_web
from netinspect.graph.render_text import render_summary, render_tree
from netinspect.graph.traverse import host_subgraph, parse_resource_ref, subgraph
from netinspect.ui.theme import Ansi, color_enabled

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_PROBLEMS = 2

log = logging.getLogger("netinspect")


# --- аргументы --------------------------------------------------------------


def _add_connection_args(p: argparse.ArgumentParser, server_required: bool = False) -> None:
    g = p.add_argument_group("подключение к кластеру")
    g.add_argument("--server", help=f"URL API, например https://api.cluster.example:6443 (или {ENV_SERVER})")
    g.add_argument(
        "--token-env",
        metavar="NAME",
        help=f"имя переменной окружения с токеном (по умолчанию {ENV_TOKEN}, иначе ввод с клавиатуры)",
    )
    tls = g.add_mutually_exclusive_group()
    tls.add_argument("--ca-file", metavar="PATH", help=f"CA-сертификат API (или {ENV_CA})")
    tls.add_argument("--insecure", action="store_true", help="не проверять сертификат сервера (только для отладки)")
    g.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="таймаут запроса, с (по умолчанию 15)")
    g.add_argument("--proxy", metavar="URL", help="HTTP(S)-прокси")


def _add_ns_args(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("-n", "--namespace", action="append", dest="namespaces", metavar="NS",
                   help="namespace (можно указать несколько раз); по умолчанию — все")
    g.add_argument("-A", "--all-namespaces", action="store_true", help="все namespace")


class _Parser(argparse.ArgumentParser):
    """ArgumentParser с кодом выхода 1 при ошибке (2 зарезервирован под «найдены проблемы»)."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: ошибка: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    """Парсер аргументов командной строки."""
    parser = _Parser(
        prog="netinspect",
        description="Диагностика сетевых правил OpenShift / Kubernetes (Istio)",
    )
    parser.add_argument("--version", action="version", version=f"netinspect {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="подробный лог (-vv — отладка)")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="count", default=argparse.SUPPRESS,
                        help="подробный лог (-vv — отладка)")
    sub = parser.add_subparsers(dest="command", required=True, metavar="КОМАНДА", parser_class=_Parser)

    p = sub.add_parser("connect", parents=[common], help="проверить подключение: версия, пользователь, права")
    _add_connection_args(p)
    p.add_argument("-n", "--namespace", dest="namespace", metavar="NS", help="namespace для проверки прав")

    p = sub.add_parser("get", parents=[common], help="вывести ресурсы одного типа")
    p.add_argument("kind", metavar="KIND", help="тип: gw, vs, dr, svc, endpointslice, route или полное имя")
    _add_ns_args(p)
    p.add_argument("--from-dir", metavar="DIR", help="читать манифесты из каталога вместо кластера")
    p.add_argument("-o", "--output", choices=("table", "json", "yaml"), default="table")
    p.add_argument("--cluster-domain", default=DEFAULT_DOMAIN, help="домен кластера (cluster.local)")
    _add_connection_args(p)

    p = sub.add_parser("graph", parents=[common], help="построить граф связей")
    entry = p.add_mutually_exclusive_group()
    entry.add_argument("--host", help="точка входа: хост (Gateway, VirtualService, Route)")
    entry.add_argument("--resource", help="точка входа: KIND/NS/NAME, например vs/prod/reviews")
    _add_ns_args(p)
    p.add_argument("--from-dir", metavar="DIR", help="читать манифесты из каталога вместо кластера")
    p.add_argument("--web-dir", metavar="DIR",
                   help="выгрузить веб-интерфейс (index.html, style.css, app.js, graph.json) для nginx")
    p.add_argument("--no-color", action="store_true", help="без ANSI-цветов")
    p.add_argument("--cluster-domain", default=DEFAULT_DOMAIN, help="домен кластера (cluster.local)")
    _add_connection_args(p)
    return parser


# --- общие помощники --------------------------------------------------------


def _client(args: argparse.Namespace, err: TextIO) -> ApiClient:
    config = build_config(
        server=args.server,
        token_env=args.token_env,
        ca_file=args.ca_file,
        insecure=args.insecure,
        timeout=args.timeout,
        proxy=args.proxy,
    )
    if config.insecure:
        print("ВНИМАНИЕ: проверка TLS-сертификата отключена (--insecure)", file=err)
    log.debug("подключение: %r", config)
    return ApiClient(config)


def _namespaces(args: argparse.Namespace) -> list[str] | None:
    if getattr(args, "all_namespaces", False):
        return None
    return list(args.namespaces) if args.namespaces else None


def _source(args: argparse.Namespace, err: TextIO) -> Source:
    if args.from_dir:
        return DirectorySource(args.from_dir)
    return ClusterSource(_client(args, err))


def _table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        widths = [max(w, len(c)) for w, c in zip(widths, row)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*headers)]
    lines.extend(fmt.format(*row) for row in rows)
    return "\n".join(line.rstrip() for line in lines)


# --- connect ----------------------------------------------------------------


def cmd_connect(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    """Проверка подключения: версия, пользователь, права на типы реестра."""
    client = _client(args, err)
    print(f"Сервер:       {client.server}", file=out)
    print(f"Версия:       {cluster_version(client)}", file=out)
    user = whoami(client)
    print(f"Пользователь: {user or 'n/a'}", file=out)
    info = discover(client)
    print(f"Istio API:    {info.istio_version or 'не найден'}", file=out)
    print(f"OpenShift:    {'да' if info.is_openshift else 'нет'}", file=out)
    scope = args.namespace or "все namespace"
    print(f"\nПрава на list ({scope}):", file=out)
    rows = []
    for res in check_access(client, args.namespace):
        rows.append([res.kind, res.resource, "да" if res.allowed else "нет", res.reason])
    print(_table(rows, ["KIND", "RESOURCE", "МОЖНО ЧИТАТЬ", "ПРИЧИНА"]), file=out)
    return EXIT_OK


# --- get --------------------------------------------------------------------


def _vs_row(res: Resource, domain: str) -> list[str]:
    spec = res.spec
    dests: list[str] = []
    for section in ("http", "tcp", "tls"):
        for rule in spec.get(section) or []:
            for route in (rule or {}).get("route") or []:
                host = ((route or {}).get("destination") or {}).get("host")
                if host:
                    fqdn = to_fqdn(str(host), res.namespace, domain)
                    if fqdn not in dests:
                        dests.append(fqdn)
    return [
        res.namespace,
        res.name,
        ",".join(normalize(str(h)) for h in spec.get("hosts") or []),
        ",".join(str(g) for g in spec.get("gateways") or []) or "(mesh)",
        ",".join(dests),
    ]


def _generic_row(res: Resource) -> list[str]:
    spec = res.spec
    info = ""
    if res.kind == "Gateway":
        hosts = [str(h) for s in spec.get("servers") or [] for h in (s or {}).get("hosts") or []]
        info = ",".join(hosts)
    elif res.kind == "DestinationRule":
        subsets = ",".join(str((s or {}).get("name")) for s in spec.get("subsets") or [])
        info = f"{spec.get('host', '')}" + (f" subsets={subsets}" if subsets else "")
    elif res.kind == "Service":
        ports = ",".join(f"{p.get('port')}/{p.get('protocol', 'TCP')}" for p in spec.get("ports") or [])
        info = f"{spec.get('type', 'ClusterIP')} {ports}"
    elif res.kind == "EndpointSlice":
        eps = res.raw.get("endpoints") or []
        ready = sum(1 for e in eps if ((e or {}).get("conditions") or {}).get("ready") is not False)
        info = f"service={res.labels.get('kubernetes.io/service-name', '')} ready={ready}/{len(eps)}"
    elif res.kind == "Route":
        info = f"{spec.get('host', '')} -> {(spec.get('to') or {}).get('name', '')}"
    return [res.namespace, res.name, info]


def cmd_get(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    """Вывести ресурсы одного типа."""
    kind = resolve_kind(args.kind)
    source = _source(args, err)
    resources = sorted(source.load([kind], _namespaces(args)), key=lambda r: (r.namespace, r.name))
    for warning in source.warnings:
        print(f"предупреждение: {warning}", file=err)
    if args.output == "json":
        print(json.dumps({"kind": "List", "items": [r.raw for r in resources]}, indent=2, ensure_ascii=False), file=out)
    elif args.output == "yaml":
        if yaml is None:
            print("ошибка: для -o yaml нужен PyYAML (pip install PyYAML); используйте -o json", file=err)
            return EXIT_ERROR
        print(yaml.safe_dump_all([r.raw for r in resources], sort_keys=False, allow_unicode=True), file=out, end="")
    elif kind == "VirtualService":
        rows = [_vs_row(r, args.cluster_domain) for r in resources]
        print(_table(rows, ["NAMESPACE", "NAME", "HOSTS", "GATEWAYS", "DESTINATIONS"]), file=out)
    else:
        rows = [_generic_row(r) for r in resources]
        print(_table(rows, ["NAMESPACE", "NAME", "INFO"]), file=out)
    if not resources:
        print(f"{kind}: ресурсы не найдены", file=err)
    return EXIT_OK


# --- graph ------------------------------------------------------------------


def cmd_graph(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    """Построить граф, вывести дерево и (опционально) выгрузить веб-интерфейс."""
    source = _source(args, err)
    resources = source.load(default_kinds(), _namespaces(args))
    full = build_graph(resources, args.cluster_domain)
    if args.host:
        graph = host_subgraph(full, args.host)
        if not graph.nodes:
            print(f"ошибка: не найдено Gateway, VirtualService или Route для хоста {args.host}", file=err)
            return EXIT_ERROR
    elif args.resource:
        key = parse_resource_ref(args.resource)
        if key not in full.nodes:
            print(f"ошибка: ресурс {key} не найден", file=err)
            return EXIT_ERROR
        graph = subgraph(full, [key])
    else:
        graph = full

    ansi = Ansi(enabled=color_enabled(out, args.no_color))
    if graph.nodes:
        print(render_tree(graph, ansi), file=out)
    else:
        print("ресурсы не найдены", file=out)
    print(render_summary(graph, source.warnings, ansi), file=out)

    if args.web_dir:
        export_web(graph, args.web_dir, server=source.description, warnings=source.warnings)
        print(f"Веб-интерфейс: {args.web_dir} (раздайте каталог через nginx, см. deploy/nginx)", file=out)
    return EXIT_PROBLEMS if graph.problem_nodes() else EXIT_OK


def _setup_logging(verbose: int, err: TextIO) -> None:
    level = logging.WARNING if verbose == 0 else logging.INFO if verbose == 1 else logging.DEBUG
    logger = logging.getLogger("netinspect")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler(err)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


COMMANDS = {"connect": cmd_connect, "get": cmd_get, "graph": cmd_graph}


def main(argv: Sequence[str] | None = None, out: TextIO | None = None, err: TextIO | None = None) -> int:
    """Точка входа CLI. Возвращает код выхода (0 — ок, 1 — ошибка, 2 — найдены проблемы)."""
    out = out or sys.stdout
    err = err or sys.stderr
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose, err)
    try:
        return COMMANDS[args.command](args, out, err)
    except NetinspectError as exc:
        print(f"ошибка: {exc}", file=err)
        return EXIT_ERROR
    except ValueError as exc:
        print(f"ошибка: {exc}", file=err)
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_OK
    except OSError as exc:
        print(f"ошибка ввода-вывода: {exc}", file=err)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("прервано", file=err)
        return EXIT_ERROR

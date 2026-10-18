"""Командная строка netinspect: ``connect``, ``get``, ``graph``."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import NoReturn, Sequence, TextIO

from netinspect import __version__
from netinspect.core.access import connection_report
from netinspect.core.client import ApiClient
from netinspect.core.config import DEFAULT_TIMEOUT, ENV_SERVER, ENV_TOKEN, build_config
from netinspect.core.errors import NetinspectError
from netinspect.core.fetcher import ClusterSource, DirectorySource, Source, default_kinds, yaml
from netinspect.core.hosts import DEFAULT_DOMAIN, normalize, to_fqdn
from netinspect.core.model import Resource
from netinspect.core.resources import resolve_kind
from netinspect.graph.builder import build_graph
from netinspect.graph.render_web import export_web
from netinspect.graph.traverse import host_subgraph, parse_resource_ref, subgraph

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

    p = sub.add_parser("serve", parents=[common], help="запустить бэкенд веб-интерфейса (за nginx)")
    p.add_argument("--listen", default="127.0.0.1", metavar="HOST",
                   help="адрес (по умолчанию 127.0.0.1 — доступ только с этой машины)")
    p.add_argument("--port", type=int, default=8081, help="порт (по умолчанию 8081)")
    p.add_argument("--session-ttl", type=float, default=480, metavar="MIN",
                   help="время жизни неактивной сессии, минут (по умолчанию 480)")
    p.add_argument("--graph-dir", default="web", metavar="DIR",
                   help="каталог с graph.json для страницы «Граф» (graph --web-dir DIR), по умолчанию web")
    p.add_argument("--api-only", action="store_true",
                   help="не раздавать интерфейс — только /api/ (когда интерфейс раздаёт nginx)")

    p = sub.add_parser("get", parents=[common], help="вывести ресурсы одного типа")
    p.add_argument("kind", metavar="KIND", help="тип: gw, vs, dr, svc, endpointslice, route или полное имя")
    _add_ns_args(p)
    p.add_argument("--from-dir", metavar="DIR", help="читать манифесты из каталога вместо кластера")
    p.add_argument("-o", "--output", choices=("table", "json", "yaml"), default="table")
    p.add_argument("--cluster-domain", default=DEFAULT_DOMAIN, help="домен кластера (cluster.local)")
    _add_connection_args(p)

    p = sub.add_parser("graph", parents=[common], help="построить граф связей для веб-интерфейса")
    entry = p.add_mutually_exclusive_group()
    entry.add_argument("--host", help="точка входа: хост (Gateway, VirtualService, Route)")
    entry.add_argument("--resource", help="точка входа: KIND/NS/NAME, например vs/prod/reviews")
    _add_ns_args(p)
    p.add_argument("--from-dir", metavar="DIR", help="читать манифесты из каталога вместо кластера")
    p.add_argument("--web-dir", metavar="DIR", default="web",
                   help="куда выгрузить граф для веб-интерфейса (graph.json и страницы), по умолчанию web")
    p.add_argument("--cluster-domain", default=DEFAULT_DOMAIN, help="домен кластера (cluster.local)")
    _add_connection_args(p)
    return parser


# --- общие помощники --------------------------------------------------------


def _client(args: argparse.Namespace, err: TextIO) -> ApiClient:
    config = build_config(
        server=args.server,
        token_env=args.token_env,
        timeout=args.timeout,
        proxy=args.proxy,
    )
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
    """Проверка подключения: версия, пользователь, ресурсы Istio и права на list."""
    client = _client(args, err)
    report = connection_report(client, args.namespace)
    print(f"Сервер:       {report.server}", file=out)
    print(f"Версия:       {report.version}", file=out)
    print(f"Пользователь: {report.user or 'n/a'}", file=out)
    print(f"Istio API:    {', '.join(report.istio_groups) or 'не найден'}", file=out)
    print(f"OpenShift:    {'да' if report.openshift else 'нет'}", file=out)
    scope = args.namespace or "все namespace"
    print(f"\nПрава на list ({scope}):", file=out)
    rows = [
        [res.kind, res.group_version, "да" if acc.allowed else "нет", acc.reason]
        for res, acc in report.resources
    ]
    print(_table(rows, ["KIND", "API", "МОЖНО ЧИТАТЬ", "ПРИЧИНА"]), file=out)
    for warning in report.warnings:
        print(f"предупреждение: {warning}", file=err)
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
    """Построить граф и выгрузить его для страницы «Граф» веб-интерфейса."""
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

    for warning in source.warnings:
        print(f"предупреждение: {warning}", file=err)
    export_web(graph, args.web_dir, server=source.description, warnings=source.warnings)
    problems = len(graph.problem_nodes())
    print(
        f"Граф выгружен в {args.web_dir}: узлов {len(graph.nodes)}, связей {len(graph.edges)}, "
        f"с проблемами {problems}. Смотреть: python -m netinspect serve --graph-dir {args.web_dir} "
        "→ http://127.0.0.1:8081/graph.html",
        file=out,
    )
    return EXIT_PROBLEMS if problems else EXIT_OK


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


def cmd_serve(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    """Запустить бэкенд веб-интерфейса. Токен вводится в браузере после запуска."""
    from netinspect.server.app import STATIC_DIR, is_loopback, make_server
    from netinspect.server.sessions import SessionStore

    if not is_loopback(args.listen):
        print(
            f"ВНИМАНИЕ: бэкенд слушает {args.listen} — токены пользователей пойдут по сети. "
            "Используйте HTTPS (nginx) или слушайте 127.0.0.1",
            file=err,
        )
    httpd = make_server(
        args.listen,
        args.port,
        SessionStore(ttl=args.session_ttl * 60),
        static_dir=None if args.api_only else STATIC_DIR,
        graph_dir=args.graph_dir,
    )
    host, port = httpd.server_address[:2]
    if args.api_only:
        print(f"netinspect API: http://{host}:{port}/api/ (интерфейс — через nginx)", file=out)
    else:
        print(f"netinspect: откройте в браузере http://{host}:{port}/", file=out)
    print("Ctrl+C — остановить", file=out)
    out.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("остановлено", file=out)
    finally:
        httpd.server_close()
    return EXIT_OK


COMMANDS = {"connect": cmd_connect, "get": cmd_get, "graph": cmd_graph, "serve": cmd_serve}


def main(argv: Sequence[str] | None = None, out: TextIO | None = None, err: TextIO | None = None) -> int:
    """Точка входа CLI. Возвращает код выхода (0 — ок, 1 — ошибка, 2 — найдены проблемы)."""
    out = out or sys.stdout
    err = err or sys.stderr
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose + (1 if args.command == "serve" else 0), err)
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

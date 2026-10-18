import io
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from netinspect import cli
from netinspect.core.model import Graph, Node, Resource
from netinspect.graph.render_web import STATIC_DIR, export_web, theme_css
from netinspect.ui import theme
from tests.test_builder import FIXTURES, load_fixture_graph

class WebExportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.g = load_fixture_graph()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = cls.tmp.name
        cls.written = export_web(cls.g, cls.out, server="dir:fixtures", warnings=["<b>warn</b>"])

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def read(self, name: str) -> str:
        with open(os.path.join(self.out, name), encoding="utf-8") as fh:
            return fh.read()

    def test_files(self) -> None:
        self.assertEqual(
            sorted(os.listdir(self.out)),
            ["app.js", "connect.js", "fonts", "graph.html", "graph.json", "index.html",
             "shell.js", "style.css", "theme-init.js", "theme.css"],
        )
        fonts = sorted(os.listdir(os.path.join(self.out, "fonts")))
        self.assertIn("inter-cyrillic-wght-normal.woff2", fonts)
        self.assertIn("jetbrains-mono-latin-wght-normal.woff2", fonts)
        self.assertIn("LICENSE-Inter.txt", fonts)
        self.assertEqual(len(self.written), 9 + len(fonts))

    def test_pages_have_no_inline_code(self) -> None:
        for name, script in (("index.html", "connect.js"), ("graph.html", "app.js")):
            page = self.read(name)
            # строгий CSP nginx: никаких inline-скриптов, стилей, style- и on*-атрибутов
            self.assertNotRegex(page, r"<script(?![^>]*\bsrc=)[^>]*>", name)
            self.assertNotIn("<style", page, name)
            self.assertNotIn("style=", page, name)
            self.assertNotRegex(page, r"\son[a-z]+=", name)
            for ref in ('href="theme.css"', 'href="style.css"', f'src="{script}"', 'src="shell.js"',
                        'src="theme-init.js"'):
                self.assertIn(ref, page, name)
            # тема применяется до отрисовки: theme-init.js без defer и раньше стилей не грузится позже
            self.assertNotRegex(page, r'<script src="theme-init.js"[^>]*defer')

    def test_no_external_urls(self) -> None:
        # namespace SVG и примеры адреса API в подсказках
        allowed = {"http://www.w3.org/2000/svg", "https://api.cluster.example:6443", "https://api."}
        for name in ("index.html", "graph.html", "style.css", "app.js", "connect.js", "shell.js",
                     "theme-init.js", "theme.css"):
            text = self.read(name)
            self.assertNotIn("@import", text)
            # адреса 127.0.0.1 — подсказки «откройте http://127.0.0.1:8081/…» в тексте
            urls = {u for u in re.findall(r"https?://[^\s\"'<>)]+", text) if not u.startswith("http://127.0.0.1")}
            self.assertLessEqual(urls, allowed, name)
            self.assertNotRegex(text, r"(src|href)=\"(https?:)?//", name)

    def test_theme_css_from_palette(self) -> None:
        css = self.read("theme.css")
        for name, value in theme.PALETTE.items():
            self.assertIn(f"--{name}: {value};", css)
        # style.css не задаёт своих hex-цветов — только переменные палитры
        self.assertIsNone(re.search(r"#[0-9a-fA-F]{3,8}\b", self.read("style.css")))

    def test_graph_json(self) -> None:
        data = json.loads(self.read("graph.json"))
        self.assertEqual(len(data["nodes"]), len(self.g.nodes))
        self.assertEqual(len(data["edges"]), len(self.g.edges))
        self.assertEqual(data["meta"]["server"], "dir:fixtures")
        self.assertEqual(data["meta"]["problems"], 7)
        self.assertEqual(data["meta"]["warnings"], ["<b>warn</b>"])  # экранирует UI (textContent)
        gw = next(n for n in data["nodes"] if n["key"] == "Gateway/prod/public-gw")
        self.assertIn("public-gw", gw["manifest"])
        self.assertNotIn("managedFields", gw["manifest"])
        self.assertEqual(data["styles"]["Gateway"]["color"], "var(--kind-gateway)")
        self.assertEqual(data["styles"]["ExternalHost"]["abbr"], "EXT")
        self.assertTrue(data["styles"]["ExternalHost"]["dashed"])

    def test_ui_does_not_use_innerhtml(self) -> None:
        for name in ("app.js", "connect.js", "shell.js", "theme-init.js"):
            js = self.read(name)
            self.assertNotIn("innerHTML", js, name)
            self.assertNotIn("eval(", js, name)
        self.assertIn("graph.json", self.read("app.js"))
        connect = self.read("connect.js")
        self.assertIn("X-Netinspect", connect)
        # токен не сохраняется в браузере
        self.assertNotIn("localStorage", connect)
        self.assertNotIn("sessionStorage", connect)
        self.assertNotIn("document.cookie", connect)

    def test_committed_theme_css_is_current(self) -> None:
        with open(os.path.join(STATIC_DIR, "theme.css"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), theme_css(), "обновите netinspect/ui/static/theme.css из ui/theme.py")

    def test_reexport_overwrites(self) -> None:
        g = Graph()
        res = Resource.from_manifest({"kind": "Service", "metadata": {"name": "x", "namespace": "n"}, "spec": {}})
        g.add_node(Node(res.key, res.kind, res.namespace, res.name, resource=res))
        with tempfile.TemporaryDirectory() as tmp:
            export_web(self.g, tmp, server="a")
            export_web(g, tmp, server="b")
            with open(os.path.join(tmp, "graph.json"), encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["meta"]["server"], "b")
            self.assertEqual(len(data["nodes"]), 1)
            self.assertFalse([n for n in os.listdir(tmp) if n.startswith(".")])


class NginxConfigTest(unittest.TestCase):
    ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "deploy", "nginx")

    def read(self, name: str) -> str:
        with open(os.path.join(self.ROOT, name), encoding="utf-8") as fh:
            return fh.read()

    def test_common_rules(self) -> None:
        conf = self.read("netinspect-common.inc")
        self.assertIn("Content-Security-Policy", conf)
        self.assertIn("script-src 'self'", conf)
        self.assertIn("deny all", conf)
        self.assertIn("location /api/", conf)
        self.assertIn("proxy_pass http://127.0.0.1:8081;", conf)
        self.assertIn("limit_except GET", conf)
        directives = "\n".join(line.split("#", 1)[0] for line in conf.splitlines())
        self.assertNotIn("$request_body", directives)

    def test_includes(self) -> None:
        system = self.read("netinspect.conf")
        local = self.read("nginx-local.conf")
        self.assertIn("include conf.d/netinspect-common.inc;", system)
        self.assertIn("include netinspect-common.inc;", local)
        self.assertIn("location = /graph.json", system)
        self.assertIn("location = /graph.json", local)
        self.assertIn("root netinspect/ui/static;", local)


class CliTest(unittest.TestCase):
    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(list(argv), out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def test_graph_exit_code_and_web_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "web")
            code, out, _ = self.run_cli("graph", "--from-dir", FIXTURES, "-A", "--web-dir", path)
            self.assertEqual(code, cli.EXIT_PROBLEMS)
            # в консоль граф не выводится — только итоговая строка
            self.assertEqual(len(out.strip().splitlines()), 1)
            self.assertIn("с проблемами 7", out)
            self.assertNotIn("└──", out)
            self.assertNotIn("\x1b[", out)
            self.assertTrue(os.path.getsize(os.path.join(path, "graph.json")) > 1000)
            self.assertTrue(os.path.isfile(os.path.join(path, "index.html")))

    def graph_keys(self, *args: str) -> tuple[int, set[str]]:
        with tempfile.TemporaryDirectory() as tmp:
            code, _, _ = self.run_cli("graph", "--from-dir", FIXTURES, "--web-dir", tmp, *args)
            with open(os.path.join(tmp, "graph.json"), encoding="utf-8") as fh:
                return code, {n["key"] for n in json.load(fh)["nodes"]}

    def test_graph_clean_subgraph(self) -> None:
        code, keys = self.graph_keys("--resource", "vs/prod/reviews")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("EndpointSlice/prod/reviews-abc12", keys)

    def test_graph_host(self) -> None:
        code, keys = self.graph_keys("--host", "api.example.com")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertNotIn("VirtualService/prod/ratings", keys)

    def test_graph_unknown_resource(self) -> None:
        code, _, err = self.run_cli("graph", "--from-dir", FIXTURES, "--resource", "vs/prod/nope")
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("не найден", err)

    def test_get_vs_table(self) -> None:
        code, out, _ = self.run_cli("get", "vs", "--from-dir", FIXTURES, "-n", "staging")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("DESTINATIONS", out)
        self.assertIn("reviews.prod.svc.cluster.local,productpage.staging.svc.cluster.local", out)
        self.assertIn("prod/public-gw", out)

    def test_get_json(self) -> None:
        code, out, _ = self.run_cli("get", "svc", "--from-dir", FIXTURES, "-A", "-o", "json")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(len(json.loads(out)["items"]), 4)

    def test_get_unknown_kind(self) -> None:
        code, _, err = self.run_cli("get", "secret", "--from-dir", FIXTURES)
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("неизвестный тип", err)

    def test_connect_auth_error_hides_token(self) -> None:
        token = "sha256~VerySecretToken9876"
        from tests.test_client import FakeOpener, http_error

        opener = FakeOpener({"/version": http_error("https://api.x:6443/version", 401)})
        with mock.patch.dict(os.environ, {"NETINSPECT_TOKEN": token}), \
                mock.patch("urllib.request.OpenerDirector.open", side_effect=lambda req, timeout=None: opener(req)):
            code, out, err = self.run_cli("connect", "--server", "https://api.cluster.example:6443", "-vv")
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("oc whoami -t", err)
        self.assertNotIn(token, out + err)
        self.assertIn("****9876", err)  # отладочный лог показывает только маску
        self.assertNotIn("Traceback", err)

    def test_bad_args_exit_1(self) -> None:
        with mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                cli.main(["graph", "--bogus"])
        self.assertEqual(ctx.exception.code, cli.EXIT_ERROR)


if __name__ == "__main__":
    unittest.main()

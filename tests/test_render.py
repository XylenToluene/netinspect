import io
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from netinspect import cli
from netinspect.core.model import Graph, Node, Resource
from netinspect.graph.render_web import export_web
from netinspect.graph.render_text import SEEN_MARK, render_summary, render_tree
from netinspect.ui import theme
from netinspect.ui.theme import Ansi, color_enabled
from tests.test_builder import FIXTURES, load_fixture_graph

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class TextRenderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.g = load_fixture_graph()

    def test_tree_plain(self) -> None:
        text = render_tree(self.g, Ansi(enabled=False))
        self.assertNotIn("\x1b[", text)
        self.assertIn("Gateway prod/public-gw  [*.example.com:443]", text)
        self.assertIn("└── VirtualService prod/legacy", text)
        self.assertIn("⚠ Gateway prod/legacy-gw", text)
        self.assertIn("[subset v3 ✗]", text)
        self.assertIn("[3 ready]", text)
        self.assertIn(SEEN_MARK, text)
        # каждый узел развёрнут ровно один раз
        for key, node in self.g.nodes.items():
            title = f"{node.kind} {node.namespace}/{node.name}" if node.kind != "ExternalHost" else f"ExternalHost {node.name}"
            pattern = re.compile(r"(^|── |⚠ )" + re.escape(title) + r"( |$)")
            full = [line for line in text.splitlines() if pattern.search(line) and SEEN_MARK not in line]
            self.assertEqual(len(full), 1, key)

    def test_roots_first(self) -> None:
        lines = render_tree(self.g).splitlines()
        self.assertTrue(lines[0].startswith("⚠ Gateway prod/legacy-gw"))

    def test_tree_colored(self) -> None:
        text = render_tree(self.g, Ansi(enabled=True))
        self.assertIn("\x1b[1;38;5;110m", text)
        self.assertIn("\x1b[38;5;180m", text)
        self.assertIn("\x1b[1;38;5;124m", text)
        self.assertEqual(ANSI_RE.sub("", text), render_tree(self.g, Ansi(enabled=False)))

    def test_summary(self) -> None:
        text = render_summary(self.g, ["warn-1"])
        self.assertIn("Проблемы (4)", text)
        self.assertIn("warn-1", text)

    def test_color_enabled(self) -> None:
        tty = mock.Mock(isatty=lambda: True)
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(color_enabled(tty))
            self.assertFalse(color_enabled(tty, force_off=True))
            self.assertFalse(color_enabled(io.StringIO()))
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertFalse(color_enabled(tty))


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
            ["app.js", "graph.json", "index.html", "style.css", "theme.css"],
        )
        self.assertEqual(len(self.written), 5)

    def test_index_has_no_inline_code(self) -> None:
        page = self.read("index.html")
        # строгий CSP nginx: никаких inline-скриптов, стилей и style-атрибутов
        self.assertNotRegex(page, r"<script(?![^>]*\bsrc=)[^>]*>")
        self.assertNotIn("<style", page)
        self.assertNotIn("style=", page)
        for ref in ('href="theme.css"', 'href="style.css"', 'src="app.js"'):
            self.assertIn(ref, page)

    def test_no_external_urls(self) -> None:
        for name in ("index.html", "style.css", "app.js", "theme.css"):
            text = self.read(name)
            self.assertNotIn("@import", text)
            urls = set(re.findall(r"https?://[^\s\"'<>)]+", text))
            self.assertLessEqual(urls, {"http://www.w3.org/2000/svg"}, name)

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
        self.assertEqual(data["meta"]["problems"], 4)
        self.assertEqual(data["meta"]["warnings"], ["<b>warn</b>"])  # экранирует UI (textContent)
        gw = next(n for n in data["nodes"] if n["key"] == "Gateway/prod/public-gw")
        self.assertIn("public-gw", gw["manifest"])
        self.assertNotIn("managedFields", gw["manifest"])
        self.assertEqual(data["styles"]["Gateway"]["fill"], "var(--blue-300)")

    def test_ui_does_not_use_innerhtml(self) -> None:
        js = self.read("app.js")
        self.assertNotIn("innerHTML", js)
        self.assertNotIn("eval(", js)
        self.assertIn("graph.json", js)

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
        self.assertIn("location = /graph.json", conf)
        self.assertIn("deny all", conf)

    def test_includes(self) -> None:
        self.assertIn("include conf.d/netinspect-common.inc;", self.read("netinspect.conf"))
        self.assertIn("include netinspect-common.inc;", self.read("nginx-local.conf"))


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
            self.assertNotIn("\x1b[", out)  # StringIO — не терминал
            self.assertTrue(os.path.getsize(os.path.join(path, "graph.json")) > 1000)
            self.assertTrue(os.path.isfile(os.path.join(path, "index.html")))

    def test_graph_clean_subgraph(self) -> None:
        code, out, _ = self.run_cli("graph", "--from-dir", FIXTURES, "--resource", "vs/prod/reviews")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("EndpointSlice prod/reviews-abc12", out)

    def test_graph_host(self) -> None:
        code, out, _ = self.run_cli("graph", "--from-dir", FIXTURES, "--host", "api.example.com")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertNotIn("ratings", out)

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

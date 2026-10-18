import io
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from netinspect import cli
from netinspect.core.model import Graph, Node, Resource
from netinspect.graph.render_html import render_html, safe_json
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


class HtmlRenderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.g = load_fixture_graph()
        cls.page = render_html(cls.g, server="dir:fixtures", warnings=["<b>warn</b>"])

    def test_self_contained(self) -> None:
        self.assertNotRegex(self.page, r"<(script|link|img)[^>]+(src|href)=")
        self.assertNotIn("@import", self.page)
        urls = set(re.findall(r"https?://[^\s\"'<>)]+", self.page))
        self.assertEqual(urls, {"http://www.w3.org/2000/svg"})

    def test_palette(self) -> None:
        for name, value in theme.PALETTE.items():
            self.assertIn(f"--{name}: {value};", self.page)
        self.assertIn("#7B1E3A", self.page)

    def test_embedded_data(self) -> None:
        m = re.search(r'<script type="application/json" id="graph-data">(.*?)</script>', self.page, re.S)
        assert m is not None
        data = json.loads(m.group(1))
        self.assertEqual(len(data["nodes"]), len(self.g.nodes))
        self.assertEqual(len(data["edges"]), len(self.g.edges))
        gw = next(n for n in data["nodes"] if n["key"] == "Gateway/prod/public-gw")
        self.assertIn("public-gw", gw["manifest"])
        self.assertNotIn("managedFields", gw["manifest"])

    def test_warnings_escaped(self) -> None:
        self.assertIn("&lt;b&gt;warn&lt;/b&gt;", self.page)
        self.assertNotIn("<b>warn</b>", self.page)

    def test_script_breakout_escaped(self) -> None:
        evil = Resource.from_manifest(
            {
                "kind": "Service",
                "metadata": {"name": "x", "namespace": "n", "annotations": {"a": "</script><script>alert(1)</script>"}},
                "spec": {},
            }
        )
        g = Graph()
        g.add_node(Node(evil.key, evil.kind, evil.namespace, evil.name, resource=evil))
        page = render_html(g, server="s")
        self.assertNotIn("alert(1)</script>", page)
        self.assertEqual(page.count("</script>"), 2)
        self.assertNotIn("</", safe_json({"a": "</script>"}))
        self.assertEqual(json.loads(safe_json({"a": "</script>&"})), {"a": "</script>&"})


class CliTest(unittest.TestCase):
    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(list(argv), out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def test_graph_exit_code_and_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.html")
            code, out, _ = self.run_cli("graph", "--from-dir", FIXTURES, "-A", "--html", path)
            self.assertEqual(code, cli.EXIT_PROBLEMS)
            self.assertNotIn("\x1b[", out)  # StringIO — не терминал
            self.assertTrue(os.path.getsize(path) > 1000)

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

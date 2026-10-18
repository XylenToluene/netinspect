import os
import re
import unittest

from netinspect.graph.render_web import STATIC_DIR
from netinspect.ui import theme

HEX = re.compile(r"^#[0-9A-Fa-f]{6}$")


class ThemeTest(unittest.TestCase):
    def test_same_tokens_in_both_themes(self) -> None:
        self.assertEqual(set(theme.LIGHT), set(theme.DARK))

    def test_text_contrast_wcag_aa(self) -> None:
        for name, palette in (("light", theme.LIGHT), ("dark", theme.DARK)):
            for fg, bg in theme.TEXT_PAIRS:
                ratio = theme.contrast_ratio(palette[fg], palette[bg])
                self.assertGreaterEqual(ratio, 4.5, f"{name}: {fg} на {bg} = {ratio:.2f}")

    def test_accent_visible_on_surface(self) -> None:
        # акцент как UI-элемент (фокус, выделение узла) — не менее 3:1 по WCAG 1.4.11
        for palette in (theme.LIGHT, theme.DARK):
            self.assertGreaterEqual(theme.contrast_ratio(palette["accent"], palette["surface"]), 3)
            self.assertGreaterEqual(theme.contrast_ratio(palette["danger"], palette["surface"]), 3)

    def test_colors_are_hex(self) -> None:
        for palette in (theme.LIGHT, theme.DARK):
            for name, value in palette.items():
                if not name.startswith(("shadow", "focus")):
                    self.assertRegex(value, HEX, name)

    def test_node_styles_use_existing_tokens(self) -> None:
        for kind, st in theme.NODE_STYLES.items():
            self.assertIn(st["color"], theme.LIGHT, kind)
            self.assertIn(st["soft"], theme.LIGHT, kind)
            self.assertTrue(st["abbr"])

    def test_css_variables(self) -> None:
        css = theme.css_variables()
        self.assertIn("@media (prefers-color-scheme: dark)", css)
        self.assertIn(':root[data-theme="dark"]', css)
        self.assertIn(':root:not([data-theme="light"])', css)
        self.assertIn("--font-sans: \"Inter Variable\"", css)
        self.assertIn("--font-mono: \"JetBrains Mono Variable\"", css)
        for name, value in theme.DARK.items():
            self.assertIn(f"--{name}: {value};", css)

    def test_font_files_present(self) -> None:
        with open(os.path.join(STATIC_DIR, "style.css"), encoding="utf-8") as fh:
            css = fh.read()
        refs = re.findall(r"url\((fonts/[^)]+)\)", css)
        self.assertEqual(len(refs), 4)
        for ref in refs:
            self.assertTrue(os.path.isfile(os.path.join(STATIC_DIR, ref)), ref)
        for lic in ("LICENSE-Inter.txt", "LICENSE-JetBrainsMono.txt"):
            with open(os.path.join(STATIC_DIR, "fonts", lic), encoding="utf-8") as fh:
                self.assertIn("SIL Open Font License", fh.read())

    def test_css_uses_only_known_tokens(self) -> None:
        with open(os.path.join(STATIC_DIR, "style.css"), encoding="utf-8") as fh:
            css = fh.read()
        known = set(theme.LIGHT) | {"font-sans", "font-mono"}
        used = set(re.findall(r"var\(--([a-z0-9-]+)\)", css))
        self.assertLessEqual(used, known, f"неизвестные токены: {used - known}")
        for name in ("app.js", "connect.js"):
            with open(os.path.join(STATIC_DIR, name), encoding="utf-8") as fh:
                js_used = set(re.findall(r"var\(--([a-z0-9-]+)\)", fh.read()))
            js_used = {u for u in js_used if not u.endswith("-")}
            self.assertLessEqual(js_used, known, f"{name}: {js_used - known}")


if __name__ == "__main__":
    unittest.main()

import os
import sys
import unittest


ROOT_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from scripts.html_security import (
    TrustedHtml,
    escape_attr,
    escape_text,
    sanitize_html_fragment,
    sanitize_url,
    trust_html,
)


class TestHtmlSecurity(unittest.TestCase):
    def test_escape_text_escapes_html_special_chars(self):
        value = '<b>"A&B"</b>'
        self.assertEqual(escape_text(value), "&lt;b&gt;&quot;A&amp;B&quot;&lt;/b&gt;")

    def test_escape_attr_escapes_attribute_breakouts(self):
        value = '" onmouseover="alert(1)'
        escaped = escape_attr(value)
        self.assertIn("&quot;", escaped)
        self.assertNotIn('"', escaped)

    def test_sanitize_url_blocks_javascript(self):
        self.assertEqual(sanitize_url("javascript:alert(1)"), "#")

    def test_sanitize_url_blocks_data_by_default(self):
        self.assertEqual(sanitize_url("data:image/png;base64,abcd"), "#")

    def test_sanitize_url_allows_data_media_when_opted_in(self):
        cleaned = sanitize_url("data:image/png;base64,abcd", allow_data_media=True)
        self.assertEqual(cleaned, "data:image/png;base64,abcd")

    def test_sanitize_url_blocks_file_and_ftp_by_default(self):
        self.assertEqual(sanitize_url("file:///tmp/evidence.jpg"), "#")
        self.assertEqual(sanitize_url("ftp://example.org/evidence.jpg"), "#")

    def test_sanitize_url_allows_local_paths_when_opted_in(self):
        win_path = r"C:\\cases\\artifact.jpg"
        self.assertEqual(sanitize_url(win_path, allow_file=True), win_path)

    def test_sanitize_html_fragment_strips_unsafe_tags_attrs_and_urls(self):
        dirty = (
            '<p onclick="x()">ok<script>alert(1)</script>'
            '<a href="javascript:alert(1)" onmouseover="x">x</a>'
            '<img src="data:text/html;base64,abcd" onerror="x" />'
            "<iframe src='https://example.com'></iframe></p>"
        )
        cleaned = sanitize_html_fragment(dirty)
        self.assertNotIn("<script", cleaned.lower())
        self.assertNotIn("<iframe", cleaned.lower())
        self.assertNotIn("onmouseover", cleaned.lower())
        self.assertNotIn("onerror", cleaned.lower())
        self.assertNotIn("onclick", cleaned.lower())
        self.assertNotIn("javascript:", cleaned.lower())
        self.assertNotIn("data:text/html", cleaned.lower())

    def test_trusted_html_wrapper(self):
        trusted = trust_html("<b>safe</b>")
        self.assertIsInstance(trusted, TrustedHtml)
        self.assertEqual(str(trusted), "<b>safe</b>")


if __name__ == "__main__":
    unittest.main()

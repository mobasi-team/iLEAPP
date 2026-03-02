import os
import sys
import unittest


ROOT_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from admin.test.scripts import audit_xss_sinks


class TestAuditXssSinks(unittest.TestCase):
    def test_detects_forbidden_dom_html_sink(self):
        issues = audit_xss_sinks.find_forbidden_patterns(
            "tmp.js",
            '$("#chat-history").html(html);',
        )
        self.assertGreater(len(issues), 0)

    def test_repository_audit_passes(self):
        issues = audit_xss_sinks.run_audit(ROOT_DIR)
        self.assertEqual(issues, [])


if __name__ == "__main__":
    unittest.main()

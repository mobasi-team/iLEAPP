import os
import re
import sys
from pathlib import Path


FORBIDDEN_PATTERNS = [
    (re.compile(r"\.html\s*\("), "jQuery .html() sink is forbidden"),
    (re.compile(r"html_escape\s*=\s*False"), "Global html_escape=False is forbidden; use html_no_escape"),
    (re.compile(r"on(click|change)\s*="), "Inline event handler attributes are forbidden"),
]

REQUIRED_PATTERNS = [
    ("scripts/artifact_report.py", re.compile(r"sanitize_html_fragment"), "artifact table sanitization missing"),
    ("scripts/artifact_report.py", re.compile(r"isinstance\(code,\s*TrustedHtml\)"), "TrustedHtml enforcement missing"),
    ("scripts/report.py", re.compile(r"get_sanitized_file_content"), "index tab log sanitization missing"),
    ("scripts/ilapfuncs.py", re.compile(r"safe_message\s*=\s*escape_text\(message\)"), "logfunc escaping missing"),
    ("scripts/ilapfuncs.py", re.compile(r"def logdevinfo\(message=\"\"\):[\s\S]*escape_text\(message\)"), "logdevinfo escaping missing"),
    ("scripts/chat_rendering.py", re.compile(r"function sanitizeFragment"), "chat DOM sanitizer missing"),
    ("scripts/artifacts/notificationsXI.py", re.compile(r"def _safe_text"), "notifications helper _safe_text missing"),
    ("scripts/artifacts/notificationsXI.py", re.compile(r"def _td"), "notifications helper _td missing"),
]


def _read_file(path):
    with open(path, "r", encoding="utf8") as fh:
        return fh.read()


def find_forbidden_patterns(file_path, text):
    issues = []
    for regex, description in FORBIDDEN_PATTERNS:
        for match in regex.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            issues.append(f"{file_path}:{line}: {description}")
    return issues


def find_untrusted_write_raw_html(file_path, text):
    issues = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if "def write_raw_html(" in line:
            continue
        if "write_raw_html(" not in line:
            continue
        if "trust_html(" in line or "TrustedHtml(" in line:
            continue
        issues.append(f"{file_path}:{line_no}: write_raw_html must receive TrustedHtml")
    return issues


def run_audit(root_dir):
    root = Path(root_dir)
    issues = []

    for rel_path, regex, description in REQUIRED_PATTERNS:
        file_path = root / rel_path
        if not file_path.is_file():
            issues.append(f"{rel_path}: required file is missing")
            continue
        data = _read_file(file_path)
        if not regex.search(data):
            issues.append(f"{rel_path}: {description}")

    py_files = list((root / "scripts").rglob("*.py"))
    for path in py_files:
        rel_path = os.path.relpath(path, root)
        data = _read_file(path)
        issues.extend(find_forbidden_patterns(rel_path, data))
        issues.extend(find_untrusted_write_raw_html(rel_path, data))

    return issues


def main():
    root_dir = Path(__file__).resolve().parents[3]
    issues = run_audit(root_dir)
    if issues:
        print("XSS sink audit failed:")
        for issue in issues:
            print(f"- {issue}")
        return 1
    print("XSS sink audit passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

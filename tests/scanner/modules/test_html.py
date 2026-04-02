from unittest.mock import MagicMock
from scanner.modules.html_check import HTMLScanner
from scanner.modules.tech import TechLeakageScanner
from scanner.modules.base import Severity


def make_response(html: str, headers: dict = None):
    resp = MagicMock()
    resp.text = html
    resp.headers = headers or {}
    return resp


def test_blank_target_without_noopener():
    html = '<a href="https://evil.com" target="_blank">link</a>'
    scanner = HTMLScanner()
    findings = scanner.run("https://example.com", make_response(html))
    ids = [f.id for f in findings]
    assert "missing-noopener" in ids


def test_blank_target_with_noopener_is_ok():
    html = '<a href="https://evil.com" target="_blank" rel="noopener noreferrer">link</a>'
    scanner = HTMLScanner()
    findings = scanner.run("https://example.com", make_response(html))
    ids = [f.id for f in findings if f.id == "missing-noopener"]
    assert len(ids) == 0


def test_todo_comment_flagged():
    html = "<!-- TODO: remove debug key sk-abc123 -->"
    scanner = HTMLScanner()
    findings = scanner.run("https://example.com", make_response(html))
    ids = [f.id for f in findings]
    assert "html-comments" in ids


def test_tech_leakage_powered_by():
    resp = make_response("", {"x-powered-by": "PHP/8.1.0"})
    scanner = TechLeakageScanner()
    findings = scanner.run("https://example.com", resp)
    ids = [f.id for f in findings]
    assert "x-powered-by-leakage" in ids
    f = next(x for x in findings if x.id == "x-powered-by-leakage")
    assert f.severity == Severity.WARNING

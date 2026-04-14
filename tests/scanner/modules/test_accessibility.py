from unittest.mock import MagicMock
from scanner.modules.accessibility import AccessibilityScanner
from scanner.modules.base import Severity


def make_response(html: str):
    resp = MagicMock()
    resp.text = html
    resp.headers = {}
    return resp


class TestAccessibilityScanner:
    def setup_method(self):
        self.scanner = AccessibilityScanner()

    def test_none_response_returns_empty(self):
        findings = self.scanner.run("https://example.com", None)
        assert findings == []

    def test_skip_link_with_sr_only_class(self):
        html = '<body><a href="#main" class="sr-only">Přeskočit na obsah</a><nav>menu</nav><main id="main">content</main></body>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "skip-link-ok" in ids
        assert "missing-skip-link" not in ids

    def test_skip_link_with_skip_nav_class(self):
        html = '<body><a href="#content" class="skip-nav">Skip</a><main id="content">content</main></body>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "skip-link-ok" in ids

    def test_skip_link_with_visually_hidden_class(self):
        html = '<body><a href="#main" class="visually-hidden">Skip to content</a></body>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "skip-link-ok" in ids

    def test_skip_link_detected_by_href_main(self):
        html = '<body><div><a href="#main">skip</a></div><main id="main">content</main></body>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "skip-link-ok" in ids

    def test_skip_link_detected_by_href_content(self):
        html = '<body><a href="#content">skip</a></body>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "skip-link-ok" in ids

    def test_skip_link_detected_by_href_main_content(self):
        html = '<body><a href="#main-content">skip</a></body>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "skip-link-ok" in ids

    def test_skip_link_detected_by_czech_text(self):
        html = '<body><a href="#obsah">Přeskočit na obsah</a></body>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "skip-link-ok" in ids

    def test_skip_link_detected_by_english_text(self):
        html = '<body><a href="#main">Skip to main content</a></body>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "skip-link-ok" in ids

    def test_skip_link_detected_by_german_text(self):
        html = '<body><a href="#inhalt">Zum Inhalt springen</a></body>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "skip-link-ok" in ids

    def test_missing_skip_link(self):
        html = '<body><nav><a href="/about">About</a></nav><main>content</main></body>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "missing-skip-link" in ids
        assert "skip-link-ok" not in ids
        f = next(x for x in findings if x.id == "missing-skip-link")
        assert f.severity == Severity.INFO

    def test_regular_anchor_link_not_detected_as_skip(self):
        html = '<body><nav><a href="#section2">Go to section 2</a></nav><main>content</main></body>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "missing-skip-link" in ids

    def test_empty_html(self):
        findings = self.scanner.run("https://example.com", make_response(""))
        ids = [f.id for f in findings]
        assert "missing-skip-link" in ids

    def test_module_metadata(self):
        assert self.scanner.name == "accessibility"
        assert self.scanner.step_label == "Přístupnost"

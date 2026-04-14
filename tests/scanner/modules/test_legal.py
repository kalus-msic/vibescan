from unittest.mock import MagicMock
from scanner.modules.legal import LegalScanner
from scanner.modules.base import Severity


def make_response(html: str):
    resp = MagicMock()
    resp.text = html
    resp.headers = {}
    return resp


class TestLegalScannerCookieConsent:
    def setup_method(self):
        self.scanner = LegalScanner()

    def test_none_response_returns_empty(self):
        findings = self.scanner.run("https://example.com", None)
        assert findings == []

    def test_detects_cookieconsent_script(self):
        html = '<html><head><script src="https://cdn.jsdelivr.net/npm/cookieconsent@3/build/cookieconsent.min.js"></script></head><body></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "cookie-consent-ok" in ids
        assert "missing-cookie-consent" not in ids

    def test_detects_cookiebot_script(self):
        html = '<html><head><script src="https://consent.cookiebot.com/uc.js"></script></head><body></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "cookie-consent-ok" in ids

    def test_detects_onetrust_element(self):
        html = '<html><body><div id="onetrust-consent-sdk">consent</div></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "cookie-consent-ok" in ids

    def test_detects_cookie_banner_id(self):
        html = '<html><body><div id="cookie-banner">cookies</div></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "cookie-consent-ok" in ids

    def test_detects_cookie_consent_class(self):
        html = '<html><body><div class="cc-window">cookies</div></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "cookie-consent-ok" in ids

    def test_missing_cookie_consent(self):
        html = '<html><body><p>Hello world</p></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "missing-cookie-consent" in ids
        f = next(x for x in findings if x.id == "missing-cookie-consent")
        assert f.severity == Severity.INFO


class TestLegalScannerPrivacyLink:
    def setup_method(self):
        self.scanner = LegalScanner()

    def test_detects_privacy_href(self):
        html = '<html><body><a href="/privacy-policy">Privacy</a></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "privacy-link-ok" in ids
        assert "missing-privacy-link" not in ids

    def test_detects_gdpr_href(self):
        html = '<html><body><a href="/gdpr">GDPR</a></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "privacy-link-ok" in ids

    def test_detects_czech_privacy_href(self):
        html = '<html><body><a href="/ochrana-osobnich-udaju">Ochrana</a></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "privacy-link-ok" in ids

    def test_detects_privacy_by_link_text(self):
        html = '<html><body><a href="/legal/info">Ochrana osobních údajů</a></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "privacy-link-ok" in ids

    def test_detects_gdpr_by_link_text(self):
        html = '<html><body><a href="/info">Zásady ochrany soukromí</a></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "privacy-link-ok" in ids

    def test_detects_datenschutz_href(self):
        html = '<html><body><a href="/datenschutz">Datenschutz</a></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "privacy-link-ok" in ids

    def test_missing_privacy_link(self):
        html = '<html><body><a href="/about">About us</a></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "missing-privacy-link" in ids
        f = next(x for x in findings if x.id == "missing-privacy-link")
        assert f.severity == Severity.INFO


class TestLegalScannerCopyright:
    def setup_method(self):
        self.scanner = LegalScanner()

    def test_detects_copyright_symbol_in_footer(self):
        html = '<html><body><footer>© 2026 Firma s.r.o.</footer></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "copyright-ok" in ids
        assert "missing-copyright" not in ids

    def test_detects_copyright_text_in_footer(self):
        html = '<html><body><footer>Copyright 2026 Firma</footer></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "copyright-ok" in ids

    def test_detects_copyright_in_body_without_footer(self):
        html = '<html><body><div>© 2026 Firma s.r.o.</div></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "copyright-ok" in ids

    def test_missing_copyright(self):
        html = '<html><body><footer>Made with love</footer></body></html>'
        findings = self.scanner.run("https://example.com", make_response(html))
        ids = [f.id for f in findings]
        assert "missing-copyright" in ids
        f = next(x for x in findings if x.id == "missing-copyright")
        assert f.severity == Severity.INFO

    def test_empty_html(self):
        findings = self.scanner.run("https://example.com", make_response(""))
        ids = [f.id for f in findings]
        assert "missing-cookie-consent" in ids
        assert "missing-privacy-link" in ids
        assert "missing-copyright" in ids

    def test_module_metadata(self):
        scanner = LegalScanner()
        assert scanner.name == "legal"
        assert scanner.step_label == "Právní náležitosti"

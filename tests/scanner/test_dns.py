import pytest
from unittest.mock import patch, MagicMock
import dns.resolver
from scanner.modules.dns_check import DNSScanner
from scanner.modules.base import Severity


class TestCAACheck:
    def setup_method(self):
        self.scanner = DNSScanner()

    @patch("scanner.modules.dns_check.dns.resolver.resolve")
    def test_caa_found(self, mock_resolve):
        rdata = MagicMock()
        rdata.flags = 0
        rdata.tag = b"issue"
        rdata.value = "letsencrypt.org"
        mock_resolve.return_value = [rdata]

        finding = self.scanner._check_caa("example.com")
        assert finding is not None
        assert finding.severity == Severity.OK
        assert "CAA" in finding.title

    @patch("scanner.modules.dns_check.dns.resolver.resolve")
    def test_caa_missing(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NoAnswer()

        finding = self.scanner._check_caa("example.com")
        assert finding is not None
        assert finding.severity == Severity.INFO
        assert "CAA" in finding.title

    @patch("scanner.modules.dns_check.dns.resolver.resolve")
    def test_caa_nxdomain(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        finding = self.scanner._check_caa("example.com")
        assert finding is not None
        assert finding.severity == Severity.INFO

    @patch("scanner.modules.dns_check.dns.resolver.resolve")
    def test_caa_dns_error_returns_none(self, mock_resolve):
        mock_resolve.side_effect = Exception("DNS timeout")

        finding = self.scanner._check_caa("example.com")
        assert finding is None


class TestDNSSECCheck:
    def setup_method(self):
        self.scanner = DNSScanner()

    @patch("scanner.modules.dns_check.dns.resolver.resolve")
    def test_dnssec_active(self, mock_resolve):
        rdata = MagicMock()
        mock_resolve.return_value = [rdata]

        finding = self.scanner._check_dnssec("example.com")
        assert finding is not None
        assert finding.severity == Severity.OK
        assert "DNSSEC" in finding.title

    @patch("scanner.modules.dns_check.dns.resolver.resolve")
    def test_dnssec_inactive(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NoAnswer()

        finding = self.scanner._check_dnssec("example.com")
        assert finding is not None
        assert finding.severity == Severity.INFO
        assert "DNSSEC" in finding.title

    @patch("scanner.modules.dns_check.dns.resolver.resolve")
    def test_dnssec_nxdomain(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        finding = self.scanner._check_dnssec("example.com")
        assert finding is not None
        assert finding.severity == Severity.INFO

    @patch("scanner.modules.dns_check.dns.resolver.resolve")
    def test_dnssec_error_returns_none(self, mock_resolve):
        mock_resolve.side_effect = Exception("DNS timeout")

        finding = self.scanner._check_dnssec("example.com")
        assert finding is None


class TestRobotsTxtCheck:
    def setup_method(self):
        self.scanner = DNSScanner()

    @patch("scanner.modules.dns_check.httpx.get")
    def test_robots_with_sensitive_paths(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /.env\n"
        mock_get.return_value = resp

        finding = self.scanner._check_robots_txt("https://example.com")
        assert finding is not None
        assert finding.severity == Severity.WARNING
        assert "/admin" in finding.detail
        assert "/backup" in finding.detail

    @patch("scanner.modules.dns_check.httpx.get")
    def test_robots_clean(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "User-agent: *\nDisallow: /search\nDisallow: /cart\n"
        mock_get.return_value = resp

        finding = self.scanner._check_robots_txt("https://example.com")
        assert finding is None

    @patch("scanner.modules.dns_check.httpx.get")
    def test_robots_not_found(self, mock_get):
        resp = MagicMock()
        resp.status_code = 404
        resp.text = ""
        mock_get.return_value = resp

        finding = self.scanner._check_robots_txt("https://example.com")
        assert finding is None

    @patch("scanner.modules.dns_check.httpx.get")
    def test_robots_http_error(self, mock_get):
        mock_get.side_effect = Exception("Connection refused")

        finding = self.scanner._check_robots_txt("https://example.com")
        assert finding is None

    @patch("scanner.modules.dns_check.httpx.get")
    def test_robots_case_insensitive_path(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "User-agent: *\nDisallow: /Admin/panel\n"
        mock_get.return_value = resp

        finding = self.scanner._check_robots_txt("https://example.com")
        assert finding is not None
        assert finding.severity == Severity.WARNING

    @patch("scanner.modules.dns_check.httpx.get")
    def test_robots_max_five_paths_in_detail(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = (
            "User-agent: *\n"
            "Disallow: /admin\n"
            "Disallow: /backup\n"
            "Disallow: /.env\n"
            "Disallow: /.git\n"
            "Disallow: /debug\n"
            "Disallow: /secret\n"
            "Disallow: /private\n"
        )
        mock_get.return_value = resp

        finding = self.scanner._check_robots_txt("https://example.com")
        assert finding is not None
        assert "dalších" in finding.detail or "..." in finding.detail

    @patch("scanner.modules.dns_check.httpx.get")
    def test_robots_empty_body(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = ""
        mock_get.return_value = resp

        finding = self.scanner._check_robots_txt("https://example.com")
        assert finding is None

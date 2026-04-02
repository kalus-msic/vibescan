from unittest.mock import patch, MagicMock
from scanner.modules.dns_check import DNSScanner
from scanner.modules.base import Severity
import dns.resolver


def test_missing_spf_is_warning():
    with patch("scanner.modules.dns_check.dns.resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NoAnswer
        scanner = DNSScanner()
        findings = scanner.run("https://example.com", MagicMock())
        ids = [f.id for f in findings]
        assert "missing-spf" in ids


def test_security_txt_missing_is_info():
    with patch("scanner.modules.dns_check.httpx.get") as mock_get:
        mock_get.return_value.status_code = 404
        scanner = DNSScanner()
        findings = scanner.run("https://example.com", MagicMock())
        ids = [f.id for f in findings]
        assert "missing-security-txt" in ids
        f = next(x for x in findings if x.id == "missing-security-txt")
        assert f.severity == Severity.WARNING

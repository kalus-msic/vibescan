from unittest.mock import patch, MagicMock
from scanner.modules.dns_check import DNSScanner
from scanner.modules.base import Severity
import dns.resolver


def _mock_resolve_no_answer(*args, **kwargs):
    raise dns.resolver.NoAnswer


def test_missing_spf_is_warning():
    with patch("scanner.modules.dns_check.dns.resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NoAnswer
        scanner = DNSScanner()
        findings = scanner.run("https://example.com", MagicMock())
        ids = [f.id for f in findings]
        assert "missing-spf" in ids


def test_dmarc_policy_none_is_warning():
    """DMARC with p=none is weak — should be WARNING."""
    rdata = MagicMock()
    rdata.strings = [b"v=dmarc1; p=none"]

    def mock_resolve(qname, rdtype):
        if "_dmarc" in qname:
            return [rdata]
        raise dns.resolver.NoAnswer

    with patch("scanner.modules.dns_check.dns.resolver.resolve", side_effect=mock_resolve):
        with patch("scanner.modules.dns_check.httpx.get") as mock_get:
            mock_get.return_value.status_code = 404
            scanner = DNSScanner()
            findings = scanner.run("https://example.com", MagicMock())
            f = next(x for x in findings if x.id == "dmarc-weak")
            assert f.severity == Severity.WARNING


def test_dmarc_policy_reject_is_ok():
    """DMARC with p=reject is strong — should be OK."""
    rdata = MagicMock()
    rdata.strings = [b"v=DMARC1; p=reject"]

    def mock_resolve(qname, rdtype):
        if "_dmarc" in qname:
            return [rdata]
        raise dns.resolver.NoAnswer

    with patch("scanner.modules.dns_check.dns.resolver.resolve", side_effect=mock_resolve):
        with patch("scanner.modules.dns_check.httpx.get") as mock_get:
            mock_get.return_value.status_code = 404
            scanner = DNSScanner()
            findings = scanner.run("https://example.com", MagicMock())
            f = next(x for x in findings if x.id == "dmarc-ok")
            assert f.severity == Severity.OK


def test_dkim_found_via_txt():
    """DKIM found when TXT record exists for a common selector."""
    rdata = MagicMock()
    rdata.strings = [b"v=DKIM1; k=rsa; p=MIGf..."]

    def mock_resolve(qname, rdtype):
        if "selector1._domainkey" in qname and rdtype == "TXT":
            return [rdata]
        raise dns.resolver.NXDOMAIN

    with patch("scanner.modules.dns_check.dns.resolver.resolve", side_effect=mock_resolve):
        with patch("scanner.modules.dns_check.httpx.get") as mock_get:
            mock_get.return_value.status_code = 404
            scanner = DNSScanner()
            findings = scanner.run("https://example.com", MagicMock())
            f = next(x for x in findings if x.id == "dkim-ok")
            assert f.severity == Severity.OK
            assert "selector1" in f.detail


def test_dkim_found_via_cname():
    """DKIM found when CNAME record exists (e.g. Microsoft 365)."""
    def mock_resolve(qname, rdtype):
        if "selector1._domainkey" in qname and rdtype == "CNAME":
            return [MagicMock()]
        raise dns.resolver.NXDOMAIN

    with patch("scanner.modules.dns_check.dns.resolver.resolve", side_effect=mock_resolve):
        with patch("scanner.modules.dns_check.httpx.get") as mock_get:
            mock_get.return_value.status_code = 404
            scanner = DNSScanner()
            findings = scanner.run("https://example.com", MagicMock())
            f = next(x for x in findings if x.id == "dkim-ok")
            assert f.severity == Severity.OK


def test_dkim_not_found_is_info():
    """DKIM not found with common selectors — INFO severity, not WARNING."""
    with patch("scanner.modules.dns_check.dns.resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        with patch("scanner.modules.dns_check.httpx.get") as mock_get:
            mock_get.return_value.status_code = 404
            scanner = DNSScanner()
            findings = scanner.run("https://example.com", MagicMock())
            f = next(x for x in findings if x.id == "dkim-not-found")
            assert f.severity == Severity.INFO


def test_subdomain_missing_dmarc_is_info():
    """Missing DMARC on a subdomain should be INFO, not WARNING."""
    with patch("scanner.modules.dns_check.dns.resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NoAnswer
        with patch("scanner.modules.dns_check.httpx.get") as mock_get:
            mock_get.return_value.status_code = 404
            scanner = DNSScanner()
            findings = scanner.run("https://app.example.com", MagicMock())
            f = next(x for x in findings if x.id == "missing-dmarc")
            assert f.severity == Severity.INFO
            assert "root" in f.description.lower()


def test_subdomain_missing_spf_is_info():
    """Missing SPF on a subdomain should be INFO, not WARNING."""
    with patch("scanner.modules.dns_check.dns.resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NoAnswer
        with patch("scanner.modules.dns_check.httpx.get") as mock_get:
            mock_get.return_value.status_code = 404
            scanner = DNSScanner()
            findings = scanner.run("https://app.example.com", MagicMock())
            f = next(x for x in findings if x.id == "missing-spf")
            assert f.severity == Severity.INFO


def test_root_domain_missing_dmarc_is_warning():
    """Missing DMARC on root domain should remain WARNING."""
    with patch("scanner.modules.dns_check.dns.resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NoAnswer
        with patch("scanner.modules.dns_check.httpx.get") as mock_get:
            mock_get.return_value.status_code = 404
            scanner = DNSScanner()
            findings = scanner.run("https://example.com", MagicMock())
            f = next(x for x in findings if x.id == "missing-dmarc")
            assert f.severity == Severity.WARNING


def test_security_txt_missing_is_warning():
    with patch("scanner.modules.dns_check.dns.resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NoAnswer
        with patch("scanner.modules.dns_check.httpx.get") as mock_get:
            mock_get.return_value.status_code = 404
            scanner = DNSScanner()
            findings = scanner.run("https://example.com", MagicMock())
            f = next(x for x in findings if x.id == "missing-security-txt")
            assert f.severity == Severity.WARNING

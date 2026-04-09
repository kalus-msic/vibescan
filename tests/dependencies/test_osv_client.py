import pytest
from unittest.mock import patch, MagicMock
from dependencies.parsers import Dependency
from dependencies.osv_client import check_vulnerabilities, Vulnerability, OsvError, CheckResult


class TestOsvClient:
    def _mock_batch_response(self, results):
        """Helper: mock querybatch response."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"results": results}
        resp.raise_for_status = MagicMock()
        return resp

    def _mock_vuln_response(self, vuln_id, summary, severity_score=None, fixed_version=None, ecosystem="PyPI", package_name="django"):
        """Helper: mock single vuln detail response."""
        resp = MagicMock()
        vuln_data = {
            "id": vuln_id,
            "summary": summary,
            "affected": [{
                "package": {"name": package_name, "ecosystem": ecosystem},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}] + ([{"fixed": fixed_version}] if fixed_version else []),
                }],
            }],
        }
        if severity_score is not None:
            vuln_data["severity"] = [{"type": "CVSS_V3", "score": str(severity_score)}]
        resp.status_code = 200
        resp.json.return_value = vuln_data
        resp.raise_for_status = MagicMock()
        return resp

    @patch("dependencies.osv_client.httpx")
    def test_no_vulnerabilities(self, mock_httpx):
        mock_httpx.post.return_value = self._mock_batch_response([{"vulns": []}, {"vulns": []}])

        deps = [
            Dependency(name="django", version="4.2.0", ecosystem="PyPI"),
            Dependency(name="requests", version="2.31.0", ecosystem="PyPI"),
        ]
        result = check_vulnerabilities(deps)
        assert result.vulnerabilities == []
        assert result.last_modified is None

    @patch("dependencies.osv_client.httpx")
    def test_with_vulnerabilities(self, mock_httpx):
        batch_resp = self._mock_batch_response([
            {"vulns": [{"id": "GHSA-1234", "modified": "2024-01-01T00:00:00Z"}]},
            {"vulns": []},
        ])
        vuln_resp = self._mock_vuln_response(
            "GHSA-1234", "SQL injection in Django", severity_score=9.8, fixed_version="4.2.1"
        )
        mock_httpx.post.return_value = batch_resp
        mock_httpx.get.return_value = vuln_resp

        deps = [
            Dependency(name="django", version="4.2.0", ecosystem="PyPI"),
            Dependency(name="requests", version="2.31.0", ecosystem="PyPI"),
        ]
        result = check_vulnerabilities(deps)
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].id == "GHSA-1234"
        assert result.vulnerabilities[0].summary == "SQL injection in Django"
        assert result.vulnerabilities[0].package_name == "django"
        assert result.last_modified == "2024-01-01"

    @patch("dependencies.osv_client.httpx")
    def test_empty_deps_list(self, mock_httpx):
        result = check_vulnerabilities([])
        assert result.vulnerabilities == []
        assert result.last_modified is None
        mock_httpx.post.assert_not_called()

    @patch("dependencies.osv_client.httpx")
    def test_api_timeout(self, mock_httpx):
        import httpx as real_httpx
        mock_httpx.post.side_effect = real_httpx.TimeoutException("timeout")
        mock_httpx.TimeoutException = real_httpx.TimeoutException

        deps = [Dependency(name="django", version="4.2.0", ecosystem="PyPI")]
        with pytest.raises(OsvError, match="neodpovídá"):
            check_vulnerabilities(deps)

    @patch("dependencies.osv_client.httpx")
    def test_api_error_status(self, mock_httpx):
        import httpx as real_httpx
        resp = MagicMock()
        resp.raise_for_status.side_effect = real_httpx.HTTPStatusError(
            "500", request=MagicMock(), response=MagicMock()
        )
        mock_httpx.post.return_value = resp
        mock_httpx.HTTPStatusError = real_httpx.HTTPStatusError

        deps = [Dependency(name="django", version="4.2.0", ecosystem="PyPI")]
        with pytest.raises(OsvError):
            check_vulnerabilities(deps)

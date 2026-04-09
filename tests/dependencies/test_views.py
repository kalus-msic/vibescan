import pytest
from unittest.mock import patch, MagicMock
from django.test import RequestFactory, Client
from dependencies.views import check_dependencies
from dependencies.osv_client import Vulnerability, CheckResult


@pytest.fixture
def rf():
    return RequestFactory()


def _make_session():
    session = MagicMock()
    session.session_key = "test-session-key"
    return session


class TestCheckDependenciesView:
    def test_empty_content_returns_error(self, rf):
        request = rf.post("/dependencies/check/", {"content": ""})
        request.session = _make_session()
        response = check_dependencies(request)
        assert response.status_code == 200
        content = response.content.decode()
        assert "prázdný" in content or "required" in content.lower() or "error" in content.lower()

    @patch("dependencies.views.check_vulnerabilities")
    @patch("dependencies.views.parse_dependencies")
    def test_valid_input_no_vulns(self, mock_parse, mock_check, rf):
        from dependencies.parsers import Dependency
        mock_parse.return_value = [Dependency("django", "4.2.0", "PyPI")]
        mock_check.return_value = CheckResult(vulnerabilities=[], last_modified=None)

        request = rf.post("/dependencies/check/", {"content": "django==4.2.0"})
        request.session = _make_session()
        response = check_dependencies(request)
        assert response.status_code == 200
        content = response.content.decode()
        assert "zranitelnost" in content.lower() or "pořádku" in content.lower()

    @patch("dependencies.views.check_vulnerabilities")
    @patch("dependencies.views.parse_dependencies")
    def test_valid_input_with_vulns(self, mock_parse, mock_check, rf):
        from dependencies.parsers import Dependency
        mock_parse.return_value = [Dependency("django", "4.2.0", "PyPI")]
        mock_check.return_value = CheckResult(vulnerabilities=[
            Vulnerability(
                id="GHSA-1234",
                summary="SQL injection",
                package_name="django",
                package_version="4.2.0",
                severity_score=9.8,
                severity_label="Critical",
                fixed_version="4.2.1",
                osv_url="https://osv.dev/vulnerability/GHSA-1234",
            )
        ], last_modified="2024-01-01")

        request = rf.post("/dependencies/check/", {"content": "django==4.2.0"})
        request.session = _make_session()
        response = check_dependencies(request)
        assert response.status_code == 200
        content = response.content.decode()
        assert "GHSA-1234" in content
        assert "django" in content

    @patch("dependencies.views.parse_dependencies")
    def test_unknown_format(self, mock_parse, rf):
        from dependencies.parsers import UnknownFormatError
        mock_parse.side_effect = UnknownFormatError()

        request = rf.post("/dependencies/check/", {"content": "garbage input"})
        request.session = _make_session()
        response = check_dependencies(request)
        assert response.status_code == 200
        content = response.content.decode()
        assert "rozpoznat" in content.lower() or "formát" in content.lower()

    @patch("dependencies.views.parse_dependencies")
    def test_osv_error(self, mock_parse, rf):
        from dependencies.parsers import Dependency
        from dependencies.osv_client import OsvError
        mock_parse.return_value = [Dependency("django", "4.2.0", "PyPI")]

        with patch("dependencies.views.check_vulnerabilities", side_effect=OsvError("timeout")):
            request = rf.post("/dependencies/check/", {"content": "django==4.2.0"})
            request.session = _make_session()
            response = check_dependencies(request)
            assert response.status_code == 200
            content = response.content.decode()
            assert "chyb" in content.lower() or "timeout" in content.lower()

    def test_get_not_allowed(self):
        from django.test import Client
        client = Client()
        response = client.get("/dependencies/check/")
        assert response.status_code == 405


@pytest.mark.django_db
class TestCheckDependenciesIntegration:
    @patch("dependencies.views.check_vulnerabilities")
    def test_full_flow_requirements_txt(self, mock_check):
        mock_check.return_value = CheckResult(vulnerabilities=[
            Vulnerability(
                id="CVE-2024-1234",
                summary="Remote code execution",
                package_name="django",
                package_version="4.2.0",
                severity_score=9.8,
                severity_label="Critical",
                fixed_version="4.2.1",
                osv_url="https://osv.dev/vulnerability/CVE-2024-1234",
            )
        ], last_modified="2024-06-15")

        client = Client()
        response = client.post("/dependencies/check/", {
            "content": "django==4.2.0\nrequests==2.31.0"
        })
        assert response.status_code == 200
        content = response.content.decode()
        assert "CVE-2024-1234" in content
        assert "django" in content
        assert "Critical" in content
        assert "4.2.1" in content

    @patch("dependencies.views.check_vulnerabilities")
    def test_full_flow_package_json(self, mock_check):
        mock_check.return_value = CheckResult(vulnerabilities=[], last_modified=None)

        client = Client()
        response = client.post("/dependencies/check/", {
            "content": '{"dependencies": {"express": "^4.18.2"}}'
        })
        assert response.status_code == 200
        content = response.content.decode()
        assert "zranitelnost" in content.lower() or "pořádku" in content.lower()

    def test_full_flow_unknown_format(self):
        client = Client()
        response = client.post("/dependencies/check/", {
            "content": "this is garbage input that is not a dep file"
        })
        assert response.status_code == 200
        content = response.content.decode()
        assert "rozpoznat" in content.lower() or "formát" in content.lower()

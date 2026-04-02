from scanner.modules.base import Finding, Severity, BaseScanModule


def test_finding_dataclass():
    f = Finding(
        id="missing-csp",
        title="Chybí Content-Security-Policy",
        description="Bez CSP je web náchylný na XSS.",
        severity=Severity.CRITICAL,
        category="headers",
        fix_url="/guide/#csp",
    )
    assert f.severity == Severity.CRITICAL
    assert f.to_dict()["id"] == "missing-csp"
    assert f.to_dict()["severity"] == "critical"


def test_base_module_is_abstract():
    import pytest
    with pytest.raises(TypeError):
        BaseScanModule()

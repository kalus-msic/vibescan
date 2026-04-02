from scanner.modules.base import Finding, Severity
from scanner.score import calculate_vibe_score, ScoreCategory


def make_finding(severity: Severity) -> Finding:
    return Finding(
        id="test", title="test", description="test",
        severity=severity, category="test"
    )


def test_no_issues_gives_100():
    findings = [make_finding(Severity.OK)] * 5
    assert calculate_vibe_score(findings) == 100


def test_critical_reduces_score():
    findings = [make_finding(Severity.CRITICAL)]
    score = calculate_vibe_score(findings)
    assert score < 100
    assert score >= 0


def test_score_never_below_zero():
    findings = [make_finding(Severity.CRITICAL)] * 20
    assert calculate_vibe_score(findings) == 0


def test_category_excellent():
    assert ScoreCategory.from_score(95) == ScoreCategory.EXCELLENT


def test_category_risky():
    assert ScoreCategory.from_score(30) == ScoreCategory.RISKY


def test_mixed_findings():
    findings = [
        make_finding(Severity.CRITICAL),
        make_finding(Severity.WARNING),
        make_finding(Severity.OK),
        make_finding(Severity.OK),
    ]
    score = calculate_vibe_score(findings)
    assert 50 < score < 90

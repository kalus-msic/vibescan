from scanner.score import recalculate_with_deep_scan


def _finding(fid, severity, category="performance", dismissed=False):
    return {"id": fid, "severity": severity, "category": category, "dismissed": dismissed}


def test_no_deep_findings_equals_base():
    findings = [_finding("a", "warning"), _finding("b", "info")]
    assert recalculate_with_deep_scan(findings, []) == 100 - 8 - 2


def test_deep_findings_add_penalties():
    findings = [_finding("a", "warning")]  # -8
    deep = [_finding("lh-x", "critical", category="performance")]  # -20
    # Different categories, no cap interference
    assert recalculate_with_deep_scan(findings, deep) == 100 - 8 - 20


def test_supersede_removes_original_finding_from_score():
    """If lh-document-title supersedes missing-title, the original is excluded."""
    findings = [
        _finding("missing-title", "warning", category="seo"),     # -8, would be excluded
        _finding("other-finding", "info", category="seo"),        # -2
    ]
    deep = [
        _finding("lh-document-title", "critical", category="seo"),  # -20 (capped)
    ]
    # seo cap = 4 (from MODULE_PENALTY_CAP). Both deep CRITICAL and other-finding
    # are seo. Without dedup: 8 + 2 + 20 → capped at 4 for seo. With dedup:
    # missing-title removed → just other-finding (2) + lh-document-title (20)
    # → seo penalty min(2+20, 4) = 4 → score = 96.
    assert recalculate_with_deep_scan(findings, deep) == 96


def test_dismissed_findings_excluded():
    findings = [_finding("a", "warning", dismissed=True)]
    deep = [_finding("lh-x", "info", category="performance", dismissed=True)]
    assert recalculate_with_deep_scan(findings, deep) == 100


def test_deep_scan_dismissed_excluded():
    findings = [_finding("a", "warning", category="dns")]  # -8
    deep = [_finding("lh-lcp", "critical", category="performance", dismissed=True)]  # excluded
    assert recalculate_with_deep_scan(findings, deep) == 100 - 8

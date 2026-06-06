from scanner.score import recalculate_with_deep_scan


def _finding(fid, severity, category="performance", dismissed=False):
    return {"id": fid, "severity": severity, "category": category, "dismissed": dismissed}


def test_no_deep_findings_equals_base():
    findings = [_finding("a", "warning"), _finding("b", "info")]
    assert recalculate_with_deep_scan(findings, []) == 100 - 8 - 2


def test_deep_findings_add_penalties():
    findings = [_finding("a", "warning", category="cookies")]  # -8 (cookies cap 16, well under)
    deep = [_finding("lh-x", "critical", category="performance")]  # raw -20, capped at 10
    # Different categories, no interference. performance critical capped at 10.
    assert recalculate_with_deep_scan(findings, deep) == 100 - 8 - 10


def test_performance_cap_limits_worst_case():
    """Many critical performance findings should not exceed performance cap (10)."""
    deep = [
        _finding("lh-lcp", "critical", category="performance"),
        _finding("lh-cls", "critical", category="performance"),
        _finding("lh-tbt", "critical", category="performance"),
        _finding("lh-si",  "critical", category="performance"),
    ]
    # Raw: 4 × 20 = 80. After cap: max 10.
    assert recalculate_with_deep_scan([], deep) == 100 - 10


def test_best_practices_cap_limits_worst_case():
    """best-practices cap = 16. Two criticals (40 raw) → capped at 16."""
    deep = [
        _finding("lh-https",            "critical", category="best-practices"),
        _finding("lh-vulnerable-libs",  "critical", category="best-practices"),
    ]
    assert recalculate_with_deep_scan([], deep) == 100 - 16


def test_total_lighthouse_worst_case_is_bounded():
    """Even if all 4 Lighthouse categories are at their cap, total deduction
    from Lighthouse alone is bounded (10 + 16 + 8 + 4 = 38)."""
    deep = [
        _finding("lh-lcp",     "critical", category="performance"),    # capped 10
        _finding("lh-bp",      "critical", category="best-practices"), # capped 16
        _finding("lh-a11y",    "critical", category="accessibility"),  # capped 8
        _finding("lh-seo",     "critical", category="seo"),            # capped 4
    ]
    assert recalculate_with_deep_scan([], deep) == 100 - 10 - 16 - 8 - 4  # = 62


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

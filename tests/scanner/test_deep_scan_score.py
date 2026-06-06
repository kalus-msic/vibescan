from scanner.score import recalculate_with_deep_scan


def _finding(fid, severity, category="performance", dismissed=False):
    return {"id": fid, "severity": severity, "category": category, "dismissed": dismissed}


def test_no_deep_findings_equals_base():
    findings = [_finding("a", "warning"), _finding("b", "info")]
    # performance cap 6: warning(5) + info(1) = 6, pod capem
    assert recalculate_with_deep_scan(findings, []) == 100 - 5 - 1


def test_deep_findings_add_penalties():
    findings = [_finding("a", "warning", category="cookies")]  # -5 (cookies cap 10, well under)
    deep = [_finding("lh-x", "critical", category="performance")]  # raw -12, capped at 6
    # Different categories, no interference.
    assert recalculate_with_deep_scan(findings, deep) == 100 - 5 - 6


def test_performance_cap_limits_worst_case():
    """Many critical performance findings should not exceed performance cap (6)."""
    deep = [
        _finding("lh-lcp", "critical", category="performance"),
        _finding("lh-cls", "critical", category="performance"),
        _finding("lh-tbt", "critical", category="performance"),
        _finding("lh-si",  "critical", category="performance"),
    ]
    # Raw: 4 × 12 = 48. After cap: max 6.
    assert recalculate_with_deep_scan([], deep) == 100 - 6


def test_best_practices_cap_limits_worst_case():
    """best-practices cap = 10. Two criticals (24 raw) → capped at 10."""
    deep = [
        _finding("lh-https",            "critical", category="best-practices"),
        _finding("lh-vulnerable-libs",  "critical", category="best-practices"),
    ]
    assert recalculate_with_deep_scan([], deep) == 100 - 10


def test_total_lighthouse_worst_case_is_bounded():
    """Even if all 4 Lighthouse categories are at their cap, total deduction
    from Lighthouse alone is bounded (6 + 10 + 5 + 3 = 24)."""
    deep = [
        _finding("lh-lcp",     "critical", category="performance"),    # capped 6
        _finding("lh-bp",      "critical", category="best-practices"), # capped 10
        _finding("lh-a11y",    "critical", category="accessibility"),  # capped 5
        _finding("lh-seo",     "critical", category="seo"),            # capped 3
    ]
    assert recalculate_with_deep_scan([], deep) == 100 - 6 - 10 - 5 - 3  # = 76


def test_supersede_removes_original_finding_from_score():
    """If lh-document-title supersedes missing-title, the original is excluded."""
    findings = [
        _finding("missing-title", "warning", category="seo"),     # -5, would be excluded
        _finding("other-finding", "info", category="seo"),        # -1
    ]
    deep = [
        _finding("lh-document-title", "critical", category="seo"),  # -12 (capped to 3)
    ]
    # seo cap = 3. Dedup vyloučí missing-title → seo penalty = min(1+12, 3) = 3 → score = 97.
    assert recalculate_with_deep_scan(findings, deep) == 97


def test_dismissed_findings_excluded():
    findings = [_finding("a", "warning", dismissed=True)]
    deep = [_finding("lh-x", "info", category="performance", dismissed=True)]
    assert recalculate_with_deep_scan(findings, deep) == 100


def test_deep_scan_dismissed_excluded():
    findings = [_finding("a", "warning", category="dns")]  # -5
    deep = [_finding("lh-lcp", "critical", category="performance", dismissed=True)]  # excluded
    assert recalculate_with_deep_scan(findings, deep) == 100 - 5

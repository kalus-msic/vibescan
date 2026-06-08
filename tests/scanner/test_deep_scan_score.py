"""Legacy single-score recalculate_with_deep_scan tests.

Per-category caps byly zrušeny (2026-06-08). Tato API už nepoužívá caps —
sečte všechny aktivní severity penalty (fast + deep) a vrátí max(0, 100-total).

Reálný UX používá tiered API (recalculate_with_deep_scan_tiered), které má
TIER_FLOOR=30 per tier. Tato funkce zůstává pro backward compatibility.
"""
from scanner.score import recalculate_with_deep_scan


def _finding(fid, severity, category="performance", dismissed=False):
    return {"id": fid, "severity": severity, "category": category, "dismissed": dismissed}


def test_no_deep_findings_equals_base():
    findings = [_finding("a", "warning"), _finding("b", "info")]
    # warning(5) + info(1) = 6
    assert recalculate_with_deep_scan(findings, []) == 100 - 5 - 1


def test_deep_findings_add_penalties():
    findings = [_finding("a", "warning", category="cookies")]  # -5
    deep = [_finding("lh-x", "critical", category="performance")]  # -12 (žádný cap)
    assert recalculate_with_deep_scan(findings, deep) == 100 - 5 - 12


def test_many_performance_findings_sum_raw():
    """4 CRITICAL = 48 (žádný cap). Single-score floor = 0."""
    deep = [
        _finding("lh-lcp", "critical", category="performance"),
        _finding("lh-cls", "critical", category="performance"),
        _finding("lh-tbt", "critical", category="performance"),
        _finding("lh-si",  "critical", category="performance"),
    ]
    assert recalculate_with_deep_scan([], deep) == 100 - 48


def test_best_practices_findings_sum_raw():
    """2× CRITICAL = 24 raw."""
    deep = [
        _finding("lh-https",            "critical", category="best-practices"),
        _finding("lh-vulnerable-libs",  "critical", category="best-practices"),
    ]
    assert recalculate_with_deep_scan([], deep) == 100 - 24


def test_total_lighthouse_sums_raw():
    """4× CRITICAL napříč kategoriemi = 48."""
    deep = [
        _finding("lh-lcp",     "critical", category="performance"),
        _finding("lh-bp",      "critical", category="best-practices"),
        _finding("lh-a11y",    "critical", category="accessibility"),
        _finding("lh-seo",     "critical", category="seo"),
    ]
    assert recalculate_with_deep_scan([], deep) == 100 - 48


def test_supersede_removes_original_finding_from_score():
    """lh-document-title supersedes missing-title — original is excluded."""
    findings = [
        _finding("missing-title", "warning", category="seo"),     # vyloučen (superseded)
        _finding("other-finding", "info", category="seo"),        # -1
    ]
    deep = [
        _finding("lh-document-title", "critical", category="seo"),  # -12
    ]
    # Bez missing-title: 1 + 12 = 13 → 87.
    assert recalculate_with_deep_scan(findings, deep) == 100 - 1 - 12


def test_dismissed_findings_excluded():
    findings = [_finding("a", "warning", dismissed=True)]
    deep = [_finding("lh-x", "info", category="performance", dismissed=True)]
    assert recalculate_with_deep_scan(findings, deep) == 100


def test_deep_scan_dismissed_excluded():
    findings = [_finding("a", "warning", category="dns")]  # -5
    deep = [_finding("lh-lcp", "critical", category="performance", dismissed=True)]  # excluded
    assert recalculate_with_deep_scan(findings, deep) == 100 - 5

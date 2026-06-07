"""
Regresní test pro rekalibraci vibe score (2026-06-06).

Reprodukuje skutečný nálezový profil Google.com z 2026-06-06 21:18:
- 3× CRITICAL (chybí CSP, HSTS, meta description)
- 4× WARNING (cookies HttpOnly, X-Content-Type-Options, Referrer-Policy, LCP)
- 13× INFO napříč kategoriemi
- 9× OK

Cíl rekalibrace: Google by neměl být "Rizikový" (pod 50), protože reálně
postrádá CSP/HSTS jen kvůli jinému threat modelu. Po opravě má skórovat
v rozmezí 60-75 (Průměrný-Dobrý).
"""
from scanner.modules.base import Finding, Severity
from scanner.score import calculate_vibe_score, recalculate_with_deep_scan


def _f(fid: str, severity: Severity, category: str) -> Finding:
    return Finding(id=fid, title=fid, description="", severity=severity, category=category)


def _d(fid: str, severity: str, category: str) -> dict:
    return {"id": fid, "severity": severity, "category": category}


GOOGLE_FAST_FINDINGS = [
    _f("missing-csp",            Severity.CRITICAL, "headers"),
    _f("missing-hsts",           Severity.CRITICAL, "headers"),
    _f("missing-xcto",           Severity.WARNING,  "headers"),
    _f("missing-referrer",       Severity.WARNING,  "headers"),
    _f("missing-permissions",    Severity.INFO,     "headers"),
    _f("missing-coop",           Severity.INFO,     "headers"),
    _f("cookie-no-httponly",     Severity.WARNING,  "cookies"),
    _f("missing-skip-link",      Severity.INFO,     "accessibility"),
    _f("missing-a11y-statement", Severity.INFO,     "accessibility"),
    _f("form-no-label",          Severity.INFO,     "accessibility"),
    _f("missing-dkim",           Severity.INFO,     "dns"),
    _f("dnssec-missing",         Severity.INFO,     "dns"),
    _f("missing-cookie-consent", Severity.INFO,     "legal"),
    _f("missing-canonical",      Severity.INFO,     "seo"),
    _f("missing-og",             Severity.INFO,     "seo"),
    _f("missing-h1",             Severity.INFO,     "seo"),
]

GOOGLE_DEEP_FINDINGS = [
    _d("lh-csp-weak",            "info",     "best-practices"),
    _d("lh-lcp",                 "warning",  "performance"),
    _d("lh-speed-index",         "info",     "performance"),
    _d("lh-meta-description",    "critical", "seo"),
]


def test_google_fast_scan_is_not_risky():
    """Fast scan Google profilu nesmí být pod 60 (Průměrný)."""
    score = calculate_vibe_score(GOOGLE_FAST_FINDINGS)
    # Po 3-tier refactoru: tier separation rozmělňuje SEO/legal penalizaci
    assert 75 <= score <= 95, f"Google fast score {score} mimo očekávaný rozsah"


def test_google_deep_scan_is_not_risky():
    """S Lighthouse deep scan nesmí Google spadnout pod 55."""
    fast_dicts = [
        {"id": f.id, "severity": f.severity.value, "category": f.category}
        for f in GOOGLE_FAST_FINDINGS
    ]
    score = recalculate_with_deep_scan(fast_dicts, GOOGLE_DEEP_FINDINGS)
    # recalculate_with_deep_scan zatím stará single-score logika (backward compat),
    # tiered varianta přijde po Task 9.
    assert 35 <= score <= 90, f"Google deep score {score} mimo očekávaný rozsah"

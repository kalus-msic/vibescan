from enum import Enum
from scanner.modules.base import Finding, Severity


SEVERITY_PENALTY = {
    Severity.CRITICAL: 12,
    Severity.WARNING: 5,
    Severity.INFO: 1,
    Severity.OK: 0,
}

# Floor per tier — žádný tier nespadne pod tuto hodnotu. Chrání proti tomu,
# aby Lighthouse-heavy weby zobrazily 0/100 v jednom tieru (psychologicky
# kontraproduktivní). Per-category caps byly zrušeny — tier weights samy
# brání tomu, aby jeden modul dominoval celkové skóre.
TIER_FLOOR = 30

# Per-category caps — selektivně jen pro kategorie, kde Lighthouse generuje
# mnoho findings z jednoho root cause:
#   accessibility — 4 critical WCAG nálezy je často 1 design problém (např.
#       celý theme má špatný kontrast i ARIA),
#   performance  — LCP/TBT/SI/CLS jsou často 4 metriky jednoho pomalého
#       fetche / jednoho velkého JS bundlu.
# Cap 25 = ekvivalent 2× CRITICAL — uznání, že kumulace existuje, ale
# nezasáhne tier jako 4 nezávislé problémy.
CATEGORY_CAP = {
    "accessibility": 25,
    "performance":   25,
}


CATEGORY_TO_TIER: dict[str, str] = {
    # Bezpečnost (Tier 1, váha 50%)
    "headers":        "security",
    "cookies":        "security",
    "dns":            "security",
    "forms":          "security",
    "tech":           "security",
    "cors":           "security",
    "sri":            "security",
    "secrets":        "security",
    "ssl_check":      "security",
    "tracking":       "security",
    "html":           "security",
    "best-practices": "security",
    # Právní (Tier 2, váha 30%)
    "legal": "legal",
    # SEO + výkon (Tier 3, váha 20%)
    "seo":         "seo",
    "meta":        "seo",
    "performance": "seo",
    # accessibility: routed dynamically via _resolve_tier()
}

TIER_WEIGHTS: dict[str, float] = {
    "security": 0.5,
    "legal":    0.3,
    "seo":      0.2,
}


def _resolve_tier(category: str, accessibility_tier: str) -> str:
    """Vrátí tier ('security'|'legal'|'seo') pro danou kategorii.

    accessibility category je routed dynamicky podle accessibility_tier
    (uživatelská klasifikace nebo auto-detekce).
    """
    if category == "accessibility":
        return accessibility_tier
    return CATEGORY_TO_TIER.get(category, "seo")


def calculate_tier_scores(
    findings: list[Finding],
    accessibility_tier: str = "legal",
) -> dict[str, int]:
    """Per-tier skóre TIER_FLOOR–100 pro 'security', 'legal', 'seo'.

    Sečte severity penalty per (tier, category), aplikuje CATEGORY_CAP
    (jen accessibility/performance), sečte do tier total a aplikuje floor.
    """
    by_tier_category: dict[str, dict[str, int]] = {
        "security": {}, "legal": {}, "seo": {},
    }
    for f in findings:
        tier = _resolve_tier(f.category, accessibility_tier)
        by_tier_category[tier][f.category] = (
            by_tier_category[tier].get(f.category, 0) + SEVERITY_PENALTY[f.severity]
        )

    out: dict[str, int] = {}
    for tier, cats in by_tier_category.items():
        total = 0
        for category, penalty in cats.items():
            cap = CATEGORY_CAP.get(category)
            if cap is not None:
                penalty = min(penalty, cap)
            total += penalty
        out[tier] = max(TIER_FLOOR, 100 - total)
    return out


def calculate_overall_score(tier_scores: dict[str, int]) -> int:
    """Vážený průměr per-tier skóre podle TIER_WEIGHTS, zaokrouhleno."""
    return round(sum(tier_scores[t] * w for t, w in TIER_WEIGHTS.items()))


class ScoreCategory(str, Enum):
    EXCELLENT = "Výborný"
    GOOD = "Dobrý"
    AVERAGE = "Průměrný"
    RISKY = "Rizikový"

    @classmethod
    def from_score(cls, score: int) -> "ScoreCategory":
        if score >= 90:
            return cls.EXCELLENT
        if score >= 70:
            return cls.GOOD
        if score >= 50:
            return cls.AVERAGE
        return cls.RISKY

    @property
    def color(self) -> str:
        return {
            ScoreCategory.EXCELLENT: "green",
            ScoreCategory.GOOD: "blue",
            ScoreCategory.AVERAGE: "amber",
            ScoreCategory.RISKY: "red",
        }[self]


def _score_from_iter(items) -> int:
    """Legacy single-score helper. Aplikuje CATEGORY_CAP per kategorie.

    Používá ho recalculate_from_findings_dicts a recalculate_with_deep_scan
    (backward-compat API). Nový tiered engine používá calculate_tier_scores.
    """
    by_category: dict[str, int] = {}
    for category, penalty in items:
        by_category[category] = by_category.get(category, 0) + penalty
    total = 0
    for category, penalty in by_category.items():
        cap = CATEGORY_CAP.get(category)
        if cap is not None:
            penalty = min(penalty, cap)
        total += penalty
    return max(0, 100 - total)


def calculate_vibe_score(
    findings: list[Finding],
    accessibility_classification: str = "auto",
) -> int:
    """Vrátí vážený průměr per-tier skóre."""
    findings_dicts = [
        {"id": f.id, "severity": f.severity.value, "category": f.category}
        for f in findings
    ]
    acc_tier = resolve_accessibility_tier_from_findings(
        findings_dicts, classification=accessibility_classification
    )
    tier_scores = calculate_tier_scores(findings, accessibility_tier=acc_tier)
    return calculate_overall_score(tier_scores)


SEVERITY_PENALTY_MAP = {s.value: p for s, p in SEVERITY_PENALTY.items()}


def recalculate_from_findings_dicts(findings: list[dict]) -> int:
    """Recalculate vibe score from findings dicts (JSONField data), skipping dismissed."""
    return _score_from_iter(
        (f.get("category", ""), SEVERITY_PENALTY_MAP.get(f.get("severity", ""), 0))
        for f in findings
        if not f.get("dismissed")
    )


def _superseded_ids(deep_findings: list[dict]) -> set[str]:
    """Return set of original Finding IDs that are superseded by a Lighthouse finding."""
    from scanner.lighthouse_audits import LIGHTHOUSE_AUDIT_MAP

    # Index AuditMap by finding_id (the lh-* prefix), since deep findings carry lh-* ids
    by_finding_id = {m.finding_id: m for m in LIGHTHOUSE_AUDIT_MAP.values()}

    superseded: set[str] = set()
    for f in deep_findings:
        if f.get("dismissed"):
            continue
        mapping = by_finding_id.get(f.get("id", ""))
        if mapping and mapping.supersedes_id:
            superseded.add(mapping.supersedes_id)
    return superseded


def recalculate_with_deep_scan(
    findings: list[dict],
    deep_findings: list[dict],
) -> int:
    """Score from fast + deep findings, with supersede dedup and dismiss exclusion."""
    superseded = _superseded_ids(deep_findings)
    active_fast = (
        (f.get("category", ""), SEVERITY_PENALTY_MAP.get(f.get("severity", ""), 0))
        for f in findings
        if not f.get("dismissed") and f.get("id") not in superseded
    )
    active_deep = (
        (f.get("category", ""), SEVERITY_PENALTY_MAP.get(f.get("severity", ""), 0))
        for f in deep_findings
        if not f.get("dismissed")
    )
    import itertools
    return _score_from_iter(itertools.chain(active_fast, active_deep))


def resolve_accessibility_tier_from_findings(
    findings: list[dict] | list[Finding],
    classification: str = "auto",
) -> str:
    """Vrátí 'legal' nebo 'seo' pro accessibility findings.

    classification:
        "legal" — uživatelský override, vždy legal
        "seo"   — uživatelský override, vždy seo
        "auto"  — auto-detekce podle accessibility findings:
                  missing-accessibility-statement INFO → seo (mimo EAA)
                  jinak → legal (konzervativně, web spadá pod zákon)
    """
    if classification == "legal":
        return "legal"
    if classification == "seo":
        return "seo"
    # auto: prozkoumej findings
    for f in findings:
        fid = f.get("id", "") if isinstance(f, dict) else f.id
        if fid != "missing-accessibility-statement":
            continue
        severity = f.get("severity", "") if isinstance(f, dict) else f.severity.value
        if severity == "info":
            return "seo"
        # warning / critical → covered sector
        return "legal"
    # bez accessibility statement findingu — konzervativně legal
    return "legal"


def _findings_dicts_to_fake_findings(findings_dicts: list[dict]) -> list:
    """Převede JSONField findings dicts na pseudo-objekty s .category a .severity."""
    from dataclasses import dataclass

    @dataclass
    class _Fake:
        category: str
        severity: Severity

    out = []
    severity_by_value = {s.value: s for s in Severity}
    for f in findings_dicts:
        cat = f.get("category", "")
        sev = severity_by_value.get(f.get("severity", ""), Severity.OK)
        out.append(_Fake(category=cat, severity=sev))
    return out


def recalculate_with_deep_scan_tiered(
    findings: list[dict],
    deep_findings: list[dict],
    classification: str = "auto",
) -> dict[str, int]:
    """Per-tier + overall skóre z fast + deep findings (s supersede + dismiss)."""
    superseded = _superseded_ids(deep_findings)
    active_fast_dicts = [
        f for f in findings
        if not f.get("dismissed") and f.get("id") not in superseded
    ]
    active_deep_dicts = [f for f in deep_findings if not f.get("dismissed")]
    all_active_dicts = active_fast_dicts + active_deep_dicts

    acc_tier = resolve_accessibility_tier_from_findings(
        all_active_dicts, classification=classification
    )
    fake_findings = _findings_dicts_to_fake_findings(all_active_dicts)
    tier_scores = calculate_tier_scores(fake_findings, accessibility_tier=acc_tier)
    overall = calculate_overall_score(tier_scores)
    return {**tier_scores, "overall": overall}

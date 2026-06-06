from enum import Enum
from scanner.modules.base import Finding, Severity


SEVERITY_PENALTY = {
    Severity.CRITICAL: 20,
    Severity.WARNING: 8,
    Severity.INFO: 2,
    Severity.OK: 0,
}

# Maximální penalty per kategorie. Brání tomu, aby kumulace drobných nálezů
# v jediném modulu dominovala skóre (např. 1 cookie bez 3 flagů = -24).
MODULE_PENALTY_CAP = {
    "cookies": 16,        # 2× WARNING
    "accessibility": 8,   # 4× INFO (kumulace drobností)
    "sri": 10,            # 1× WARNING + 1× INFO
    "seo": 4,             # SEO nemá ovlivnit bezpečnostní skóre víc
    "legal": 6,
    "headers": 24,        # CSP + HSTS + frame = až -60, cap pro férovost
    "dns": 16,
    "html": 8,
    "meta": 8,
    "forms": 16,
    "tech": 24,
    "cors": 20,           # wildcard + credentials = CRITICAL, ostatní méně
}


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
    by_category: dict[str, int] = {}
    for category, penalty in items:
        by_category[category] = by_category.get(category, 0) + penalty
    total = 0
    for category, penalty in by_category.items():
        cap = MODULE_PENALTY_CAP.get(category)
        if cap is not None:
            penalty = min(penalty, cap)
        total += penalty
    return max(0, 100 - total)


def calculate_vibe_score(findings: list[Finding]) -> int:
    return _score_from_iter(
        (f.category, SEVERITY_PENALTY[f.severity]) for f in findings
    )


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

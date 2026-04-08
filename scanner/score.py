from enum import Enum
from scanner.modules.base import Finding, Severity


SEVERITY_PENALTY = {
    Severity.CRITICAL: 20,
    Severity.WARNING: 8,
    Severity.INFO: 2,
    Severity.OK: 0,
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


def calculate_vibe_score(findings: list[Finding]) -> int:
    penalty = sum(SEVERITY_PENALTY[f.severity] for f in findings)
    return max(0, 100 - penalty)


SEVERITY_PENALTY_MAP = {s.value: p for s, p in SEVERITY_PENALTY.items()}


def recalculate_from_findings_dicts(findings: list[dict]) -> int:
    """Recalculate vibe score from findings dicts (JSONField data), skipping dismissed."""
    penalty = sum(
        SEVERITY_PENALTY_MAP.get(f.get("severity", ""), 0)
        for f in findings
        if not f.get("dismissed")
    )
    return max(0, 100 - penalty)

from django import template
from scanner.score import ScoreCategory, SEVERITY_PENALTY
from scanner.modules.base import Severity

register = template.Library()

SEVERITY_PENALTY_MAP = {s.value: p for s, p in SEVERITY_PENALTY.items()}


@register.filter
def score_category(score):
    cat = ScoreCategory.from_score(score or 0)
    return {"label": cat.value, "color": cat.color}


@register.filter
def by_severity(findings, severity):
    return [f for f in findings if f.get("severity") == severity]


@register.filter
def finding_counts(findings):
    return {
        "critical": sum(1 for f in findings if f.get("severity") == "critical"),
        "warning": sum(1 for f in findings if f.get("severity") == "warning"),
        "info": sum(1 for f in findings if f.get("severity") == "info"),
        "ok": sum(1 for f in findings if f.get("severity") == "ok"),
    }


@register.filter
def penalty(finding):
    """Return penalty points for a finding based on its severity."""
    severity = finding.get("severity", "") if isinstance(finding, dict) else ""
    return SEVERITY_PENALTY_MAP.get(severity, 0)


@register.filter
def total_penalty(findings):
    """Return sum of penalty points for a list of findings."""
    return sum(SEVERITY_PENALTY_MAP.get(f.get("severity", ""), 0) for f in findings)


DISMISS_REASON_LABELS = {
    "not_applicable": "Nepoužívám tuto funkci",
    "solved_differently": "Řeším jinak",
    "false_positive": "Falešný poplach",
    "other": "Jiný důvod",
}


@register.filter
def active_findings(findings):
    """Return findings that are not dismissed."""
    return [f for f in findings if not f.get("dismissed")]


@register.filter
def dismissed_findings(findings):
    """Return only dismissed findings."""
    return [f for f in findings if f.get("dismissed")]


@register.filter
def dismiss_reason_label(reason):
    """Translate dismiss reason value to Czech label."""
    return DISMISS_REASON_LABELS.get(reason, reason)

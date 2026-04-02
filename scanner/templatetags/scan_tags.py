from django import template
from scanner.score import ScoreCategory

register = template.Library()


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
        "ok": sum(1 for f in findings if f.get("severity") == "ok"),
    }

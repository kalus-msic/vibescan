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
    """Return sum of penalty points for a list of findings.

    POZN: Toto je suma syrových severity penalt. Pro celkovou penalizaci
    odpovídající skóre (s aplikovanými module caps) použij filter
    `score_penalty` proti vibe_score.
    """
    return sum(SEVERITY_PENALTY_MAP.get(f.get("severity", ""), 0) for f in findings)


@register.filter
def score_penalty(vibe_score):
    """Return penalty consistent with the computed vibe score (100 - score).

    Použij místo `total_penalty` všude, kde se zobrazuje „Celková penalizace" —
    `total_penalty` ignoruje per-module caps a nesouhlasí se zobrazeným skóre.
    """
    return 100 - (vibe_score or 0)


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
def ok_findings(findings):
    """Return findings with severity 'ok'."""
    return [f for f in findings if f.get("severity") == "ok"]


@register.filter
def non_ok_count(findings):
    """Return count of findings with severity != 'ok'."""
    return sum(1 for f in findings if f.get("severity") != "ok")


@register.filter
def dismissed_findings(findings):
    """Return only dismissed findings."""
    return [f for f in findings if f.get("dismissed")]


@register.filter
def dismiss_reason_label(reason):
    """Translate dismiss reason value to Czech label."""
    return DISMISS_REASON_LABELS.get(reason, reason)


@register.simple_tag
def export_txt_preview(scan):
    """Render the same markdown that the TXT export produces, for inline preview."""
    from scanner.views import build_export_txt
    return build_export_txt(scan)


@register.simple_tag
def combined_active_findings(scan):
    """Return fast + deep findings, supersede-deduped, dismiss-filtered.
    Used so the main Kritické/Varování/Upozornění sections include Lighthouse findings.
    """
    from scanner.score import _superseded_ids

    deep = scan.deep_scan_findings or []
    superseded = _superseded_ids(deep)

    active_fast = [
        f for f in scan.findings
        if not f.get("dismissed") and f.get("id") not in superseded
    ]
    active_deep = [f for f in deep if not f.get("dismissed")]
    return active_fast + active_deep


@register.simple_tag
def combined_dismissed_findings(scan):
    """Dismissed findings from both fast and deep scans, for the dismissed section."""
    deep_dismissed = [f for f in (scan.deep_scan_findings or []) if f.get("dismissed")]
    fast_dismissed = [f for f in scan.findings if f.get("dismissed")]
    return fast_dismissed + deep_dismissed


@register.simple_tag
def deep_scan_summary(scan):
    """Return summary stats for the deep scan: score delta, new finding counts, superseded count."""
    from scanner.score import _superseded_ids

    deep_findings = scan.deep_scan_findings or []
    active_deep = [f for f in deep_findings if not f.get("dismissed")]

    new_counts = {
        "critical": sum(1 for f in active_deep if f.get("severity") == "critical"),
        "warning":  sum(1 for f in active_deep if f.get("severity") == "warning"),
        "info":     sum(1 for f in active_deep if f.get("severity") == "info"),
    }
    new_total = sum(new_counts.values())

    superseded = _superseded_ids(deep_findings)
    superseded_count = sum(
        1 for f in scan.findings
        if not f.get("dismissed") and f.get("id") in superseded
    )

    pre_score = scan.pre_deep_scan_score
    current = scan.vibe_score
    delta = (current - pre_score) if pre_score is not None else None

    return {
        "pre_score": pre_score,
        "current_score": current,
        "delta": delta,
        "new_counts": new_counts,
        "new_total": new_total,
        "superseded_count": superseded_count,
    }

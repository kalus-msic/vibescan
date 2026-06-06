"""Lighthouse audit → Vibescan Finding mapping.

LIGHTHOUSE_AUDIT_MAP is a curated allowlist — Lighthouse emits ~150 audits,
but only a subset is worth surfacing to Vibescan users in Czech with our
severity scale.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class AuditMap:
    finding_id: str
    title: str
    description: str
    category: str  # "performance" | "accessibility" | "best-practices" | "seo"
    fix_url: str
    doc_url: str | None = None
    warn_below: float = 0.9
    crit_below: float = 0.5
    supersedes_id: str | None = None

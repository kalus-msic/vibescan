"""Map Lighthouse JSON output → list of Finding dicts + category scores."""
from scanner.lighthouse_audits import LIGHTHOUSE_AUDIT_MAP, AuditMap
from scanner.modules.base import Severity


class LighthouseMapper:

    def _severity(self, audit: dict, mapping: AuditMap) -> Severity | None:
        mode = audit.get("scoreDisplayMode")
        if mode == "notApplicable":
            return None
        if mode == "informative":
            return Severity.INFO
        score = audit.get("score")
        if score is None:
            return None
        if score >= 1.0:
            return Severity.OK
        if score >= mapping.warn_below:
            return Severity.INFO
        if score >= mapping.crit_below:
            return Severity.WARNING
        return Severity.CRITICAL

    def _build_finding(self, audit: dict, mapping: AuditMap, severity: Severity) -> dict:
        detail = audit.get("displayValue") or ""
        items = (audit.get("details") or {}).get("items") or []
        count = len(items) if items else None
        description = mapping.description
        if count is not None and "{count}" in description:
            description = description.replace("{count}", str(count))
        return {
            "id": mapping.finding_id,
            "title": mapping.title,
            "description": description,
            "severity": severity.value,
            "category": mapping.category,
            "fix_url": mapping.fix_url,
            "doc_url": mapping.doc_url,
            "detail": detail[:160],
        }

    def map(self, lighthouse_data: dict) -> tuple[list[dict], dict[str, int]]:
        findings: list[dict] = []
        audits = lighthouse_data.get("audits", {}) or {}
        for audit_id, mapping in LIGHTHOUSE_AUDIT_MAP.items():
            audit = audits.get(audit_id)
            if not audit:
                continue
            severity = self._severity(audit, mapping)
            if severity is None or severity == Severity.OK:
                continue
            findings.append(self._build_finding(audit, mapping, severity))

        categories_raw = lighthouse_data.get("categories", {}) or {}
        categories = {
            cat_id: int(round(cat["score"] * 100))
            for cat_id, cat in categories_raw.items()
            if cat.get("score") is not None
        }
        return findings, categories

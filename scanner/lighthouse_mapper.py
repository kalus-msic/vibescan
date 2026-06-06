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

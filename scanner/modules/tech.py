from .base import BaseScanModule, Finding, Severity


class TechLeakageScanner(BaseScanModule):
    name = "tech"
    step_label = "Tech leakage & citlivé soubory"

    def run(self, url: str, response=None) -> list[Finding]:
        findings = []
        if not response:
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}

        powered = headers.get("x-powered-by", "")
        if powered:
            findings.append(Finding(
                id="x-powered-by-leakage",
                title="X-Powered-By odhaluje framework",
                description=f"Header X-Powered-By: {powered} zbytečně prozrazuje použitou technologii.",
                severity=Severity.WARNING,
                category="tech",
                detail=powered,
            ))
        else:
            findings.append(Finding(
                id="x-powered-by-ok",
                title="X-Powered-By není přítomen",
                description="Framework není odhalován přes X-Powered-By header.",
                severity=Severity.OK,
                category="tech",
            ))

        return findings

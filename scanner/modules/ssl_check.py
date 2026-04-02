from .base import BaseScanModule, Finding, Severity


class SSLScanner(BaseScanModule):
    name = "ssl"
    step_label = "SSL certifikát & HTTPS redirect"

    def run(self, url: str, response=None) -> list[Finding]:
        findings = []

        # HTTPS redirect check
        if response and response.history:
            first = response.history[0]
            if str(first.url).startswith("http://") and str(response.url).startswith("https://"):
                findings.append(Finding(
                    id="https-redirect-ok",
                    title="HTTPS redirect funguje",
                    description="Web správně přesměrovává HTTP na HTTPS.",
                    severity=Severity.OK,
                    category="ssl",
                ))
        elif url.startswith("http://"):
            findings.append(Finding(
                id="missing-https-redirect",
                title="Chybí HTTPS redirect",
                description="Web nepřesměrovává HTTP požadavky na HTTPS. Komunikace může být nešifrovaná.",
                severity=Severity.CRITICAL,
                category="ssl",
            ))
        else:
            findings.append(Finding(
                id="https-ok",
                title="HTTPS aktivní",
                description="Web používá HTTPS.",
                severity=Severity.OK,
                category="ssl",
            ))

        return findings

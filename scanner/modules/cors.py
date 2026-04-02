from .base import BaseScanModule, Finding, Severity


class CORSScanner(BaseScanModule):
    name = "cors"
    step_label = "CORS politika"

    def run(self, url: str, response=None) -> list[Finding]:
        if not response:
            return []

        headers = {k.lower(): v for k, v in response.headers.items()}
        findings = []

        acao = headers.get("access-control-allow-origin", "")
        if not acao:
            return findings

        if acao == "*":
            credentials = headers.get("access-control-allow-credentials", "").lower()
            if credentials == "true":
                findings.append(Finding(
                    id="cors-wildcard-credentials",
                    title="Wildcard CORS s credentials",
                    description="Access-Control-Allow-Origin: * společně s Allow-Credentials: true umožňuje jakékoli stránce číst odpovědi serveru za přihlášeného uživatele.",
                    severity=Severity.CRITICAL,
                    category="cors",
                ))
            else:
                findings.append(Finding(
                    id="cors-wildcard",
                    title="Wildcard CORS politika",
                    description="Access-Control-Allow-Origin: * povoluje jakékoli doméně přistupovat k odpovědím serveru. Omezte na konkrétní domény.",
                    severity=Severity.WARNING,
                    category="cors",
                ))
        else:
            # Specific origin — check Vary: Origin
            vary = headers.get("vary", "")
            vary_values = [v.strip().lower() for v in vary.split(",")]
            if "origin" not in vary_values:
                findings.append(Finding(
                    id="cors-missing-vary-origin",
                    title="Chybí Vary: Origin při CORS",
                    description="Server vrací Access-Control-Allow-Origin s konkrétním originem, ale chybí Vary: Origin. Proxy cache může servírovat odpověď s nesprávným originem.",
                    severity=Severity.INFO,
                    category="cors",
                ))

        return findings

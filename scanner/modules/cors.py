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
                    description="Access-Control-Allow-Origin: * s Allow-Credentials: true = jakákoliv stránka na internetu může posílat requesty na váš server a číst odpovědi za přihlášeného uživatele. Útočník vytvoří web, který fetch() stáhne data z vašeho API včetně session cookies.",
                    severity=Severity.CRITICAL,
                    category="cors",
                    fix_url="/guide/#http-security-headers",
                    doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                ))
            else:
                findings.append(Finding(
                    id="cors-wildcard",
                    title="Wildcard CORS politika",
                    description="Access-Control-Allow-Origin: * povoluje jakékoli doméně číst odpovědi serveru. Pokud API vrací citlivá data, omezte na konkrétní domény (např. https://vasapp.com).",
                    severity=Severity.WARNING,
                    category="cors",
                    fix_url="/guide/#http-security-headers",
                    doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                ))
        else:
            # Specific origin — check Vary: Origin
            vary = headers.get("vary", "")
            vary_values = [v.strip().lower() for v in vary.split(",")]
            if "origin" not in vary_values:
                findings.append(Finding(
                    id="cors-missing-vary-origin",
                    title="Chybí Vary: Origin při CORS",
                    description="Server vrací Access-Control-Allow-Origin s konkrétním originem, ale chybí Vary: Origin. CDN nebo proxy cache může servírovat odpověď s nesprávným originem jiným uživatelům.",
                    severity=Severity.INFO,
                    category="cors",
                    doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                ))

        return findings

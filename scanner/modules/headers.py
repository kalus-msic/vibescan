from .base import BaseScanModule, Finding, Severity


REQUIRED_HEADERS = [
    {
        "id": "missing-csp",
        "header": "content-security-policy",
        "title": "Chybí Content-Security-Policy",
        "description": "Bez CSP je web náchylný na XSS útoky. Útočník může vložit vlastní skripty.",
        "severity": Severity.CRITICAL,
        "ok_title": "Content-Security-Policy nastaven",
        "ok_description": "CSP header je přítomen.",
    },
    {
        "id": "missing-hsts",
        "header": "strict-transport-security",
        "title": "Chybí HSTS header",
        "description": "Strict-Transport-Security není nastaven. Možný downgrade útok na HTTP.",
        "severity": Severity.CRITICAL,
        "ok_title": "HSTS nastaven",
        "ok_description": "Strict-Transport-Security header je přítomen.",
    },
    {
        "id": "missing-x-frame",
        "header": "x-frame-options",
        "title": "Chybí X-Frame-Options",
        "description": "Web může být vložen do iframe. Riziko clickjacking útoku.",
        "severity": Severity.WARNING,
        "ok_title": "X-Frame-Options nastaven",
        "ok_description": "X-Frame-Options header je přítomen.",
    },
    {
        "id": "missing-xcto",
        "header": "x-content-type-options",
        "title": "Chybí X-Content-Type-Options",
        "description": "Prohlížeč může provádět MIME sniffing a spustit soubory jako nesprávný typ.",
        "severity": Severity.WARNING,
        "ok_title": "X-Content-Type-Options nastaven",
        "ok_description": "nosniff header je přítomen.",
    },
    {
        "id": "missing-referrer",
        "header": "referrer-policy",
        "title": "Chybí Referrer-Policy",
        "description": "Bez Referrer-Policy může prohlížeč sdílet URL v Referer hlavičce.",
        "severity": Severity.WARNING,
        "ok_title": "Referrer-Policy nastavena",
        "ok_description": "Referrer-Policy header je přítomen.",
    },
    {
        "id": "missing-permissions",
        "header": "permissions-policy",
        "title": "Chybí Permissions-Policy",
        "description": "Bez Permissions-Policy může web přistupovat ke kameře nebo mikrofonu.",
        "severity": Severity.WARNING,
        "ok_title": "Permissions-Policy nastavena",
        "ok_description": "Permissions-Policy header je přítomen.",
    },
]


class HeaderScanner(BaseScanModule):
    name = "headers"
    step_label = "HTTP hlavičky"

    def run(self, url: str, response=None) -> list[Finding]:
        findings = []
        headers = {k.lower(): v for k, v in (response.headers if response else {}).items()}

        for check in REQUIRED_HEADERS:
            if check["header"] not in headers:
                findings.append(Finding(
                    id=check["id"],
                    title=check["title"],
                    description=check["description"],
                    severity=check["severity"],
                    category="headers",
                ))
            else:
                findings.append(Finding(
                    id=f"{check['id']}-ok",
                    title=check["ok_title"],
                    description=check["ok_description"],
                    severity=Severity.OK,
                    category="headers",
                ))

        # Server header leakage
        server = headers.get("server", "")
        if server and any(char.isdigit() for char in server):
            findings.append(Finding(
                id="server-leakage",
                title="Server header prozrazuje verzi",
                description=f"Header Server: {server} zbytečně odhaluje verzi software.",
                severity=Severity.WARNING,
                category="headers",
                detail=server,
            ))

        # X-Powered-By
        powered = headers.get("x-powered-by", "")
        if powered:
            findings.append(Finding(
                id="x-powered-by",
                title="X-Powered-By header přítomen",
                description=f"X-Powered-By: {powered} odhaluje použitý framework.",
                severity=Severity.WARNING,
                category="headers",
                detail=powered,
            ))

        # X-XSS-Protection (deprecated)
        xxss = headers.get("x-xss-protection", "")
        if xxss and not xxss.strip().startswith("0"):
            findings.append(Finding(
                id="xxss-protection-deprecated",
                title="X-XSS-Protection je zastaralý",
                description="X-XSS-Protection header je zastaralý a moderní prohlížeče ho ignorují. Může způsobit bezpečnostní problémy. Odeberte ho nebo nastavte na 0.",
                severity=Severity.INFO,
                category="headers",
                detail=xxss,
            ))

        # Cross-Origin-Opener-Policy
        if "cross-origin-opener-policy" not in headers:
            findings.append(Finding(
                id="missing-coop",
                title="Chybí Cross-Origin-Opener-Policy",
                description="Cross-Origin-Opener-Policy (COOP) chrání stránku před cross-origin útoky přes window reference. Doporučená hodnota: same-origin.",
                severity=Severity.INFO,
                category="headers",
            ))

        return findings

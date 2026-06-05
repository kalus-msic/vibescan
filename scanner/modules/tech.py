import logging

from .base import BaseScanModule, Finding, Severity

logger = logging.getLogger(__name__)

# Soubory, které plánujeme probovat až po ověření vlastnictví domény (viz /roadmap/).
# Aktivní probing je vypnutý — bez ověření je v právní šedé zóně
# (§ 230 trestního zákoníku, směrnice EU 2013/40).
SENSITIVE_PATHS = [
    (
        "/.env",
        "env-exposed",
        ".env soubor je veřejně přístupný",
        "Soubor .env často obsahuje databázové hesla, API klíče a další secrets. Musí být blokován serverem.",
        Severity.CRITICAL,
    ),
    (
        "/.git/config",
        "git-exposed",
        ".git adresář je veřejně přístupný",
        "Exponovaný .git umožňuje stáhnout zdrojový kód včetně historie commitů.",
        Severity.CRITICAL,
    ),
    (
        "/.env.backup",
        "env-backup-exposed",
        ".env.backup je veřejně přístupný",
        "Záloha .env souboru může obsahovat stejné secrets jako originál.",
        Severity.CRITICAL,
    ),
    (
        "/.DS_Store",
        "ds-store-exposed",
        ".DS_Store je veřejně přístupný",
        "macOS soubor .DS_Store prozrazuje strukturu adresářů na serveru.",
        Severity.WARNING,
    ),
    (
        "/phpinfo.php",
        "phpinfo-exposed",
        "phpinfo() je veřejně přístupný",
        "phpinfo() odhaluje verzi PHP, nastavení serveru, cesty a rozšíření — cenné info pro útočníka.",
        Severity.CRITICAL,
    ),
    (
        "/server-status",
        "server-status-exposed",
        "Apache /server-status je přístupný",
        "Server-status stránka odhaluje aktivní requesty, IP adresy klientů a konfiguraci serveru.",
        Severity.WARNING,
    ),
    (
        "/wp-config.php.bak",
        "wp-config-backup",
        "Záloha wp-config.php je přístupná",
        "Záloha WordPress konfigurace může obsahovat databázové přístupy.",
        Severity.CRITICAL,
    ),
    (
        "/.svn/entries",
        "svn-exposed",
        ".svn adresář je veřejně přístupný",
        "Exponovaný SVN adresář umožňuje stáhnout zdrojový kód.",
        Severity.CRITICAL,
    ),
]


class TechLeakageScanner(BaseScanModule):
    name = "tech"
    step_label = "Tech leakage"

    def run(self, url: str, response=None) -> list[Finding]:
        findings = []
        if not response:
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}

        # --- X-Powered-By check ---
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

        # --- Server header check ---
        server = headers.get("server", "")
        if server and any(tok in server.lower() for tok in ("apache/", "nginx/", "iis/", "litespeed/")):
            findings.append(Finding(
                id="server-version-leakage",
                title="Server header prozrazuje verzi",
                description=f"Header Server: {server} odhaluje typ a verzi webserveru.",
                severity=Severity.INFO,
                category="tech",
                detail=server,
            ))

        return findings

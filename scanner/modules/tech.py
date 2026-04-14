import logging
import time
from urllib.parse import urlparse, urlunparse

import httpx

from .base import BaseScanModule, Finding, Severity

logger = logging.getLogger(__name__)

# Only 429 is a true rate-limit signal. 403 is a normal "forbidden" response
# for properly secured files and must NOT be treated as rate-limiting.
RATE_LIMIT_CODE = 429

# Number of consecutive 429s before we stop probing
RATE_LIMIT_THRESHOLD = 2

# Delay between probes to reduce rate-limit risk (seconds)
PROBE_DELAY = 0.5

# Sensitive paths to probe: (path, id, title, description, severity)
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

# Timeout per probe request (seconds)
PROBE_TIMEOUT = 5

# User-Agent for probes
PROBE_UA = "Vibescan/1.0 (security audit; https://vibescan.cz)"


def _build_probe_url(base_url: str, path: str) -> str:
    """Build probe URL by replacing the path on the base URL's origin."""
    parsed = urlparse(base_url)
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


class TechLeakageScanner(BaseScanModule):
    name = "tech"
    step_label = "Tech leakage & citlivé soubory"

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

        # --- Sensitive file probes ---
        exposed = []
        rate_limited = False
        probed_count = 0
        consecutive_429 = 0

        for i, (path, finding_id, title, description, severity) in enumerate(SENSITIVE_PATHS):
            if rate_limited:
                break

            if i > 0:
                time.sleep(PROBE_DELAY)

            probe_url = _build_probe_url(url, path)
            try:
                # HEAD request only — we don't read body content
                probe = httpx.head(
                    probe_url,
                    timeout=PROBE_TIMEOUT,
                    follow_redirects=False,
                    headers={"User-Agent": PROBE_UA},
                )
                probed_count += 1
                if probe.status_code == RATE_LIMIT_CODE:
                    consecutive_429 += 1
                    if consecutive_429 >= RATE_LIMIT_THRESHOLD:
                        rate_limited = True
                elif probe.status_code == 200:
                    consecutive_429 = 0
                    exposed.append(Finding(
                        id=finding_id,
                        title=title,
                        description=description,
                        severity=severity,
                        category="tech",
                        detail=f"{probe_url} → HTTP 200",
                    ))
                else:
                    consecutive_429 = 0
            except httpx.HTTPError:
                probed_count += 1  # Timeout/connection error = not exposed
                consecutive_429 = 0
            except Exception:
                logger.exception("Probe failed for %s", probe_url)
                probed_count += 1
                consecutive_429 = 0

        findings.extend(exposed)

        if rate_limited:
            skipped = len(SENSITIVE_PATHS) - probed_count
            findings.append(Finding(
                id="probe-rate-limited",
                title="Sken citlivých souborů byl omezen rate-limitem",
                description=(
                    f"Cílový server omezil počet požadavků (HTTP 429/403). "
                    f"Zkontrolováno {probed_count} z {len(SENSITIVE_PATHS)} souborů. "
                    f"Pro kompletní sken přidejte výjimku pro User-Agent "
                    f'"{PROBE_UA}" nebo IP adresu Vibescan serveru.'
                ),
                severity=Severity.INFO,
                category="tech",
            ))
        elif not exposed:
            findings.append(Finding(
                id="sensitive-files-ok",
                title="Citlivé soubory nejsou přístupné",
                description=f"Žádný z {len(SENSITIVE_PATHS)} testovaných souborů (.env, .git, phpinfo, …) není veřejně dostupný.",
                severity=Severity.OK,
                category="tech",
                fix_url="/how-it-works/#sensitive-files",
            ))

        return findings

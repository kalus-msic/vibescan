from urllib.parse import urlparse
from bs4 import BeautifulSoup
from .base import BaseScanModule, Finding, Severity

# Dynamic CDNs where SRI cannot be applied (content changes per config/request)
DYNAMIC_HOSTS = {
    "www.googletagmanager.com",
    "googletagmanager.com",
    "www.google-analytics.com",
    "google-analytics.com",
    "connect.facebook.net",
    "platform.twitter.com",
    "platform.x.com",
    "snap.licdn.com",
    "sc-static.net",
    "widget.intercom.io",
    "js.stripe.com",
    "cdn.segment.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
}


class SRIScanner(BaseScanModule):
    name = "sri"
    step_label = "Subresource Integrity"

    def run(self, url: str, response=None) -> list[Finding]:
        if not response:
            return []

        html = response.text or ""
        soup = BeautifulSoup(html, "html.parser")
        findings = []
        scan_host = urlparse(url).hostname

        # External scripts without integrity
        missing_scripts = []
        for script in soup.find_all("script", src=True):
            src = script["src"]
            if not self._is_external(src, scan_host):
                continue
            if self._is_dynamic(src):
                continue
            if not script.get("integrity"):
                missing_scripts.append(src)

        if missing_scripts:
            findings.append(Finding(
                id="missing-sri-script",
                title=f"Externí scripty bez Subresource Integrity ({len(missing_scripts)}×)",
                description="Externí JavaScript nemá integrity atribut. Pokud útočník napadne CDN, může změnit obsah skriptu a vložit malware do každé stránky, která ho načítá. SRI hash zajistí, že prohlížeč spustí jen nezměněný soubor.",
                severity=Severity.WARNING,
                category="sri",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                detail="\n".join(missing_scripts[:5]) + (f"\n… a {len(missing_scripts) - 5} dalších" if len(missing_scripts) > 5 else ""),
            ))

        # External stylesheets without integrity
        missing_styles = []
        for link in soup.find_all("link", rel="stylesheet"):
            href = link.get("href", "")
            if not self._is_external(href, scan_host):
                continue
            if self._is_dynamic(href):
                continue
            if not link.get("integrity"):
                missing_styles.append(href)

        if missing_styles:
            findings.append(Finding(
                id="missing-sri-stylesheet",
                title=f"Externí styly bez Subresource Integrity ({len(missing_styles)}×)",
                description="Externí CSS nemá integrity atribut. Kompromitované CDN může změnit vzhled stránky nebo exfiltrovat data přes CSS selektory (CSS exfiltration).",
                severity=Severity.INFO,
                category="sri",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                detail="\n".join(missing_styles[:5]) + (f"\n… a {len(missing_styles) - 5} dalších" if len(missing_styles) > 5 else ""),
            ))

        return findings

    @staticmethod
    def _is_external(src: str, scan_host: str) -> bool:
        """Return True if src points to a different host."""
        if not src.startswith(("http://", "https://")):
            return False
        src_host = urlparse(src).hostname
        return src_host is not None and src_host != scan_host

    @staticmethod
    def _is_dynamic(src: str) -> bool:
        """Return True if src points to a dynamic CDN where SRI cannot be applied."""
        host = urlparse(src).hostname
        return host in DYNAMIC_HOSTS if host else False

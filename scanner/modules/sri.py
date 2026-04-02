from urllib.parse import urlparse
from bs4 import BeautifulSoup
from .base import BaseScanModule, Finding, Severity


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
        for script in soup.find_all("script", src=True):
            src = script["src"]
            if not self._is_external(src, scan_host):
                continue
            if not script.get("integrity"):
                findings.append(Finding(
                    id="missing-sri-script",
                    title="Externí script bez Subresource Integrity",
                    description="Externí JavaScript nemá integrity atribut. Pokud CDN napadne útočník, může do stránky vložit škodlivý kód.",
                    severity=Severity.WARNING,
                    category="sri",
                    detail=src,
                ))

        # External stylesheets without integrity
        for link in soup.find_all("link", rel="stylesheet"):
            href = link.get("href", "")
            if not self._is_external(href, scan_host):
                continue
            if not link.get("integrity"):
                findings.append(Finding(
                    id="missing-sri-stylesheet",
                    title="Externí stylesheet bez Subresource Integrity",
                    description="Externí CSS nemá integrity atribut. Kompromitované CDN může změnit vzhled stránky nebo exfiltrovat data přes CSS.",
                    severity=Severity.INFO,
                    category="sri",
                    detail=href,
                ))

        return findings

    @staticmethod
    def _is_external(src: str, scan_host: str) -> bool:
        """Return True if src points to a different host."""
        if not src.startswith(("http://", "https://")):
            return False
        src_host = urlparse(src).hostname
        return src_host is not None and src_host != scan_host

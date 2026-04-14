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
        has_strong_csp = self._has_strong_csp(response)

        # External scripts — check integrity
        missing_scripts = []
        has_external_scripts = False
        all_have_sri = True
        for script in soup.find_all("script", src=True):
            src = script["src"]
            if not self._is_external(src, scan_host):
                continue
            if self._is_dynamic(src):
                continue
            has_external_scripts = True
            if not script.get("integrity"):
                missing_scripts.append(src)
                all_have_sri = False

        if missing_scripts:
            # CSP + SRI relationship:
            # - No CSP + No SRI → WARNING (CDN compromise not protected)
            # - Strong CSP + No SRI → INFO (CSP is primary protection, SRI is bonus)
            if has_strong_csp:
                severity = Severity.INFO
                desc = (
                    f"Externí JavaScript ({len(missing_scripts)}×) nemá integrity atribut. "
                    "CSP s nonce/strict-dynamic poskytuje hlavní ochranu proti XSS, ale SRI by přidal druhou vrstvu — "
                    "při kompromitaci CDN prohlížeč odmítne spustit změněný soubor."
                )
            else:
                severity = Severity.WARNING
                desc = (
                    f"Externí JavaScript ({len(missing_scripts)}×) nemá integrity atribut a web nemá silné CSP. "
                    "Bez obou ochran může útočník napadnout CDN a vložit malware do každé stránky. "
                    "Přidejte SRI hash nebo CSP s nonce/strict-dynamic."
                )

            findings.append(Finding(
                id="missing-sri-script",
                title=f"Externí scripty bez Subresource Integrity ({len(missing_scripts)}×)",
                description=desc,
                severity=severity,
                category="sri",
                fix_url="/guide/#sri-integrita",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                detail="\n".join(missing_scripts[:5]) + (f"\n… a {len(missing_scripts) - 5} dalších" if len(missing_scripts) > 5 else ""),
            ))
        elif has_external_scripts and all_have_sri:
            if has_strong_csp:
                findings.append(Finding(
                    id="sri-csp-ok",
                    title="CSP s nonce + SRI na externích scriptech",
                    description="Web má silné CSP (nonce/strict-dynamic) i SRI na externích scriptech — dvouvrstvá ochrana proti XSS i kompromitaci CDN.",
                    severity=Severity.OK,
                    category="sri",
                ))
            else:
                findings.append(Finding(
                    id="sri-ok",
                    title="SRI na externích scriptech",
                    description="Externí scripty mají integrity atribut — prohlížeč odmítne spustit změněný soubor.",
                    severity=Severity.OK,
                    category="sri",
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
                fix_url="/guide/#sri-integrita",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                detail="\n".join(missing_styles[:5]) + (f"\n… a {len(missing_styles) - 5} dalších" if len(missing_styles) > 5 else ""),
            ))

        return findings

    @staticmethod
    def _has_strong_csp(response) -> bool:
        """Check if response has CSP with nonce or strict-dynamic (strong XSS protection)."""
        csp = ""
        for header in ("content-security-policy", "content-security-policy-report-only"):
            val = response.headers.get(header, "")
            if val:
                csp = val.lower()
                break
        if not csp:
            return False
        return "'nonce-" in csp or "'strict-dynamic'" in csp

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

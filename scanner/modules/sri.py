from urllib.parse import urlparse
from bs4 import BeautifulSoup
from .base import BaseScanModule, Finding, Severity, guide_url

# Dynamic CDNs where SRI cannot be applied (content changes per config/request)
DYNAMIC_HOSTS = {
    # Tag managers & analytics
    "www.googletagmanager.com",
    "googletagmanager.com",
    "www.google-analytics.com",
    "google-analytics.com",
    "assets.adobedtm.com",  # Adobe DTM / Launch
    "cdn.segment.com",
    "static.hotjar.com",
    "cdn.heapanalytics.com",
    "static.cloudflareinsights.com",
    "cdn.matomo.cloud",
    # Social / marketing
    "connect.facebook.net",
    "platform.twitter.com",
    "platform.x.com",
    "snap.licdn.com",
    "sc-static.net",
    "analytics.tiktok.com",
    "bat.bing.com",
    "mc.yandex.ru",
    # Widgets & payments
    "widget.intercom.io",
    "js.stripe.com",
    "js.hsforms.net",  # HubSpot
    "js.hs-scripts.com",
    "js.hs-analytics.net",
    # reCAPTCHA — Google host but specific dynamic endpoint
    "www.google.com",
    "www.gstatic.com",
    # Fonts
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
                fix_url=guide_url("sri-integrita"),
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
                fix_url=guide_url("sri-integrita"),
                doc_url="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                detail="\n".join(missing_styles[:5]) + (f"\n… a {len(missing_styles) - 5} dalších" if len(missing_styles) > 5 else ""),
            ))

        return findings

    @staticmethod
    def _has_strong_csp(response) -> bool:
        """CSP poskytuje silnou XSS ochranu (nonce, strict-dynamic, nebo hash)."""
        csp = ""
        for header in ("content-security-policy", "content-security-policy-report-only"):
            val = response.headers.get(header, "")
            if val:
                csp = val.lower()
                break
        if not csp:
            return False
        return (
            "'nonce-" in csp
            or "'strict-dynamic'" in csp
            or "'sha256-" in csp
            or "'sha384-" in csp
            or "'sha512-" in csp
        )

    @staticmethod
    def _registrable_domain(host: str) -> str:
        """
        Heuristika pro "same-org" detekci bez závislosti na PSL.
        Pro běžné TLDs vrací poslední 2 části (example.com),
        pro známé dvojdílné TLDs poslední 3 části (example.co.uk).
        """
        if not host:
            return ""
        parts = host.lower().rstrip(".").split(".")
        if len(parts) < 2:
            return host.lower()
        two_part_tlds = {
            "co.uk", "co.cz", "com.br", "com.au", "co.jp",
            "org.uk", "net.au", "co.nz", "co.za", "co.in",
            "ac.uk", "gov.uk",
        }
        last_two = ".".join(parts[-2:])
        if last_two in two_part_tlds and len(parts) >= 3:
            return ".".join(parts[-3:])
        return last_two

    @classmethod
    def _is_external(cls, src: str, scan_host: str) -> bool:
        """External = jiná organizace.

        Považujeme za same-org:
        - shodná registrable doména (např. www.mozilla.org pro mozilla.org)
        - same-org asset domain (např. github.githubassets.com pro github.com)
        """
        if not src.startswith(("http://", "https://")):
            return False
        src_host = urlparse(src).hostname
        if not src_host:
            return False
        if cls._registrable_domain(src_host) == cls._registrable_domain(scan_host):
            return False
        if cls._is_same_org_asset_host(src_host, scan_host):
            return False
        return True

    @classmethod
    def _is_same_org_asset_host(cls, src_host: str, scan_host: str) -> bool:
        """GitHub-style asset domain: github.com → *.githubassets.com.

        Pravidlo: src registrable SLD začíná scan SLD a končí známým
        asset suffixem (assets, cdn, static, …).
        """
        scan_reg = cls._registrable_domain(scan_host)
        src_reg = cls._registrable_domain(src_host)
        scan_sld = scan_reg.split(".", 1)[0]
        src_sld = src_reg.split(".", 1)[0]
        if len(scan_sld) < 4 or not src_sld.startswith(scan_sld):
            return False
        suffix = src_sld[len(scan_sld):]
        return suffix in {
            "assets", "cdn", "static", "media", "files",
            "usercontent", "content", "img", "images",
        }

    @staticmethod
    def _is_dynamic(src: str) -> bool:
        """Return True if src points to a dynamic CDN where SRI cannot be applied."""
        host = urlparse(src).hostname
        return host in DYNAMIC_HOSTS if host else False

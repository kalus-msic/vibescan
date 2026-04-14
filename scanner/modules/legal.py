import re
from bs4 import BeautifulSoup
from .base import BaseScanModule, Finding, Severity


CONSENT_SCRIPT_PATTERNS = (
    "cookieconsent", "cookiebot", "onetrust", "klaro",
    "tarteaucitron", "cookie-notice", "cookie-script",
    "complianz", "iubenda", "quantcast",
)

CONSENT_ELEMENT_IDS = {
    "cookie-banner", "cookie-consent", "cookie-notice", "cookie-bar",
    "cookieconsent", "onetrust-consent-sdk", "onetrust-banner-sdk",
    "CybotCookiebotDialog", "klaro", "tarteaucitron",
}

CONSENT_ELEMENT_CLASSES = {
    "cc-window", "cc-banner", "cookie-banner", "cookie-consent",
    "cookie-notice", "cookie-bar", "cookieconsent",
}

PRIVACY_HREF_PATTERNS = re.compile(
    r"/(gdpr|privacy|ochrana-osobnich-udaju|zasady-ochrany|osobni-udaje|"
    r"datenschutz|privacy-policy|ochrana-udaju|ochrana-soukromi)",
    re.IGNORECASE,
)

PRIVACY_TEXT_PATTERNS = re.compile(
    r"(ochrana osobních údajů|zásady ochrany|privacy policy|"
    r"osobní údaje|gdpr|datenschutz|ochrana soukromí)",
    re.IGNORECASE,
)

COPYRIGHT_PATTERN = re.compile(r"(©|&copy;|\bcopyright\b|\(c\)\s*\d{4})", re.IGNORECASE)


class LegalScanner(BaseScanModule):
    name = "legal"
    step_label = "Právní náležitosti"

    def run(self, url: str, response=None) -> list[Finding]:
        if not response:
            return []

        html = response.text or ""
        soup = BeautifulSoup(html, "html.parser")
        findings = []

        findings.append(self._check_cookie_consent(soup, html))
        findings.append(self._check_privacy_link(soup))
        findings.append(self._check_copyright(soup, html))

        return findings

    def _check_cookie_consent(self, soup: BeautifulSoup, html: str) -> Finding:
        for script in soup.find_all("script", src=True):
            src = script["src"].lower()
            if any(pattern in src for pattern in CONSENT_SCRIPT_PATTERNS):
                return Finding(
                    id="cookie-consent-ok",
                    title="Cookie consent mechanismus nalezen",
                    description="Stránka obsahuje knihovnu pro správu souhlasu s cookies.",
                    severity=Severity.OK,
                    category="legal",
                )

        for element_id in CONSENT_ELEMENT_IDS:
            if soup.find(id=element_id):
                return Finding(
                    id="cookie-consent-ok",
                    title="Cookie consent mechanismus nalezen",
                    description="Stránka obsahuje element pro správu souhlasu s cookies.",
                    severity=Severity.OK,
                    category="legal",
                )

        for element in soup.find_all(class_=True):
            classes = set(element.get("class", []))
            if classes & CONSENT_ELEMENT_CLASSES:
                return Finding(
                    id="cookie-consent-ok",
                    title="Cookie consent mechanismus nalezen",
                    description="Stránka obsahuje element pro správu souhlasu s cookies.",
                    severity=Severity.OK,
                    category="legal",
                )

        return Finding(
            id="missing-cookie-consent",
            title="Nenašli jsme mechanismus pro souhlas s cookies",
            description="Nenašli jsme cookie consent lištu ani známou consent knihovnu. Podle GDPR musí web zobrazit souhlas s cookies před jejich uložením. Tlačítka pro přijetí a odmítnutí musí mít stejnou vizuální váhu. Ověřte, zda se tento prvek nachází na jiné stránce vašeho webu.",
            severity=Severity.INFO,
            category="legal",
            fix_url="/guide/#pravni-dokumenty",
            doc_url="https://gdpr.eu/cookies/",
        )

    def _check_privacy_link(self, soup: BeautifulSoup) -> Finding:
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if PRIVACY_HREF_PATTERNS.search(href):
                return Finding(
                    id="privacy-link-ok",
                    title="Odkaz na ochranu osobních údajů nalezen",
                    description="Stránka obsahuje odkaz na informace o ochraně osobních údajů.",
                    severity=Severity.OK,
                    category="legal",
                )

            text = a.get_text(strip=True)
            if PRIVACY_TEXT_PATTERNS.search(text):
                return Finding(
                    id="privacy-link-ok",
                    title="Odkaz na ochranu osobních údajů nalezen",
                    description="Stránka obsahuje odkaz na informace o ochraně osobních údajů.",
                    severity=Severity.OK,
                    category="legal",
                )

        return Finding(
            id="missing-privacy-link",
            title="Nenašli jsme odkaz na ochranu osobních údajů",
            description="Nenašli jsme odkaz na stránku s informacemi o ochraně osobních údajů (GDPR). Každý web musí mít dostupnou stránku popisující práva návštěvníků ohledně jejich dat. Ověřte, zda se tento odkaz nachází na jiné stránce vašeho webu.",
            severity=Severity.INFO,
            category="legal",
            fix_url="/guide/#pravni-dokumenty",
            doc_url="https://www.uoou.cz/",
        )

    def _check_copyright(self, soup: BeautifulSoup, html: str) -> Finding:
        footer = soup.find("footer")
        search_text = footer.get_text() if footer else html

        if COPYRIGHT_PATTERN.search(search_text):
            return Finding(
                id="copyright-ok",
                title="Copyright informace nalezeny",
                description="Stránka obsahuje označení autorských práv.",
                severity=Severity.OK,
                category="legal",
            )

        return Finding(
            id="missing-copyright",
            title="Nenašli jsme copyright informace",
            description="Nenašli jsme označení autorských práv (© rok a název provozovatele) v patičce webu. Ověřte, zda se tato informace nachází na jiné stránce vašeho webu.",
            severity=Severity.INFO,
            category="legal",
            fix_url="/guide/#pravni-dokumenty",
            doc_url="https://www.zakonyprolidi.cz/cs/2000-121",
        )

import re
from bs4 import BeautifulSoup
from .base import BaseScanModule, Finding, Severity


KNOWN_SKIP_HREFS = {"#main", "#content", "#main-content"}

SKIP_LINK_CLASSES = {
    "sr-only", "skip-link", "skip-nav", "skip-to-content",
    "visually-hidden", "screen-reader-text",
}

SKIP_TEXT_PATTERNS = re.compile(
    r"(přeskočit|skip to|skip navigation|zum inhalt)",
    re.IGNORECASE,
)

ACCESSIBILITY_STATEMENT_HREFS = re.compile(
    r"/(prohlaseni-o-pristupnosti|accessibility-statement|accessibility|pristupnost|barrierefreiheit)",
    re.IGNORECASE,
)

ACCESSIBILITY_STATEMENT_TEXTS = re.compile(
    r"(prohlášení o přístupnosti|accessibility statement|přístupnost webu|barrierefreiheit)",
    re.IGNORECASE,
)


class AccessibilityScanner(BaseScanModule):
    name = "accessibility"
    step_label = "Přístupnost"

    def run(self, url: str, response=None) -> list[Finding]:
        if not response:
            return []

        html = response.text or ""
        soup = BeautifulSoup(html, "html.parser")
        findings = []

        if self._has_skip_link(soup):
            findings.append(Finding(
                id="skip-link-ok",
                title="Odkaz pro přeskočení navigace nalezen",
                description="Stránka obsahuje skip link, který umožňuje uživatelům klávesnice a hlasových čteček přeskočit opakující se navigaci.",
                severity=Severity.OK,
                category="accessibility",
                doc_url="https://pristupne-stranky.cz/zakon-a-standardy/",
            ))
        else:
            findings.append(Finding(
                id="missing-skip-link",
                title="Nenašli jsme odkaz pro přeskočení navigace",
                description="Odkaz pro přeskočení navigace (skip link) umožňuje uživatelům klávesnice a hlasových čteček přeskočit opakující se menu a přejít přímo na hlavní obsah. Je to základní požadavek přístupnosti (WCAG 2.4.1). Ověřte, zda váš web tento prvek obsahuje.",
                severity=Severity.INFO,
                category="accessibility",
                fix_url="/guide/#pravni-dokumenty",
                doc_url="https://pristupne-stranky.cz/zakon-a-standardy/",
            ))

        if self._has_accessibility_statement(soup):
            findings.append(Finding(
                id="accessibility-statement-ok",
                title="Prohlášení o přístupnosti nalezeno",
                description="Stránka obsahuje odkaz na prohlášení o přístupnosti.",
                severity=Severity.OK,
                category="accessibility",
                doc_url="https://pristupne-stranky.cz/zakon-a-standardy/",
            ))
        else:
            findings.append(Finding(
                id="missing-accessibility-statement",
                title="Nenašli jsme prohlášení o přístupnosti",
                description="Nenašli jsme odkaz na prohlášení o přístupnosti webu. Veřejnoprávní subjekty jsou povinny toto prohlášení zveřejnit ze zákona (zákon č. 99/2019 Sb.). Pro komerční weby je to doporučená praxe. Ověřte, zda se tento odkaz nachází na jiné stránce vašeho webu.",
                severity=Severity.INFO,
                category="accessibility",
                fix_url="/guide/#pravni-dokumenty",
                doc_url="https://pristupne-stranky.cz/zakon-a-standardy/",
            ))

        return findings

    def _has_skip_link(self, soup: BeautifulSoup) -> bool:
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if not href.startswith("#"):
                continue

            if href in KNOWN_SKIP_HREFS:
                return True

            css_classes = set(a.get("class", []))
            if css_classes & SKIP_LINK_CLASSES:
                return True

            text = a.get_text(strip=True)
            if SKIP_TEXT_PATTERNS.search(text):
                return True

        return False

    def _has_accessibility_statement(self, soup: BeautifulSoup) -> bool:
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if ACCESSIBILITY_STATEMENT_HREFS.search(href):
                return True

            text = a.get_text(strip=True)
            if ACCESSIBILITY_STATEMENT_TEXTS.search(text):
                return True

        return False

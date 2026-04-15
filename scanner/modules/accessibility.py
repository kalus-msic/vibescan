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

        # HTML lang attribute
        html_tag = soup.find("html")
        if html_tag and html_tag.get("lang"):
            findings.append(Finding(
                id="html-lang-ok",
                title="Atribut lang nalezen",
                description=f"Element <html> má nastaven jazyk: {html_tag['lang']}.",
                severity=Severity.OK,
                category="accessibility",
            ))
        else:
            findings.append(Finding(
                id="missing-html-lang",
                title="Chybí atribut lang na <html>",
                description="Element <html> nemá nastaven atribut lang. Hlasové čtečky potřebují znát jazyk stránky pro správnou výslovnost. Přidejte např. <html lang=\"cs\">.",
                severity=Severity.INFO,
                category="accessibility",
                fix_url="/guide/#pravni-dokumenty",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/lang",
            ))

        # Images without alt
        imgs_without_alt = []
        for img in soup.find_all("img"):
            if img.get("alt") is None:
                src = img.get("src", "")[:80]
                imgs_without_alt.append(src)
        if imgs_without_alt:
            findings.append(Finding(
                id="missing-img-alt",
                title=f"Obrázky bez alt atributu ({len(imgs_without_alt)}\u00d7)",
                description="Obrázky bez alt atributu jsou neviditelné pro hlasové čtečky a zhoršují SEO. Každý <img> musí mít alt \u2014 pro dekorativní obrázky použijte alt=\"\".",
                severity=Severity.INFO,
                category="accessibility",
                fix_url="/guide/#pravni-dokumenty",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTML/Element/img#alt",
                detail=", ".join(imgs_without_alt[:5]),
            ))
        elif soup.find_all("img"):
            findings.append(Finding(
                id="img-alt-ok",
                title="Obrázky mají alt atributy",
                description="Všechny obrázky na stránce mají nastaven alt atribut.",
                severity=Severity.OK,
                category="accessibility",
            ))

        # Form inputs without labels
        inputs_without_label = []
        for inp in soup.find_all(["input", "select", "textarea"]):
            if inp.get("type") in ("hidden", "submit", "button", "reset", "image"):
                continue
            inp_id = inp.get("id")
            has_label = False
            if inp_id and soup.find("label", attrs={"for": inp_id}):
                has_label = True
            if inp.find_parent("label"):
                has_label = True
            if inp.get("aria-label") or inp.get("aria-labelledby"):
                has_label = True
            if not has_label:
                name = inp.get("name", inp.get("id", inp.name))
                inputs_without_label.append(name)
        if inputs_without_label:
            findings.append(Finding(
                id="missing-form-labels",
                title=f"Formul\u00e1\u0159ov\u00e9 prvky bez label ({len(inputs_without_label)}\u00d7)",
                description="Formul\u00e1\u0159ov\u00e9 prvky nemaj\u00ed p\u0159i\u0159azen\u00fd <label>, aria-label ani aria-labelledby. Hlasov\u00e9 \u010dte\u010dky nedok\u00e1\u017e\u00ed u\u017eivateli sd\u011blit, co m\u00e1 do pole zadat.",
                severity=Severity.INFO,
                category="accessibility",
                fix_url="/guide/#pravni-dokumenty",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTML/Element/label",
                detail=", ".join(inputs_without_label[:5]),
            ))

        # Empty links and buttons
        # Note: no OK finding here — absence of empty elements is expected, not noteworthy
        empty_interactive = []
        for el in soup.find_all(["a", "button"]):
            text = el.get_text(strip=True)
            if not text and not el.get("aria-label") and not el.get("aria-labelledby") and not el.get("title"):
                if el.find("img", alt=True):
                    continue
                if el.find("svg"):
                    has_sr = el.find(class_=re.compile(r"sr-only"))
                    if has_sr:
                        continue
                tag = el.name
                identifier = el.get("href", el.get("id", ""))[:60]
                empty_interactive.append(f"<{tag}> {identifier}")
        if empty_interactive:
            findings.append(Finding(
                id="empty-interactive",
                title=f"Pr\u00e1zdn\u00e9 odkazy nebo tla\u010d\u00edtka ({len(empty_interactive)}\u00d7)",
                description="Odkazy nebo tla\u010d\u00edtka nemaj\u00ed \u017e\u00e1dn\u00fd text, aria-label ani title. Hlasov\u00e9 \u010dte\u010dky je ozna\u010d\u00ed jako \u201eodkaz\u201c nebo \u201etla\u010d\u00edtko\u201c bez dal\u0161\u00edho kontextu.",
                severity=Severity.INFO,
                category="accessibility",
                fix_url="/guide/#pravni-dokumenty",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a#accessibility",
                detail=", ".join(empty_interactive[:5]),
            ))

        # Heading hierarchy
        headings = []
        for h in soup.find_all(re.compile(r"^h[1-6]$")):
            headings.append(int(h.name[1]))
        skipped = []
        for i in range(1, len(headings)):
            if headings[i] > headings[i - 1] + 1:
                skipped.append(f"h{headings[i-1]} \u2192 h{headings[i]}")
        if skipped:
            findings.append(Finding(
                id="heading-hierarchy",
                title=f"P\u0159esko\u010den\u00e9 \u00farovn\u011b nadpis\u016f ({len(skipped)}\u00d7)",
                description="Nadpisy p\u0159eskakuj\u00ed \u00farovn\u011b (nap\u0159. z h1 na h3). Spr\u00e1vn\u00e1 hierarchie nadpis\u016f pom\u00e1h\u00e1 hlasov\u00fdm \u010dte\u010dk\u00e1m a zlep\u0161uje SEO.",
                severity=Severity.INFO,
                category="accessibility",
                fix_url="/guide/#pravni-dokumenty",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTML/Element/Heading_Elements",
                detail=", ".join(skipped[:5]),
            ))
        elif headings:
            findings.append(Finding(
                id="heading-hierarchy-ok",
                title="Hierarchie nadpis\u016f je spr\u00e1vn\u00e1",
                description="Nadpisy na str\u00e1nce dodr\u017euj\u00ed spr\u00e1vnou hierarchii bez p\u0159esko\u010den\u00fdch \u00farovn\u00ed.",
                severity=Severity.OK,
                category="accessibility",
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

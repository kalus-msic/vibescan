import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from .base import BaseScanModule, Finding, Severity


class SEOScanner(BaseScanModule):
    name = "seo"
    step_label = "SEO z\u00e1klady"

    def run(self, url: str, response=None) -> list[Finding]:
        if not response:
            return []

        html = response.text or ""
        soup = BeautifulSoup(html, "html.parser")
        findings = []

        findings.append(self._check_title(soup))
        findings.append(self._check_meta_description(soup))
        findings.append(self._check_canonical(soup, url))
        findings.append(self._check_og_tags(soup))
        findings.append(self._check_h1(soup))

        return findings

    def _check_title(self, soup: BeautifulSoup) -> Finding:
        title = soup.find("title")
        if not title or not title.get_text(strip=True):
            return Finding(
                id="missing-title",
                title="Chyb\u00ed element <title>",
                description="Str\u00e1nka nem\u00e1 nastaven\u00fd <title>. Titulek je z\u00e1kladn\u00ed SEO element \u2014 zobrazuje se ve v\u00fdsledc\u00edch vyhled\u00e1v\u00e1n\u00ed a v z\u00e1lo\u017ek\u00e1ch prohl\u00ed\u017ee\u010de.",
                severity=Severity.WARNING,
                category="seo",
                fix_url="/guide/#seo-zaklady",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTML/Element/title",
            )
        text = title.get_text(strip=True)
        length = len(text)
        if length > 60:
            return Finding(
                id="title-too-long",
                title=f"Titulek je p\u0159\u00edli\u0161 dlouh\u00fd ({length} znak\u016f)",
                description="Doporu\u010den\u00e1 d\u00e9lka titulku je 50\u201360 znak\u016f. Del\u0161\u00ed titulek se ve v\u00fdsledc\u00edch vyhled\u00e1v\u00e1n\u00ed o\u0159\u00edzne.",
                severity=Severity.INFO,
                category="seo",
                fix_url="/guide/#seo-zaklady",
                detail=text[:80],
            )
        return Finding(
            id="title-ok",
            title="Titulek str\u00e1nky nastaven",
            description=f"Str\u00e1nka m\u00e1 titulek ({length} znak\u016f).",
            severity=Severity.OK,
            category="seo",
            detail=text[:80],
        )

    def _check_meta_description(self, soup: BeautifulSoup) -> Finding:
        meta = soup.find("meta", attrs={"name": re.compile(r"^description$", re.IGNORECASE)})
        if not meta or not meta.get("content", "").strip():
            return Finding(
                id="missing-meta-description",
                title="Chyb\u00ed meta description",
                description="Str\u00e1nka nem\u00e1 meta description. Vyhled\u00e1va\u010de ho zobrazuj\u00ed jako popisek ve v\u00fdsledc\u00edch \u2014 bez n\u011bj si Google vybere vlastn\u00ed text ze str\u00e1nky.",
                severity=Severity.WARNING,
                category="seo",
                fix_url="/guide/#seo-zaklady",
                doc_url="https://developer.mozilla.org/en-US/docs/Learn/HTML/Introduction_to_HTML/The_head_metadata_in_HTML#adding_an_author_and_description",
            )
        content = meta["content"].strip()
        length = len(content)
        if length > 160:
            return Finding(
                id="meta-description-too-long",
                title=f"Meta description je p\u0159\u00edli\u0161 dlouh\u00fd ({length} znak\u016f)",
                description="Doporu\u010den\u00e1 d\u00e9lka meta description je 120\u2013160 znak\u016f. Del\u0161\u00ed text se o\u0159\u00edzne.",
                severity=Severity.INFO,
                category="seo",
                fix_url="/guide/#seo-zaklady",
                detail=content[:180],
            )
        return Finding(
            id="meta-description-ok",
            title="Meta description nastaven",
            description=f"Str\u00e1nka m\u00e1 meta description ({length} znak\u016f).",
            severity=Severity.OK,
            category="seo",
            detail=content[:160],
        )

    def _check_canonical(self, soup: BeautifulSoup, url: str) -> Finding:
        link = soup.find("link", rel="canonical")
        if not link or not link.get("href", "").strip():
            return Finding(
                id="missing-canonical",
                title="Chyb\u00ed canonical URL",
                description="Str\u00e1nka nem\u00e1 <link rel=\"canonical\">. Canonical URL \u0159\u00edk\u00e1 vyhled\u00e1va\u010d\u016fm, kter\u00e1 verze str\u00e1nky je hlavn\u00ed \u2014 p\u0159edch\u00e1z\u00ed probl\u00e9m\u016fm s duplicitn\u00edm obsahem.",
                severity=Severity.INFO,
                category="seo",
                fix_url="/guide/#seo-zaklady",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/rel#canonical",
            )
        return Finding(
            id="canonical-ok",
            title="Canonical URL nastavena",
            description="Str\u00e1nka m\u00e1 nastavenou canonical URL.",
            severity=Severity.OK,
            category="seo",
            detail=link["href"][:100],
        )

    def _check_og_tags(self, soup: BeautifulSoup) -> Finding:
        og_title = soup.find("meta", property="og:title")
        og_desc = soup.find("meta", property="og:description")
        missing = []
        if not og_title or not og_title.get("content", "").strip():
            missing.append("og:title")
        if not og_desc or not og_desc.get("content", "").strip():
            missing.append("og:description")
        if missing:
            return Finding(
                id="missing-og-tags",
                title=f"Chyb\u00ed Open Graph tagy ({', '.join(missing)})",
                description="Open Graph tagy ur\u010duj\u00ed, jak str\u00e1nka vypad\u00e1 p\u0159i sd\u00edlen\u00ed na soci\u00e1ln\u00edch s\u00edt\u00edch (Facebook, LinkedIn, Slack). Bez nich se zobraz\u00ed genericky.",
                severity=Severity.INFO,
                category="seo",
                fix_url="/guide/#seo-zaklady",
                doc_url="https://ogp.me/",
                detail=", ".join(missing),
            )
        return Finding(
            id="og-tags-ok",
            title="Open Graph tagy nastaveny",
            description="Str\u00e1nka m\u00e1 og:title a og:description pro sd\u00edlen\u00ed na soci\u00e1ln\u00edch s\u00edt\u00edch.",
            severity=Severity.OK,
            category="seo",
        )

    def _check_h1(self, soup: BeautifulSoup) -> Finding:
        h1_tags = soup.find_all("h1")
        if not h1_tags:
            return Finding(
                id="missing-h1",
                title="Chyb\u00ed nadpis <h1>",
                description="Str\u00e1nka nem\u00e1 \u017e\u00e1dn\u00fd <h1> nadpis. Ka\u017ed\u00e1 str\u00e1nka by m\u011bla m\u00edt pr\u00e1v\u011b jeden <h1>, kter\u00fd popisuje jej\u00ed hlavn\u00ed obsah.",
                severity=Severity.INFO,
                category="seo",
                fix_url="/guide/#seo-zaklady",
            )
        if len(h1_tags) > 1:
            return Finding(
                id="multiple-h1",
                title=f"V\u00edce nadpis\u016f <h1> ({len(h1_tags)}\u00d7)",
                description="Str\u00e1nka m\u00e1 v\u00edce ne\u017e jeden <h1>. Doporu\u010duje se pou\u017e\u00edt pr\u00e1v\u011b jeden <h1> na str\u00e1nku pro jasnou strukturu obsahu.",
                severity=Severity.INFO,
                category="seo",
                fix_url="/guide/#seo-zaklady",
                detail=", ".join(h.get_text(strip=True)[:50] for h in h1_tags),
            )
        return Finding(
            id="h1-ok",
            title="Nadpis <h1> nalezen",
            description="Str\u00e1nka m\u00e1 pr\u00e1v\u011b jeden <h1> nadpis.",
            severity=Severity.OK,
            category="seo",
            detail=h1_tags[0].get_text(strip=True)[:80],
        )

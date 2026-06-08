"""Lighthouse audit → Vibescan Finding mapping.

LIGHTHOUSE_AUDIT_MAP is a curated allowlist — Lighthouse emits ~150 audits,
but only a subset is worth surfacing to Vibescan users in Czech with our
severity scale.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class AuditMap:
    finding_id: str
    title: str
    description: str
    category: str  # "performance" | "accessibility" | "best-practices" | "seo"
    fix_url: str
    doc_url: str | None = None
    warn_below: float = 0.9
    crit_below: float = 0.5
    supersedes_id: str | None = None
    # Strop pro vypočtenou severity. Lighthouse skóre je binární (0/1) pro
    # mnoho audit failů, takže by jinak heading-order / aria-valid-attr-value
    # / html-lang-valid dostaly CRITICAL. Reálně je to "moderate" — best
    # practice, ne blocker. Hodnoty: "warning" | "info" | None (= bez stropu).
    max_severity: str | None = None


def _guide(slug: str) -> str:
    """Mirror of scanner.modules.base.guide_url to avoid circular import."""
    return f"/guide/{slug}/"


LIGHTHOUSE_AUDIT_MAP: dict[str, AuditMap] = {
    # ---- SEO (supersedes existing seo.py findings) ----
    "document-title": AuditMap(
        finding_id="lh-document-title",
        title="Chybí element <title>",
        description="Lighthouse nenašel <title>. Titulek se zobrazuje ve výsledcích vyhledávání a v záložkách prohlížeče.",
        category="seo",
        fix_url=_guide("seo-zaklady"),
        doc_url="https://developer.mozilla.org/en-US/docs/Web/HTML/Element/title",
        supersedes_id="missing-title",
    ),
    "meta-description": AuditMap(
        finding_id="lh-meta-description",
        title="Chybí meta description",
        description="Lighthouse nenašel meta description. Bez něj si Google vybírá popisek z obsahu stránky.",
        category="seo",
        fix_url=_guide("seo-zaklady"),
        supersedes_id="missing-meta-description",
    ),
    "canonical": AuditMap(
        finding_id="lh-canonical",
        title="Chybí canonical URL",
        description="Lighthouse nenašel platnou canonical URL. Bez ní vyhledávače mohou indexovat duplicitní verze.",
        category="seo",
        fix_url=_guide("seo-zaklady"),
        supersedes_id="missing-canonical",
    ),
    "robots-txt": AuditMap(
        finding_id="lh-robots-txt",
        title="robots.txt je neplatný",
        description="Lighthouse našel chyby v robots.txt. Vyhledávače je nemusí správně interpretovat.",
        category="seo",
        fix_url=_guide("seo-zaklady"),
    ),
    "hreflang": AuditMap(
        finding_id="lh-hreflang",
        title="Chybné hreflang atributy",
        description="Lighthouse našel chybné hreflang odkazy pro různé jazykové verze.",
        category="seo",
        fix_url=_guide("seo-zaklady"),
    ),

    # ---- Accessibility (supersedes existing accessibility.py findings) ----
    "html-has-lang": AuditMap(
        finding_id="lh-html-has-lang",
        title="Chybí atribut lang na <html>",
        description="Lighthouse: <html> nemá atribut lang. Hlasové čtečky potřebují znát jazyk pro správnou výslovnost.",
        category="accessibility",
        fix_url=_guide("pravni-dokumenty"),
        supersedes_id="missing-html-lang",
    ),
    "html-lang-valid": AuditMap(
        finding_id="lh-html-lang-valid",
        title="Neplatný BCP47 jazykový kód",
        description="Lighthouse: hodnota atributu lang není validní BCP47 (např. 'cz' místo 'cs').",
        category="accessibility",
        fix_url=_guide("pravni-dokumenty"),
        max_severity="warning",
    ),
    "image-alt": AuditMap(
        finding_id="lh-image-alt",
        title="Obrázky bez alt atributu",
        description="Lighthouse našel obrázky bez alt atributu. Nedostupné pro hlasové čtečky a zhoršují SEO.",
        category="accessibility",
        fix_url=_guide("pravni-dokumenty"),
        supersedes_id="missing-img-alt",
    ),
    "label": AuditMap(
        finding_id="lh-label",
        title="Formulářové prvky bez label",
        description="Lighthouse našel input/select/textarea bez přiřazeného <label>, aria-label ani aria-labelledby.",
        category="accessibility",
        fix_url=_guide("pravni-dokumenty"),
        supersedes_id="missing-form-labels",
    ),
    "link-name": AuditMap(
        finding_id="lh-link-name",
        title="Odkazy bez popisného textu",
        description="Lighthouse našel <a> bez textu, aria-label ani title. Hlasové čtečky je nedokážou popsat.",
        category="accessibility",
        fix_url=_guide("pravni-dokumenty"),
        supersedes_id="empty-interactive",
    ),
    "button-name": AuditMap(
        finding_id="lh-button-name",
        title="Tlačítka bez popisného textu",
        description="Lighthouse našel <button> bez textu, aria-label ani title.",
        category="accessibility",
        fix_url=_guide("pravni-dokumenty"),
    ),
    "heading-order": AuditMap(
        finding_id="lh-heading-order",
        title="Přeskočené úrovně nadpisů",
        description="Lighthouse našel nadpisy, které přeskakují úroveň (např. h1 → h3).",
        category="accessibility",
        fix_url=_guide("pravni-dokumenty"),
        supersedes_id="heading-hierarchy",
        max_severity="warning",
    ),
    "color-contrast": AuditMap(
        finding_id="lh-color-contrast",
        title="Nedostatečný kontrast textu",
        description="Lighthouse našel prvky s nedostatečným kontrastem textu vůči pozadí (WCAG 1.4.3 AA: 4.5:1 pro běžný text).",
        category="accessibility",
        fix_url=_guide("pravni-dokumenty"),
        doc_url="https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_Color/Color_contrast",
    ),
    "aria-required-attr": AuditMap(
        finding_id="lh-aria-required-attr",
        title="Chybí povinné ARIA atributy",
        description="Lighthouse: prvky s ARIA rolemi nemají požadované atributy (např. role=checkbox bez aria-checked).",
        category="accessibility",
        fix_url=_guide("pravni-dokumenty"),
    ),
    "aria-valid-attr-value": AuditMap(
        finding_id="lh-aria-valid-attr-value",
        title="Neplatné hodnoty ARIA atributů",
        description="Lighthouse: ARIA atributy mají neplatné hodnoty (např. aria-checked=\"yes\" místo \"true\").",
        category="accessibility",
        fix_url=_guide("pravni-dokumenty"),
        max_severity="warning",
    ),

    # ---- Performance (no overlap with existing modules) ----
    "largest-contentful-paint": AuditMap(
        finding_id="lh-lcp",
        title="Largest Contentful Paint je pomalý",
        description="LCP měří, jak rychle se zobrazí největší prvek ve viewportu. Cíl ≤ 2.5 s.",
        category="performance",
        fix_url=_guide("vykon-webu"),
        doc_url="https://web.dev/lcp/",
    ),
    "cumulative-layout-shift": AuditMap(
        finding_id="lh-cls",
        title="Vysoký Cumulative Layout Shift",
        description="CLS měří, jak moc se prvky během načítání posunují. Cíl ≤ 0.1.",
        category="performance",
        fix_url=_guide("vykon-webu"),
        doc_url="https://web.dev/cls/",
    ),
    "total-blocking-time": AuditMap(
        finding_id="lh-tbt",
        title="Vysoký Total Blocking Time",
        description="TBT měří, jak dlouho je hlavní vlákno zablokované JS. Cíl ≤ 200 ms.",
        category="performance",
        fix_url=_guide("vykon-webu"),
        doc_url="https://web.dev/tbt/",
    ),
    "speed-index": AuditMap(
        finding_id="lh-speed-index",
        title="Pomalý Speed Index",
        description="Speed Index měří, jak rychle se obsah vykresluje vizuálně. Cíl ≤ 3.4 s.",
        category="performance",
        fix_url=_guide("vykon-webu"),
        doc_url="https://web.dev/speed-index/",
    ),
    "uses-text-compression": AuditMap(
        finding_id="lh-uses-text-compression",
        title="Chybí komprese textových odpovědí",
        description="Lighthouse: server neposílá textové odpovědi s gzip/brotli kompresí. Zbytečně velký přenos.",
        category="performance",
        fix_url=_guide("vykon-webu"),
    ),
    "modern-image-formats": AuditMap(
        finding_id="lh-modern-image-formats",
        title="Obrázky nejsou ve WebP/AVIF",
        description="Lighthouse navrhuje modernější formáty obrázků (WebP, AVIF) — typicky 25–50% menší velikost.",
        category="performance",
        fix_url=_guide("vykon-webu"),
    ),

    # ---- Best Practices (mostly no overlap) ----
    "is-on-https": AuditMap(
        finding_id="lh-is-on-https",
        title="Stránka není na HTTPS",
        description="Lighthouse: stránka se načítá přes HTTP nebo má mixed content.",
        category="best-practices",
        fix_url=_guide("https-a-ssl"),
    ),
    "no-vulnerable-libraries": AuditMap(
        finding_id="lh-vulnerable-libraries",
        title="Použity JS knihovny se známými zranitelnostmi",
        description="Lighthouse: stránka načítá JS knihovny se známými CVE.",
        category="best-practices",
        fix_url=_guide("zastarale-knihovny"),
        doc_url="https://snyk.io/advisor/",
    ),
    "csp-xss": AuditMap(
        finding_id="lh-csp-xss",
        title="Slabá Content Security Policy",
        description="Lighthouse: CSP neposkytuje účinnou ochranu proti XSS.",
        category="best-practices",
        fix_url=_guide("csp-headers"),
    ),
    "errors-in-console": AuditMap(
        finding_id="lh-console-errors",
        title="Chyby v konzoli prohlížeče",
        description="Lighthouse: stránka generuje JS chyby v konzoli.",
        category="best-practices",
        fix_url=_guide("html-validace"),
    ),
    "geolocation-on-start": AuditMap(
        finding_id="lh-geolocation-on-start",
        title="Geolokace se vyžaduje při načtení",
        description="Lighthouse: stránka žádá o polohu hned při načtení — neetické.",
        category="best-practices",
        fix_url=_guide("html-validace"),
    ),
}

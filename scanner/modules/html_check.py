import re
from bs4 import BeautifulSoup
from .base import BaseScanModule, Finding, Severity


class HTMLScanner(BaseScanModule):
    name = "html"
    step_label = "HTML analýza & JS soubory"

    def run(self, url: str, response=None) -> list[Finding]:
        findings = []
        if not response:
            return findings

        html = response.text or ""
        soup = BeautifulSoup(html, "html.parser")

        # target="_blank" bez rel="noopener"
        bad_links = []
        for tag in soup.find_all("a", target="_blank"):
            rel = tag.get("rel", [])
            if isinstance(rel, str):
                rel = rel.split()
            if "noopener" not in rel:
                bad_links.append(tag.get("href", ""))

        if bad_links:
            findings.append(Finding(
                id="missing-noopener",
                title=f'target="_blank" bez rel="noopener" ({len(bad_links)}×)',
                description='Odkaz s target="_blank" bez rel="noopener" umožňuje otevřené stránce přistoupit k window.opener. Útočník může přesměrovat původní záložku na phishing stránku (reverse tabnabbing).',
                severity=Severity.WARNING,
                category="html",
                fix_url="/guide/#html-bezpecnost",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/rel/noopener",
                detail=", ".join(bad_links[:3]),
            ))

        # HTML komentáře s citlivými klíčovými slovy
        comments = soup.find_all(string=lambda t: isinstance(t, str) and "<!--" not in t
                                 and t.__class__.__name__ == "Comment")
        sensitive_patterns = re.compile(
            r"(todo|fixme|hack|password|secret|api.?key|token|debug|remove)", re.IGNORECASE
        )
        flagged_comments = [str(c)[:100] for c in comments if sensitive_patterns.search(str(c))]
        if flagged_comments:
            findings.append(Finding(
                id="html-comments",
                title=f"Citlivé HTML komentáře ({len(flagged_comments)}×)",
                description="HTML komentáře obsahují klíčová slova jako TODO, password nebo api_key. Komentáře jsou viditelné v zdrojovém kódu stránky — mohou prozradit interní informace, testovací účty nebo zapomenuté API klíče.",
                severity=Severity.WARNING,
                category="html",
                fix_url="/guide/#html-bezpecnost",
                detail=flagged_comments[0],
            ))

        return findings

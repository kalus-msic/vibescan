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

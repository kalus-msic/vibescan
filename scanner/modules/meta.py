import re
from bs4 import BeautifulSoup
from .base import BaseScanModule, Finding, Severity


VERSION_PATTERN = re.compile(r"[\d]+(?:\.[\d]+)+")


class MetaTagScanner(BaseScanModule):
    name = "meta"
    step_label = "Meta tag analýza"

    def run(self, url: str, response=None) -> list[Finding]:
        if not response:
            return []

        html = response.text or ""
        soup = BeautifulSoup(html, "html.parser")
        findings = []

        generator = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.IGNORECASE)})
        if not generator:
            return findings

        content = generator.get("content", "").strip()
        if not content:
            return findings

        has_version = bool(VERSION_PATTERN.search(content))

        if has_version:
            findings.append(Finding(
                id="meta-generator-version",
                title="CMS verze odhalena v meta tagu",
                description=f"Meta tag generator obsahuje '{content}'. Útočník vyhledá v CVE databázi známé zranitelnosti pro tuto verzi a zneužije je automatizovaným nástrojem.",
                severity=Severity.WARNING,
                category="meta",
                doc_url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework",
                detail=content,
            ))
        else:
            findings.append(Finding(
                id="meta-generator",
                title="CMS identifikováno v meta tagu",
                description=f"Meta tag generator obsahuje '{content}'. Odhaluje použitý systém, ale bez verze.",
                severity=Severity.INFO,
                category="meta",
                detail=content,
            ))

        return findings

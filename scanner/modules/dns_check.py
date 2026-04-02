import httpx
import dns.resolver
from urllib.parse import urlparse
from .base import BaseScanModule, Finding, Severity


COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "mail", "dkim",
]


class DNSScanner(BaseScanModule):
    name = "dns"
    step_label = "DNS záznamy (SPF, DMARC, DKIM)"

    def run(self, url: str, response=None) -> list[Finding]:
        findings = []
        domain = urlparse(url).hostname or ""

        # SPF
        findings.append(self._check_spf(domain))

        # DMARC
        findings.append(self._check_dmarc(domain))

        # DKIM
        findings.append(self._check_dkim(domain))

        # security.txt
        findings.append(self._check_security_txt(url))

        return findings

    def _check_spf(self, domain: str) -> Finding:
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for rdata in answers:
                for txt in rdata.strings:
                    if txt.decode("utf-8", errors="ignore").startswith("v=spf1"):
                        return Finding(
                            id="spf-ok",
                            title="SPF záznam nalezen",
                            description="Doména má nastaven SPF záznam pro ochranu emailů.",
                            severity=Severity.OK,
                            category="dns",
                        )
        except Exception:
            pass
        return Finding(
            id="missing-spf",
            title="Chybí SPF záznam",
            description="SPF záznam chrání doménu před email spoofingem. Není nastaven.",
            severity=Severity.WARNING,
            category="dns",
        )

    def _check_dmarc(self, domain: str) -> Finding:
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                for txt in rdata.strings:
                    raw = txt.decode("utf-8", errors="ignore")
                    if raw.lower().startswith("v=dmarc1"):
                        policy = ""
                        for part in raw.split(";"):
                            part = part.strip().lower()
                            if part.startswith("p="):
                                policy = part[2:]
                        if policy == "none":
                            return Finding(
                                id="dmarc-weak",
                                title="DMARC záznam nalezen, ale politika je p=none",
                                description="DMARC existuje, ale p=none nezabraňuje zneužití domény. Doporučujeme p=quarantine nebo p=reject.",
                                severity=Severity.WARNING,
                                category="dns",
                                detail=raw,
                            )
                        return Finding(
                            id="dmarc-ok",
                            title="DMARC záznam nalezen",
                            description=f"Doména má nastaven DMARC záznam s politikou p={policy}.",
                            severity=Severity.OK,
                            category="dns",
                            detail=raw,
                        )
                    # TXT record exists at _dmarc but doesn't start with v=DMARC1
                    if "dmarc" in raw.lower():
                        return Finding(
                            id="dmarc-invalid",
                            title="DMARC záznam nalezen, ale má neplatný formát",
                            description='Záznam na _dmarc existuje, ale nezačíná "v=DMARC1". Zkontrolujte formát podle RFC 7489.',
                            severity=Severity.WARNING,
                            category="dns",
                            detail=raw,
                        )
        except Exception:
            pass
        return Finding(
            id="missing-dmarc",
            title="Chybí DMARC záznam",
            description="DMARC záznam pomáhá předcházet phishingovým útokům přes tvou doménu.",
            severity=Severity.WARNING,
            category="dns",
        )

    def _check_dkim(self, domain: str) -> Finding:
        found_selectors = []
        for selector in COMMON_DKIM_SELECTORS:
            try:
                dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                found_selectors.append(selector)
            except Exception:
                try:
                    dns.resolver.resolve(f"{selector}._domainkey.{domain}", "CNAME")
                    found_selectors.append(selector)
                except Exception:
                    pass

        if found_selectors:
            return Finding(
                id="dkim-ok",
                title=f"DKIM nalezen ({', '.join(found_selectors)})",
                description="Doména má nastaven DKIM pro ověřování emailů.",
                severity=Severity.OK,
                category="dns",
                detail=f"Nalezené selektory: {', '.join(found_selectors)}",
            )
        return Finding(
            id="dkim-not-found",
            title="DKIM nebyl nalezen (základní kontrola)",
            description="Kontrolujeme jen běžné selektory (google, selector1, default…). DKIM může být nastaven s jiným selektorem.",
            severity=Severity.INFO,
            category="dns",
        )

    def _check_security_txt(self, url: str) -> Finding:
        base = f"{urlparse(url).scheme}://{urlparse(url).hostname}"
        for path in ["/.well-known/security.txt", "/security.txt"]:
            try:
                resp = httpx.get(f"{base}{path}", timeout=5, follow_redirects=True)
                if resp.status_code == 200 and "Contact:" in resp.text:
                    return Finding(
                        id="security-txt-ok",
                        title="security.txt nalezen",
                        description="Web má security.txt podle RFC 9116.",
                        severity=Severity.OK,
                        category="dns",
                    )
            except Exception:
                pass
        return Finding(
            id="missing-security-txt",
            title="Chybí security.txt",
            description="Bezpečnostní výzkumníci nemají kam hlásit zranitelnosti (RFC 9116).",
            severity=Severity.WARNING,
            category="dns",
        )

import httpx
import dns.resolver
from urllib.parse import urlparse
from .base import BaseScanModule, Finding, Severity


COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "mail", "dkim",
]

SENSITIVE_ROBOT_PATHS = {
    "/admin", "/administrator", "/wp-admin", "/wp-login",
    "/phpmyadmin", "/pma", "/cpanel",
    "/api/internal", "/api/private", "/api/debug",
    "/backup", "/backups", "/dump", "/export",
    "/debug", "/trace", "/profiler",
    "/.env", "/.git", "/.svn",
    "/config", "/configuration",
    "/secret", "/private", "/internal",
    "/staging", "/dev", "/test",
}


def _is_subdomain(domain: str) -> bool:
    """Check if domain is a subdomain (has more than 2 parts, ignoring co.uk etc.)."""
    parts = domain.rstrip(".").split(".")
    # Simple heuristic: more than 2 parts = subdomain
    # Handles: app.example.com (True), example.com (False), example.co.uk (False)
    if len(parts) <= 2:
        return False
    # Common two-part TLDs
    two_part_tlds = {"co.uk", "co.cz", "com.br", "com.au", "co.jp", "org.uk", "net.au"}
    tld = ".".join(parts[-2:])
    if tld in two_part_tlds:
        return len(parts) > 3
    return True


class DNSScanner(BaseScanModule):
    name = "dns"
    step_label = "DNS záznamy & robots.txt"

    def run(self, url: str, response=None) -> list[Finding]:
        findings = []
        domain = urlparse(url).hostname or ""
        is_sub = _is_subdomain(domain)

        # SPF
        findings.append(self._check_spf(domain, is_sub))

        # DMARC
        findings.append(self._check_dmarc(domain, is_sub))

        # DKIM
        findings.append(self._check_dkim(domain, is_sub))

        # security.txt
        findings.append(self._check_security_txt(url))

        caa = self._check_caa(domain)
        if caa:
            findings.append(caa)

        dnssec = self._check_dnssec(domain)
        if dnssec:
            findings.append(dnssec)

        robots = self._check_robots_txt(url)
        if robots:
            findings.append(robots)

        return findings

    def _check_spf(self, domain: str, is_sub: bool = False) -> Finding:
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
        sub_note = " SPF se obvykle nastavuje na root doméně." if is_sub else ""
        return Finding(
            id="missing-spf",
            title="Chybí SPF záznam",
            description=f"SPF záznam chrání doménu před email spoofingem. Není nastaven.{sub_note}",
            severity=Severity.INFO if is_sub else Severity.WARNING,
            category="dns",
        )

    def _check_dmarc(self, domain: str, is_sub: bool = False) -> Finding:
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
                                severity=Severity.INFO if is_sub else Severity.WARNING,
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
                    if "dmarc" in raw.lower():
                        return Finding(
                            id="dmarc-invalid",
                            title="DMARC záznam nalezen, ale má neplatný formát",
                            description='Záznam na _dmarc existuje, ale nezačíná "v=DMARC1". Zkontrolujte formát podle RFC 7489.',
                            severity=Severity.INFO if is_sub else Severity.WARNING,
                            category="dns",
                            detail=raw,
                        )
        except Exception:
            pass
        sub_note = " DMARC se obvykle nastavuje na root doméně." if is_sub else ""
        return Finding(
            id="missing-dmarc",
            title="Chybí DMARC záznam",
            description=f"DMARC záznam pomáhá předcházet phishingovým útokům přes tvou doménu.{sub_note}",
            severity=Severity.INFO if is_sub else Severity.WARNING,
            category="dns",
        )

    def _check_dkim(self, domain: str, is_sub: bool = False) -> Finding:
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

    def _check_caa(self, domain: str):
        """Check CAA DNS records — which CAs can issue certificates."""
        try:
            answers = dns.resolver.resolve(domain, "CAA")
            issuers = []
            for rdata in answers:
                if hasattr(rdata, "value"):
                    issuers.append(str(rdata.value))
            return Finding(
                id="caa-ok",
                title="CAA záznam nalezen",
                description="Doména má CAA záznamy, které omezují kdo může vydat SSL certifikát.",
                severity=Severity.OK,
                category="dns",
                detail=", ".join(issuers) if issuers else None,
            )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return Finding(
                id="missing-caa",
                title="Chybí CAA DNS záznam",
                description="CAA záznam omezuje, které certifikační autority mohou vydat certifikát pro doménu. Bez CAA může certifikát vydat jakákoliv CA.",
                severity=Severity.INFO,
                category="dns",
            )
        except Exception:
            return None

    def _check_dnssec(self, domain: str):
        """Check if DNSSEC is active by looking for DNSKEY records."""
        try:
            dns.resolver.resolve(domain, "DNSKEY")
            return Finding(
                id="dnssec-ok",
                title="DNSSEC je aktivní",
                description="Doména má aktivní DNSSEC, který chrání DNS záznamy před podvržením.",
                severity=Severity.OK,
                category="dns",
            )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return Finding(
                id="missing-dnssec",
                title="DNSSEC není aktivní",
                description="DNSSEC chrání DNS záznamy před manipulací. Doporučujeme aktivovat, zejména pro .cz domény.",
                severity=Severity.INFO,
                category="dns",
            )
        except Exception:
            return None

    def _check_robots_txt(self, url: str):
        """Check robots.txt for sensitive paths in Disallow directives."""
        base = f"{urlparse(url).scheme}://{urlparse(url).hostname}"
        try:
            resp = httpx.get(
                f"{base}/robots.txt",
                timeout=5,
                follow_redirects=True,
                headers={"User-Agent": "Vibescan/1.0 (security audit; https://vibescan.io)"},
            )
            if resp.status_code != 200 or not resp.text.strip():
                return None
        except Exception:
            return None

        sensitive_found = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line.lower().startswith("disallow:"):
                continue
            path = line.split(":", 1)[1].strip().lower()
            if not path:
                continue
            for sensitive in SENSITIVE_ROBOT_PATHS:
                if path.startswith(sensitive.lower()):
                    sensitive_found.append(line.split(":", 1)[1].strip())
                    break

        if not sensitive_found:
            return None

        if len(sensitive_found) <= 5:
            detail = ", ".join(sensitive_found)
        else:
            detail = ", ".join(sensitive_found[:5]) + f" ... a {len(sensitive_found) - 5} dalších"

        return Finding(
            id="robots-sensitive-paths",
            title=f"robots.txt prozrazuje citlivé cesty ({len(sensitive_found)}×)",
            description="Soubor robots.txt obsahuje Disallow pravidla pro cesty, které naznačují přítomnost administrace, záloh nebo konfiguračních souborů. Útočník může tyto cesty využít.",
            severity=Severity.WARNING,
            category="dns",
            detail=detail,
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

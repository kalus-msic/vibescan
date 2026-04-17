import re
from .base import BaseScanModule, Finding, Severity


CRITICAL_PATTERNS = {
    "OpenAI API Key": r"sk-proj-[A-Za-z0-9_-]{20,}",
    "OpenAI Legacy Key": r"sk-[A-Za-z0-9]{20,}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "GitHub PAT": r"ghp_[A-Za-z0-9]{36}",
    "GitHub OAuth Token": r"gho_[A-Za-z0-9]{36}",
    "GitHub Fine-grained PAT": r"github_pat_[A-Za-z0-9_]{22,}",
    "Vercel PAT": r"vcp_[A-Za-z0-9]{24,}",
    "Vercel Integration Token": r"vci_[A-Za-z0-9]{24,}",
    "Vercel API Key": r"vck_[A-Za-z0-9]{24,}",
    "Stripe Secret Key": r"sk_live_[A-Za-z0-9]{24,}",
    "Supabase Secret Key": r"sb_secret_[A-Za-z0-9_-]{32,}",
    "Supabase PAT": r"sbp_[a-f0-9]{40}",
}

WARNING_PATTERNS = {
    "Google API Key": {
        "pattern": r"AIzaSy[A-Za-z0-9_-]{33}",
        "description": "V HTML stránky byl nalezen Google API Key (Firebase, YouTube, Maps aj.). Tyto klíče jsou často záměrně veřejné a chráněné pomocí API restrictions (HTTP referrer, IP whitelist). Ověřte, že máte nastavená omezení v Google Cloud Console.",
    },
    "Supabase Legacy JWT": {
        "pattern": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}",
        "description": "V HTML stránky byl nalezen HS256 JWT token — může jít o Supabase anon key (to je ok) nebo service_role key (kritické — plný přístup k DB). Ověřte který klíč to je.",
    },
}

GENERIC_PATTERNS = {
    "Hardcoded Secret": r"""(?:password|secret|token|apikey|api_key)\s*[=:]\s*["'][^"']{8,}["']""",
}


def _mask_value(value: str) -> str:
    """Show first 16 chars + '...' to avoid leaking full key."""
    return value[:16] + "..." if len(value) > 16 else value


class SecretLeakageScanner(BaseScanModule):
    name = "secrets"
    step_label = "Úniky API klíčů"

    def run(self, url: str, response=None) -> list[Finding]:
        if not response:
            return []

        text = response.text or ""
        findings = []
        seen = set()

        for label, pattern in CRITICAL_PATTERNS.items():
            matches = []
            for match in re.finditer(pattern, text):
                value = match.group()
                if value in seen:
                    continue
                seen.add(value)
                matches.append(_mask_value(value))
            if matches:
                count = f" ({len(matches)}×)" if len(matches) > 1 else ""
                findings.append(Finding(
                    id=f"secret-{label.lower().replace(' ', '-')}",
                    title=f"{label} nalezen v HTML{count}",
                    description=f"V HTML stránky byl nalezen {label}. Kdokoliv může otevřít zdrojový kód stránky (Ctrl+U) a klíč zkopírovat. Přesuňte na server a použijte environment variables.",
                    severity=Severity.CRITICAL,
                    category="secrets",
                    fix_url="/guide/#secrets-env",
                    doc_url="https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
                    detail="\n".join(matches[:5]) + (f"\n… a {len(matches) - 5} dalších" if len(matches) > 5 else ""),
                ))

        for label, config in WARNING_PATTERNS.items():
            matches = []
            for match in re.finditer(config["pattern"], text):
                value = match.group()
                if value in seen:
                    continue
                seen.add(value)
                matches.append(_mask_value(value))
            if matches:
                count = f" ({len(matches)}×)" if len(matches) > 1 else ""
                findings.append(Finding(
                    id=f"secret-{label.lower().replace(' ', '-')}",
                    title=f"{label} nalezen v HTML{count}",
                    description=config["description"],
                    severity=Severity.WARNING,
                    category="secrets",
                    fix_url="/guide/#secrets-env",
                    doc_url="https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
                    detail="\n".join(matches[:5]) + (f"\n… a {len(matches) - 5} dalších" if len(matches) > 5 else ""),
                ))

        generic_matches = []
        for label, pattern in GENERIC_PATTERNS.items():
            for match in re.finditer(pattern, text, re.IGNORECASE):
                value = match.group()
                if value in seen:
                    continue
                seen.add(value)
                generic_matches.append(_mask_value(value))

        if generic_matches:
            findings.append(Finding(
                id="secret-hardcoded",
                title=f"Možné hardcoded secrets v HTML ({len(generic_matches)}×)",
                description="V HTML nebo inline JS byly nalezeny řetězce typu password='...', secret='...' nebo apikey='...'. I pokud jde o testovací hodnoty, nemají být v klientském kódu.",
                severity=Severity.WARNING,
                category="secrets",
                fix_url="/guide/#secrets-env",
                doc_url="https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
                detail="\n".join(generic_matches[:5]) + (f"\n… a {len(generic_matches) - 5} dalších" if len(generic_matches) > 5 else ""),
            ))

        return findings

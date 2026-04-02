import re
from .base import BaseScanModule, Finding, Severity


CRITICAL_PATTERNS = {
    "OpenAI API Key": r"sk-proj-[A-Za-z0-9_-]{20,}",
    "OpenAI Legacy Key": r"sk-[A-Za-z0-9]{20,}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Firebase API Key": r"AIzaSy[A-Za-z0-9_-]{33}",
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
    "Supabase Legacy JWT": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}",
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
            for match in re.finditer(pattern, text):
                value = match.group()
                if value in seen:
                    continue
                seen.add(value)
                findings.append(Finding(
                    id=f"secret-{label.lower().replace(' ', '-')}",
                    title=f"{label} nalezen v HTML",
                    description=f"V HTML stránky byl nalezen {label}. Klíč musí být uložen na serveru, nikdy v klientském kódu.",
                    severity=Severity.CRITICAL,
                    category="secrets",
                    detail=_mask_value(value),
                ))

        for label, pattern in WARNING_PATTERNS.items():
            for match in re.finditer(pattern, text):
                value = match.group()
                if value in seen:
                    continue
                seen.add(value)
                findings.append(Finding(
                    id=f"secret-{label.lower().replace(' ', '-')}",
                    title=f"{label} nalezen v HTML",
                    description=f"V HTML stránky byl nalezen HS256 JWT token — může jít o Supabase klíč. Ověřte, zda nejde o service_role key.",
                    severity=Severity.WARNING,
                    category="secrets",
                    detail=_mask_value(value),
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
                description="V HTML nebo inline JS byly nalezeny řetězce, které vypadají jako hesla nebo API klíče.",
                severity=Severity.WARNING,
                category="secrets",
                detail="\n".join(generic_matches[:5]) + (f"\n… a {len(generic_matches) - 5} dalších" if len(generic_matches) > 5 else ""),
            ))

        return findings

from bs4 import BeautifulSoup
from .base import BaseScanModule, Finding, Severity


CSRF_TOKEN_NAMES = {
    "csrf", "_token", "csrfmiddlewaretoken", "authenticity_token",
    "_wpnonce", "nonce", "__requestverificationtoken", "_csrf_token", "token",
    "csrf_token", "csrftoken", "_csrf", "xsrf", "xsrf-token", "xsrf_token",
    "x-csrf-token", "x-xsrf-token", "anti-csrf-token", "anticsrf",
    "form_token", "form-token", "request_token",
}

# Naming patterns that indicate a CSRF token by their suffix/prefix.
CSRF_TOKEN_PATTERNS = ("csrf", "xsrf", "_token", "-token", "nonce")


def _looks_like_csrf_name(name: str) -> bool:
    n = (name or "").lower()
    if not n:
        return False
    if n in CSRF_TOKEN_NAMES:
        return True
    return any(p in n for p in CSRF_TOKEN_PATTERNS)


def _has_meta_csrf_token(soup: BeautifulSoup) -> bool:
    """Rails/Laravel/Django REST pattern — token v <meta>, vkládá ho JS."""
    for meta in soup.find_all("meta"):
        name = (meta.get("name") or "").lower()
        if name in ("csrf-token", "csrf_token", "_csrf", "xsrf-token", "x-csrf-token"):
            if (meta.get("content") or "").strip():
                return True
    return False


class FormScanner(BaseScanModule):
    name = "forms"
    step_label = "Formuláře & CSRF"

    def run(self, url: str, response=None) -> list[Finding]:
        if not response:
            return []

        html = response.text or ""
        soup = BeautifulSoup(html, "html.parser")
        findings = []

        page_has_meta_csrf = _has_meta_csrf_token(soup)

        # Check POST forms for CSRF tokens
        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            if method != "POST":
                continue

            hidden_inputs = form.find_all("input", attrs={"type": "hidden"})
            has_csrf = page_has_meta_csrf or any(
                _looks_like_csrf_name(inp.get("name"))
                for inp in hidden_inputs
            )

            if not has_csrf:
                action = form.get("action") or "bez action atributu"
                findings.append(Finding(
                    id="missing-csrf-token",
                    title="POST formulář bez CSRF ochrany",
                    description="Formulář odesílá POST bez CSRF tokenu. Pokud formulář provádí citlivou akci (přihlášení, změna údajů, platba), útočník může vytvořit stránku s neviditelným formulářem, který se automaticky odešle — prohlížeč přiloží cookies a akce proběhne za přihlášeného uživatele. U veřejných formulářů (newsletter, vyhledávání) je riziko minimální.",
                    severity=Severity.WARNING,
                    category="forms",
                    fix_url="/guide/#csrf-forms",
                    doc_url="https://owasp.org/www-community/attacks/csrf",
                    detail=action,
                ))

        # Check password inputs for autocomplete
        for pw_input in soup.find_all("input", attrs={"type": "password"}):
            autocomplete = (pw_input.get("autocomplete") or "").lower()
            if autocomplete not in ("off", "new-password", "current-password"):
                name = pw_input.get("name") or pw_input.get("id") or "password input"
                findings.append(Finding(
                    id="password-autocomplete",
                    title="Heslo bez autocomplete=off",
                    description="Password input nemá nastaven autocomplete atribut. Prohlížeč může nabídnout uložení hesla v nezabezpečeném kontextu.",
                    severity=Severity.INFO,
                    category="forms",
                    detail=name,
                ))

        return findings

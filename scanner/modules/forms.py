from bs4 import BeautifulSoup
from .base import BaseScanModule, Finding, Severity


CSRF_TOKEN_NAMES = {
    "csrf", "_token", "csrfmiddlewaretoken", "authenticity_token",
    "_wpnonce", "nonce", "__requestverificationtoken", "_csrf_token", "token",
}


class FormScanner(BaseScanModule):
    name = "forms"
    step_label = "Formuláře & CSRF"

    def run(self, url: str, response=None) -> list[Finding]:
        if not response:
            return []

        html = response.text or ""
        soup = BeautifulSoup(html, "html.parser")
        findings = []

        # Check POST forms for CSRF tokens
        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            if method != "POST":
                continue

            hidden_inputs = form.find_all("input", attrs={"type": "hidden"})
            has_csrf = any(
                (inp.get("name") or "").lower() in CSRF_TOKEN_NAMES
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

import re

from bs4 import BeautifulSoup
from .base import BaseScanModule, Finding, Severity, guide_url


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


# Detekce CSRF tokenu v inline JS — pokrývá:
#   var/let/const X = '...'   (declaration)
#   window.X = '...'          (global)
#   X = '...'                 (plain assignment, ČSOB pattern)
#   X: '...'                  (object property, Liferay/Adobe DTM pattern)
#   window['X'] = '...'       (bracket notation)
# Filtr na X: musí být csrf/xsrf/_token/nonce/token (čisté slovo).
_JS_ASSIGN_RE = re.compile(
    r"""(?:^|[\s;{,])
        (?:var\s+|let\s+|const\s+|window\.|self\.)?
        ([A-Za-z_][A-Za-z0-9_]*)
        \s*[:=]\s*['"][^'"]{8,}['"]""",
    re.IGNORECASE | re.VERBOSE,
)
_JS_BRACKET_RE = re.compile(
    r"""(?:window|self|globalThis)\s*\[\s*['"]([A-Za-z_][A-Za-z0-9_-]*)['"]\s*\]
        \s*=\s*['"][^'"]{8,}['"]""",
    re.IGNORECASE | re.VERBOSE,
)


def _is_csrf_identifier(ident: str) -> bool:
    n = (ident or "").lower()
    if not n:
        return False
    if n == "token":
        return True
    return any(p in n for p in CSRF_TOKEN_PATTERNS)


def _has_inline_js_csrf(soup: BeautifulSoup) -> bool:
    """Detekce CSRF token v inline <script>.

    Pokrývá ČSOB (`Token = '...'`), Liferay/AdobeDTM (`csrfToken: '...'`),
    Express/Koa (`window['_csrf'] = '...'`) a další.
    """
    for script in soup.find_all("script"):
        body = script.string
        if not body:
            continue
        for match in _JS_ASSIGN_RE.finditer(body):
            if _is_csrf_identifier(match.group(1)):
                return True
        for match in _JS_BRACKET_RE.finditer(body):
            if _is_csrf_identifier(match.group(1)):
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

        page_has_csrf_signal = _has_meta_csrf_token(soup) or _has_inline_js_csrf(soup)

        # Check POST forms for CSRF tokens — agregujeme do jednoho findingu.
        unprotected_actions = []
        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            if method != "POST":
                continue

            hidden_inputs = form.find_all("input", attrs={"type": "hidden"})
            has_csrf = page_has_csrf_signal or any(
                _looks_like_csrf_name(inp.get("name"))
                for inp in hidden_inputs
            )

            if not has_csrf:
                action = form.get("action") or "bez action atributu"
                unprotected_actions.append(action)

        if unprotected_actions:
            count = len(unprotected_actions)
            unique_actions = list(dict.fromkeys(unprotected_actions))  # preserve order, dedupe
            detail = ", ".join(unique_actions[:5]) + (
                f" … a {len(unique_actions) - 5} dalších" if len(unique_actions) > 5 else ""
            )
            title = (
                "POST formulář bez CSRF ochrany"
                if count == 1
                else f"POST formuláře bez CSRF ochrany ({count}×)"
            )
            findings.append(Finding(
                id="missing-csrf-token",
                title=title,
                description="Formulář odesílá POST bez CSRF tokenu. Pokud formulář provádí citlivou akci (přihlášení, změna údajů, platba), útočník může vytvořit stránku s neviditelným formulářem, který se automaticky odešle — prohlížeč přiloží cookies a akce proběhne za přihlášeného uživatele. U veřejných formulářů (newsletter, vyhledávání) je riziko minimální.",
                severity=Severity.WARNING,
                category="forms",
                fix_url=guide_url("csrf-forms"),
                doc_url="https://owasp.org/www-community/attacks/csrf",
                detail=detail,
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

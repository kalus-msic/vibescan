"""Cookie consent enforcement check (deep scan).

scanner/js/consent_check.js opens the site in real Chromium and returns raw
data (cookies, Google request URLs, banner button presence). This module
classifies that raw data and turns it into deep-scan finding dicts.
The raw data is untrusted: every field is type-checked.
"""
import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from scanner.modules.base import Severity, guide_url

logger = logging.getLogger(__name__)

CONSENT_SCRIPT = Path(__file__).resolve().parent / "js" / "consent_check.js"
CONSENT_TIMEOUT_SECONDS = 90


# Google hosts whose requests may carry the gcs consent-state parameter.
GOOGLE_CONSENT_HOST_SUFFIXES = (
    "google-analytics.com",
    "analytics.google.com",
    "googletagmanager.com",
    "googleadservices.com",
    "doubleclick.net",
    "google.com",
)

# (cookie name pattern, service name, required cookie domain suffix or None).
# Service names = values of scanner.modules.tracking.TRACKING_NAMES (+ Google Ads).
TRACKING_COOKIE_RULES = (
    (re.compile(r"^_ga(_.+)?$"), "Google Analytics", None),
    (re.compile(r"^_gid$"), "Google Analytics", None),
    (re.compile(r"^_gat(_.+)?$"), "Google Analytics", None),
    (re.compile(r"^_gcl_(au|aw|dc)$"), "Google Ads", None),
    (re.compile(r"^_gac_.+$"), "Google Ads", None),
    (re.compile(r"^_fb[pc]$"), "Facebook Pixel", None),
    (re.compile(r"^(_hjid|_hjSession(User)?_.+)$"), "Hotjar", None),
    (re.compile(r"^(_ttp|_tt_enable_cookie)$"), "TikTok Pixel", None),
    (re.compile(r"^_uet(sid|vid)$"), "Bing UET", None),
    (re.compile(r"^ajs_anonymous_id$"), "Segment", None),
    (re.compile(r"^(li_sugr|bcookie)$"), "LinkedIn Insight", "linkedin.com"),
    (re.compile(r"^_ym_(uid|d)$"), "Yandex Metrica", None),
)

# gcs=G1<ad_storage><analytics_storage>; any "1" means granted storage
_GCS_RE = re.compile(r"^G1([01])([01])$")

TRACKING_NO_CONSENT_ID = "tracking-no-consent"
MISSING_CONSENT_ID = "missing-cookie-consent"
_FIX_URL = guide_url("pravni-dokumenty")
_DOC_URL = "https://gdpr.eu/cookies/"
_DETAIL_MAX = 160


def _host_matches(host: str, suffixes) -> bool:
    host = host.lower().lstrip(".")
    return any(host == s or host.endswith("." + s) for s in suffixes)


def classify_cookie(name, domain) -> str | None:
    """Return the tracking service name for a cookie, or None."""
    if not isinstance(name, str) or not isinstance(domain, str) or not name:
        return None
    for pattern, service, domain_suffix in TRACKING_COOKIE_RULES:
        if not pattern.match(name):
            continue
        if domain_suffix and not _host_matches(domain, (domain_suffix,)):
            continue
        return service
    return None


def granted_gcs(url) -> str | None:
    """Return the gcs value when a Google request reports granted storage.

    gcs can show up in the query string joined with '&' or ';', or inside a
    Floodlight ';'-separated path matrix - so search the whole URL rather than
    only parsing the query string.
    """
    if not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
    except ValueError:
        return None
    if not _host_matches(host, GOOGLE_CONSENT_HOST_SUFFIXES):
        return None
    match = re.search(r"[?&;]gcs=(G1[01][01])(?=[&;#?/]|$)", url)
    if not match:
        return None
    value = match.group(1)
    gcs_match = _GCS_RE.match(value)
    if gcs_match and "1" in gcs_match.groups():
        return value
    return None


@dataclass
class PhaseEvidence:
    cookies: dict[str, list[str]] = field(default_factory=dict)  # service -> names
    gcs: list[str] = field(default_factory=list)

    @property
    def has_tracking(self) -> bool:
        return bool(self.cookies or self.gcs)

    @property
    def count(self) -> int:
        """Distinct tracking cookie names + distinct granted gcs values."""
        return sum(len(names) for names in self.cookies.values()) + len(self.gcs)

    def entries(self) -> list[str]:
        out = [
            f"{service} ({', '.join(names)})"
            for service, names in sorted(self.cookies.items())
        ]
        if self.gcs:
            out.append(
                "Google tag se souhlasem ("
                + ", ".join(f"gcs={v}" for v in self.gcs) + ")"
            )
        return out


def phase_evidence(phase) -> PhaseEvidence | None:
    """Classify one collector phase. None when the phase data is unusable."""
    if not isinstance(phase, dict):
        return None
    cookies = phase.get("cookies")
    requests = phase.get("requests", [])
    if not isinstance(cookies, list) or not isinstance(requests, list):
        return None

    evidence = PhaseEvidence()
    for cookie in cookies:
        if not isinstance(cookie, dict):
            continue
        name = cookie.get("name")
        service = classify_cookie(name, cookie.get("domain", ""))
        if service:
            names = evidence.cookies.setdefault(service, [])
            if name not in names:
                names.append(name)
    for url in requests:
        value = granted_gcs(url)
        if value and value not in evidence.gcs:
            evidence.gcs.append(value)
    return evidence


def _finding(fid: str, title: str, description: str, severity: Severity,
             supersedes: list[str], detail: str = "") -> dict:
    return {
        "id": fid,
        "title": title,
        "description": description,
        "severity": severity.value,
        "category": "tracking",
        "fix_url": _FIX_URL,
        "doc_url": _DOC_URL,
        "detail": detail[:_DETAIL_MAX],
        "supersedes_ids": supersedes,
    }


def _before_consent(evidence: PhaseEvidence) -> dict:
    return _finding(
        "consent-tracking-before-consent",
        f"Tracking cookies před udělením souhlasu ({evidence.count}×)",
        "Web má cookie lištu, ale tracking cookies se ukládají ještě před tím, "
        "než uživatel udělí souhlas. Podle GDPR se analytické a marketingové "
        "cookies smí uložit až po aktivním souhlasu. Consent lišta tak neplní "
        "svou funkci.",
        Severity.WARNING,
        [TRACKING_NO_CONSENT_ID, MISSING_CONSENT_ID],
        detail=", ".join(evidence.entries()),
    )


def _reject_ineffective(evidence: PhaseEvidence) -> dict:
    return _finding(
        "consent-reject-ineffective",
        f"Tlačítko odmítnutí nefunguje ({evidence.count}×)",
        "Po kliknutí na odmítnutí cookies se tracking cookies přesto ukládají. "
        "Odmítnutí musí účinně zastavit všechny cookies kromě technicky "
        "nezbytných. Toto je přímé porušení GDPR — souhlas musí být svobodný "
        "a odmítnutí účinné.",
        Severity.CRITICAL,
        [TRACKING_NO_CONSENT_ID, MISSING_CONSENT_ID],
        detail=", ".join(evidence.entries()),
    )


def _no_reject_option() -> dict:
    return _finding(
        "consent-no-reject-option",
        "Cookie lišta bez možnosti odmítnutí",
        "Cookie lišta nabízí přijetí, ale na první vrstvě chybí stejně dostupná "
        "možnost odmítnutí. Podle výkladu ÚOOÚ a evropských dozorových úřadů "
        "musí být odmítnutí stejně snadné jako přijetí (jedno kliknutí, stejná "
        "vrstva).",
        Severity.WARNING,
        [MISSING_CONSENT_ID],
    )


def _enforcement_ok(after_accept: PhaseEvidence | None) -> dict:
    detail = ""
    if after_accept and after_accept.has_tracking:
        detail = "Po přijetí: " + ", ".join(after_accept.entries())
    return _finding(
        "consent-enforcement-ok",
        "Cookie consent funguje správně",
        "Ověřili jsme v prohlížeči: tracking cookies se neukládají před "
        "souhlasem ani po odmítnutí. Consent mechanismus plní svou funkci.",
        Severity.OK,
        [TRACKING_NO_CONSENT_ID, MISSING_CONSENT_ID],
        detail=detail,
    )


def _flag(raw: dict, key: str) -> bool:
    return raw.get(key) is True


def evaluate(raw) -> list[dict]:
    """Turn collector JSON into consent findings (see spec scenario matrix)."""
    if not isinstance(raw, dict) or raw.get("fatal"):
        return []
    reject_found = _flag(raw, "reject_button_found")
    accept_found = _flag(raw, "accept_button_found")
    if not (reject_found or accept_found):
        return []  # banner not rendered in the browser
    baseline = phase_evidence(raw.get("baseline"))
    if baseline is None:
        return []
    # after_reject counts only when the click was verified (banner closed)
    after_reject = None
    if reject_found and _flag(raw, "reject_banner_closed"):
        after_reject = phase_evidence(raw.get("after_reject"))
    after_accept = phase_evidence(raw.get("after_accept")) if accept_found else None

    findings: list[dict] = []
    if after_reject is not None and after_reject.has_tracking:
        findings.append(_reject_ineffective(after_reject))
    elif baseline.has_tracking:
        findings.append(_before_consent(baseline))
    if not reject_found:
        findings.append(_no_reject_option())

    run_complete = after_reject is not None and (not accept_found or after_accept is not None)
    if not findings and run_complete:
        findings.append(_enforcement_ok(after_accept))
    return findings


def run_consent_check(url: str) -> list[dict]:
    """Run the Node collector against url and evaluate its output.

    Never raises for collector problems - the deep scan must not fail because
    of the consent check. Returns [] on timeout, crash or invalid output.
    """
    config = json.dumps({"tracking_host_suffixes": list(GOOGLE_CONSENT_HOST_SUFFIXES)})
    try:
        proc = subprocess.run(
            ["node", str(CONSENT_SCRIPT), url, config],
            capture_output=True, text=True, timeout=CONSENT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        logger.warning("Consent check timed out for %s", url)
        return []
    except OSError:
        logger.exception("Consent check could not start for %s", url)
        return []
    if proc.returncode != 0:
        logger.warning("Consent check exit %s for %s: %s",
                       proc.returncode, url, (proc.stderr or "")[:500])
        return []
    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError:
        logger.warning("Consent check returned invalid JSON for %s", url)
        return []
    if isinstance(raw, dict):
        if raw.get("fatal"):
            fatal_text = str(raw["fatal"])[:300]
            fatal_lower = fatal_text.lower()
            if "failed to launch" in fatal_lower or "executable" in fatal_lower:
                logger.warning("Consent check aborted for %s: %s", url, fatal_text)
            else:
                logger.info("Consent check aborted for %s: %s", url, fatal_text)
        errors = raw.get("errors")
        if isinstance(errors, list):
            for error in errors[:10]:
                logger.info("Consent check warning for %s: %s", url, str(error)[:300])
    return evaluate(raw)

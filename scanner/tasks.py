import json
import logging
import re
import subprocess

import httpx
from datetime import datetime, timezone
from urllib.parse import urlparse
from celery import shared_task
from django.utils import timezone as _timezone

logger = logging.getLogger(__name__)


# Markery pro typické bot challenge / WAF stránky.
# Detekce dříve než moduly začnou počítat falešné skóre.
_CHALLENGE_TITLE_PATTERNS = re.compile(
    r"<title>[^<]*("
    r"just a moment|please wait|"
    r"please confirm you are human|"
    r"checking your browser|"
    r"attention required|"
    r"access denied|verifying you are human|"
    r"one more step|moment ago"
    r")[^<]*</title>",
    re.IGNORECASE,
)
_CHALLENGE_BODY_MARKERS = (
    "/cdn-cgi/challenge-platform/",        # Cloudflare
    "/cdn-cgi/styles/challenges.css",      # Cloudflare
    "g-recaptcha\" data-sitekey",          # Generic reCAPTCHA wall (rare on normal pages)
    "challenge-form",                       # Generic challenge form
    "_imp_apg-",                           # Imperva
    "px-captcha",                          # PerimeterX
    "akamai-bot-manager",                  # Akamai
    "ddos-guard",                          # DDoS-Guard
)


def _is_bot_challenge(html: str) -> bool:
    """Detekuje typické bot challenge stránky (Cloudflare, Akamai, Imperva, PX, ...)."""
    if not html:
        return False
    if _CHALLENGE_TITLE_PATTERNS.search(html):
        return True
    return any(marker in html for marker in _CHALLENGE_BODY_MARKERS)

from .models import ScanResult, ScanStatus
from .modules.headers import HeaderScanner
from .modules.ssl_check import SSLScanner
from .modules.html_check import HTMLScanner
from .modules.secrets import SecretLeakageScanner
from .modules.forms import FormScanner
from .modules.sri import SRIScanner
from .modules.meta import MetaTagScanner
from .modules.cors import CORSScanner
from .modules.cookies import CookieScanner
from .modules.tracking import TrackingConsentScanner
from .modules.accessibility import AccessibilityScanner
from .modules.legal import LegalScanner
from .modules.dns_check import DNSScanner
from .modules.seo import SEOScanner
from .lighthouse_mapper import LighthouseMapper
from .score import calculate_vibe_score, recalculate_with_deep_scan
from .validator import validate_resolved_ip, validate_scan_url, SSRFError

# Max response size we're willing to process (5 MB)
MAX_RESPONSE_SIZE = 5 * 1024 * 1024

# Content types we'll parse — skip binaries
ALLOWED_CONTENT_TYPES = ("text/html", "text/plain", "application/xhtml+xml")

SCAN_MODULES = [
    HeaderScanner(),
    SSLScanner(),
    HTMLScanner(),
    SecretLeakageScanner(),
    FormScanner(),
    SRIScanner(),
    MetaTagScanner(),
    CORSScanner(),
    CookieScanner(),
    TrackingConsentScanner(),
    AccessibilityScanner(),
    LegalScanner(),
    DNSScanner(),
    SEOScanner(),
    # TechLeakageScanner — disabled, requires domain verification (Phase 3)
]


def _initial_progress() -> list:
    return [
        {"label": m.step_label, "status": "pending"}
        for m in SCAN_MODULES
    ]


def _fail_scan(scan, message):
    scan.status = ScanStatus.FAILED
    scan.error_message = message
    scan.completed_at = datetime.now(timezone.utc)
    scan.save(update_fields=["status", "error_message", "completed_at"])


def _fetch_url(url):
    """Fetch URL with safety checks: size limit, content-type, SSRF on redirects."""
    # Re-validate DNS right before connecting to minimize TOCTOU window
    validate_scan_url(url)

    # Realistický UA snižuje false-block z bot mitigation (Cloudflare/Akamai).
    # Identita Vibescanu zůstává čitelná v Sec-Browser headeru i From: hlavičce.
    user_agent = (
        "Mozilla/5.0 (compatible; Vibescan/1.0; +https://vibescan.cz/) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    with httpx.stream(
        "GET",
        url,
        timeout=10,
        follow_redirects=True,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "cs-CZ,cs;q=0.9,en;q=0.8",
            "From": "audit@vibescan.cz",
        },
    ) as response:
        # Check final URL after redirects — prevent SSRF bypass via redirect
        final_host = urlparse(str(response.url)).hostname
        if final_host:
            validate_resolved_ip(final_host)

        # Check content length before reading body
        content_length = response.headers.get("content-length")
        if content_length and int(content_length) > MAX_RESPONSE_SIZE:
            raise ValueError(f"Odpověď je příliš velká ({int(content_length) // 1024 // 1024} MB)")

        # Read body with size limit
        chunks = []
        size = 0
        for chunk in response.iter_bytes(chunk_size=8192):
            size += len(chunk)
            if size > MAX_RESPONSE_SIZE:
                raise ValueError("Odpověď je příliš velká (> 5 MB)")
            chunks.append(chunk)

        # Set content manually — stream is already consumed
        response._content = b"".join(chunks)

    return response


@shared_task(bind=True)
def run_scan(self, scan_id: str):
    try:
        scan = ScanResult.objects.get(id=scan_id)
    except ScanResult.DoesNotExist:
        return

    scan.status = ScanStatus.RUNNING
    scan.progress = _initial_progress()
    scan.save(update_fields=["status", "progress"])

    try:
        response = _fetch_url(scan.url)
    except SSRFError as e:
        _fail_scan(scan, str(e))
        return
    except (httpx.RequestError, ValueError) as e:
        _fail_scan(scan, str(e))
        return

    # Check content type — only parse HTML-like responses
    content_type = response.headers.get("content-type", "").lower().split(";")[0].strip()
    is_html = content_type in ALLOWED_CONTENT_TYPES

    # Detekce bot challenge / WAF stránek. Pokud cílový server skener
    # zablokoval Cloudflare/Akamai/PerimeterX challenge, nepočítáme falešné
    # skóre z challenge stránky — vrátíme jasnou chybu.
    if is_html and _is_bot_challenge(response.text or ""):
        _fail_scan(
            scan,
            "Cílový web vrátil bot challenge (Cloudflare/Akamai/podobné). "
            "Sken nemůže vyhodnotit obsah. Zkuste přidat výjimku pro "
            "User-Agent 'Vibescan' nebo IP skeneru ve WAF konfiguraci.",
        )
        return

    all_findings = []
    progress = _initial_progress()

    for i, module in enumerate(SCAN_MODULES):
        progress[i]["status"] = "running"
        scan.progress = progress
        scan.save(update_fields=["progress"])

        try:
            # Skip HTML parsing modules for non-HTML responses
            if not is_html and module.name in ("html", "secrets", "forms", "sri", "meta", "tracking", "accessibility", "legal", "seo"):
                progress[i]["status"] = "done"
                continue
            findings = module.run(scan.url, response)
            all_findings.extend(findings)
        except Exception:
            logger.exception("Module %s failed for %s", module.name, scan.url)

        progress[i]["status"] = "done"

    scan.findings = [f.to_dict() for f in all_findings]
    scan.vibe_score = calculate_vibe_score(all_findings)
    scan.status = ScanStatus.DONE
    scan.progress = progress
    scan.completed_at = datetime.now(timezone.utc)
    scan.save(update_fields=["findings", "vibe_score", "status", "progress", "completed_at"])


@shared_task(bind=True, max_retries=0)
def run_lighthouse_scan(self, scan_id: str):
    try:
        scan = ScanResult.objects.get(id=scan_id)
    except ScanResult.DoesNotExist:
        return

    scan.deep_scan_status = "running"
    scan.deep_scan_started_at = _timezone.now()
    scan.save(update_fields=["deep_scan_status", "deep_scan_started_at"])

    try:
        proc = subprocess.run(
            [
                "lighthouse", scan.url,
                "--output=json", "--quiet",
                "--chrome-flags=--headless --no-sandbox --disable-gpu",
                "--max-wait-for-load=30000",
                "--only-categories=performance,accessibility,best-practices,seo",
            ],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Lighthouse exit {proc.returncode}: {proc.stderr[:500]}")
        data = json.loads(proc.stdout)
        if data.get("runtimeError"):
            raise RuntimeError(f"Lighthouse runtime: {data['runtimeError'].get('message', 'unknown')}")
        findings, categories = LighthouseMapper().map(data)
        scan.deep_scan_findings = findings
        scan.deep_scan_categories = categories
        scan.deep_scan_status = "done"
    except subprocess.TimeoutExpired:
        scan.deep_scan_status = "timeout"
        scan.deep_scan_error = "Lighthouse překročil 60 s"
    except json.JSONDecodeError:
        scan.deep_scan_status = "failed"
        scan.deep_scan_error = "Neplatný výstup Lighthouse (JSON parse error)"
        logger.exception("Lighthouse JSON parse failed for %s", scan_id)
    except Exception as e:
        scan.deep_scan_status = "failed"
        scan.deep_scan_error = str(e)[:500]
        logger.exception("Lighthouse scan failed for %s", scan_id)

    scan.deep_scan_finished_at = _timezone.now()
    if scan.deep_scan_status == "done":
        if scan.pre_deep_scan_score is None:
            scan.pre_deep_scan_score = scan.vibe_score  # snapshot for "78 → 72 (−6)" tooltip
        scan.vibe_score = recalculate_with_deep_scan(scan.findings, scan.deep_scan_findings)
    scan.save()

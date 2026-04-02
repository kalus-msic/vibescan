import logging

import httpx
from datetime import datetime, timezone
from urllib.parse import urlparse
from celery import shared_task

logger = logging.getLogger(__name__)

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
from .modules.dns_check import DNSScanner
from .score import calculate_vibe_score
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
    DNSScanner(),
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

    with httpx.stream(
        "GET",
        url,
        timeout=10,
        follow_redirects=True,
        headers={"User-Agent": "Vibescan/1.0 (security audit; https://vibescan.io)"},
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

    all_findings = []
    progress = _initial_progress()

    for i, module in enumerate(SCAN_MODULES):
        progress[i]["status"] = "running"
        scan.progress = progress
        scan.save(update_fields=["progress"])

        try:
            # Skip HTML parsing modules for non-HTML responses
            if not is_html and module.name in ("html", "secrets", "forms", "sri", "meta", "tracking"):
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

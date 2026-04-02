import httpx
from datetime import datetime, timezone
from celery import shared_task
from .models import ScanResult, ScanStatus
from .modules.headers import HeaderScanner
from .modules.ssl_check import SSLScanner
from .modules.html_check import HTMLScanner
from .modules.dns_check import DNSScanner
from .modules.tech import TechLeakageScanner
from .score import calculate_vibe_score


SCAN_MODULES = [
    HeaderScanner(),
    SSLScanner(),
    HTMLScanner(),
    DNSScanner(),
    TechLeakageScanner(),
]


def _initial_progress() -> list:
    return [
        {"label": m.step_label, "status": "pending"}
        for m in SCAN_MODULES
    ]


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
        response = httpx.get(
            scan.url,
            timeout=10,
            follow_redirects=True,
            headers={"User-Agent": "Vibescan/1.0 (security audit; https://vibescan.io)"},
        )
    except httpx.RequestError as e:
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        scan.completed_at = datetime.now(timezone.utc)
        scan.save(update_fields=["status", "error_message", "completed_at"])
        return

    all_findings = []
    progress = _initial_progress()

    for i, module in enumerate(SCAN_MODULES):
        progress[i]["status"] = "running"
        scan.progress = progress
        scan.save(update_fields=["progress"])

        try:
            findings = module.run(scan.url, response)
            all_findings.extend(findings)
        except Exception:
            pass

        progress[i]["status"] = "done"

    scan.findings = [f.to_dict() for f in all_findings]
    scan.vibe_score = calculate_vibe_score(all_findings)
    scan.status = ScanStatus.DONE
    scan.progress = progress
    scan.completed_at = datetime.now(timezone.utc)
    scan.save(update_fields=["findings", "vibe_score", "status", "progress", "completed_at"])

from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit
from .models import ScanResult, ScanStatus
from .forms import ScanForm
from .tasks import run_scan


def _session_key(group, request):
    """Rate limit key based on session — each browser gets its own limit."""
    if not request.session.session_key:
        request.session.create()
    return request.session.session_key


@ratelimit(key="ip", rate="60/h", method="POST", block=True, group="scan-ip")
@ratelimit(key=_session_key, rate="10/h", method="POST", block=True, group="scan-session")
@require_http_methods(["GET", "POST"])
def home(request):
    form = ScanForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        scan = ScanResult.objects.create(url=form.cleaned_data["url"])
        run_scan.delay(str(scan.id))
        return redirect("scanner:scan_detail", pk=scan.id)
    return render(request, "scanner/home.html", {"form": form})


def scan_detail(request, pk):
    scan = get_object_or_404(ScanResult, pk=pk)
    return render(request, "scanner/scan.html", {"scan": scan})


@ratelimit(key="ip", rate="60/h", method="POST", block=True, group="scan-ip")
@ratelimit(key=_session_key, rate="10/h", method="POST", block=True, group="scan-session")
@require_http_methods(["POST"])
def scan_rescan(request, pk):
    original = get_object_or_404(ScanResult, pk=pk)
    scan = ScanResult.objects.create(url=original.url)
    run_scan.delay(str(scan.id))
    return redirect("scanner:scan_detail", pk=scan.id)


def scan_status(request, pk):
    scan = get_object_or_404(ScanResult, pk=pk)

    # Detect stuck scans — if pending/running for more than 2 minutes, mark as failed
    if scan.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
        from django.utils import timezone
        age = (timezone.now() - scan.created_at).total_seconds()
        if age > 120:
            scan.status = ScanStatus.FAILED
            scan.error_message = "Sken vypršel — Celery worker pravděpodobně neodpovídá. Zkuste to znovu."
            scan.completed_at = timezone.now()
            scan.save(update_fields=["status", "error_message", "completed_at"])

    if scan.status == ScanStatus.DONE:
        return render(request, "scanner/partials/results.html", {"scan": scan})
    if scan.status == ScanStatus.FAILED:
        return render(request, "scanner/partials/failed.html", {"scan": scan})
    return render(request, "scanner/partials/progress.html", {"scan": scan})

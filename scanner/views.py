from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.http import require_http_methods
from django.http import HttpResponse, HttpResponseBadRequest, Http404
from django_ratelimit.decorators import ratelimit
from urllib.parse import urlparse
from .models import ScanResult, ScanStatus
from .forms import ScanForm
from .tasks import run_scan
from scanner.score import ScoreCategory, recalculate_from_findings_dicts


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
        scan = ScanResult.objects.create(
            url=form.cleaned_data["url"],
            ephemeral=form.cleaned_data.get("ephemeral", False),
        )
        run_scan.delay(str(scan.id))
        return redirect("scanner:scan_detail", pk=scan.id)
    return render(request, "scanner/home.html", {"form": form})


def scan_detail(request, pk):
    try:
        scan = ScanResult.objects.get(pk=pk)
    except ScanResult.DoesNotExist:
        return render(request, "scanner/scan_expired.html", status=410)
    ctx = {"scan": scan}
    if scan.ephemeral and scan.status == ScanStatus.DONE:
        response = render(request, "scanner/scan.html", ctx)
        scan.delete()
        return response
    return render(request, "scanner/scan.html", ctx)


@ratelimit(key="ip", rate="60/h", method="POST", block=True, group="scan-ip")
@ratelimit(key=_session_key, rate="10/h", method="POST", block=True, group="scan-session")
@require_http_methods(["POST"])
def scan_rescan(request, pk):
    original = get_object_or_404(ScanResult, pk=pk)
    scan = ScanResult.objects.create(url=original.url)
    run_scan.delay(str(scan.id))
    return redirect("scanner:scan_detail", pk=scan.id)


def scan_status(request, pk):
    try:
        scan = ScanResult.objects.get(pk=pk)
    except ScanResult.DoesNotExist:
        return render(request, "scanner/partials/expired.html", status=410)

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
        response = render(request, "scanner/partials/results.html", {"scan": scan})
        if scan.ephemeral:
            scan.delete()
        return response
    if scan.status == ScanStatus.FAILED:
        return render(request, "scanner/partials/failed.html", {"scan": scan})
    return render(request, "scanner/partials/progress.html", {"scan": scan})


@require_http_methods(["GET"])
def scan_export_txt(request, pk):
    scan = get_object_or_404(ScanResult, pk=pk, status=ScanStatus.DONE)
    category = ScoreCategory.from_score(scan.vibe_score)

    active = [f for f in scan.findings if not f.get("dismissed")]
    dismissed = [f for f in scan.findings if f.get("dismissed")]

    # Group active findings by category
    categories = {}
    for f in active:
        cat = f.get("category", "other")
        categories.setdefault(cat, []).append(f)
    findings_by_category = sorted(categories.items())

    domain = urlparse(scan.url).hostname or "scan"
    content = render(request, "scanner/export_txt.md", {
        "scan": scan,
        "category": {"label": category.value},
        "findings_by_category": findings_by_category,
        "dismissed": dismissed,
    }).content.decode("utf-8")

    response = HttpResponse(content, content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="vibescan-report-{domain}.txt"'
    return response


@require_http_methods(["GET"])
def scan_export_pdf(request, pk):
    import weasyprint
    scan = get_object_or_404(ScanResult, pk=pk, status=ScanStatus.DONE)
    html_string = render(request, "scanner/export_pdf.html", {"scan": scan}).content.decode("utf-8")
    pdf_bytes = weasyprint.HTML(string=html_string).write_pdf()

    domain = urlparse(scan.url).hostname or "scan"
    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="vibescan-report-{domain}.pdf"'
    return response


VALID_DISMISS_REASONS = {"not_applicable", "solved_differently", "false_positive", "other"}


@require_http_methods(["POST"])
def dismiss_finding(request, pk, finding_id):
    scan = get_object_or_404(
        ScanResult, pk=pk, status=ScanStatus.DONE, ephemeral=False
    )
    reason = request.POST.get("reason", "")
    if reason not in VALID_DISMISS_REASONS:
        return HttpResponseBadRequest("Invalid reason")

    finding = None
    for f in scan.findings:
        if f.get("id") == finding_id:
            finding = f
            break
    if finding is None:
        raise Http404("Finding not found")

    finding["dismissed"] = True
    finding["dismiss_reason"] = reason
    scan.vibe_score = recalculate_from_findings_dicts(scan.findings)
    scan.save(update_fields=["findings", "vibe_score"])
    return render(request, "scanner/partials/results.html", {"scan": scan})


@require_http_methods(["POST"])
def restore_finding(request, pk, finding_id):
    scan = get_object_or_404(
        ScanResult, pk=pk, status=ScanStatus.DONE, ephemeral=False
    )

    finding = None
    for f in scan.findings:
        if f.get("id") == finding_id:
            finding = f
            break
    if finding is None:
        raise Http404("Finding not found")

    finding.pop("dismissed", None)
    finding.pop("dismiss_reason", None)
    scan.vibe_score = recalculate_from_findings_dicts(scan.findings)
    scan.save(update_fields=["findings", "vibe_score"])
    return render(request, "scanner/partials/results.html", {"scan": scan})

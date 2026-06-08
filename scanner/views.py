from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.http import require_http_methods
from django.http import HttpResponse, HttpResponseBadRequest, Http404
from django_ratelimit.decorators import ratelimit
from urllib.parse import urlparse
from .models import ScanResult, ScanLog, ScanStatus
from .forms import ScanForm
from .tasks import run_scan, run_lighthouse_scan
from scanner.score import (
    ScoreCategory,
    recalculate_with_deep_scan_tiered,
)


def _apply_tiered_scores(scan):
    """Recalc per-tier + overall scores, store on scan.

    Returns list of fields the caller must include in scan.save(update_fields=...).
    Caller is responsible for also adding findings/deep_scan_findings as needed.
    """
    deep = scan.deep_scan_findings if scan.deep_scan_status == "done" else []
    result = recalculate_with_deep_scan_tiered(
        scan.findings, deep or [],
        classification=scan.accessibility_classification,
    )
    scan.score_security = result["security"]
    scan.score_legal = result["legal"]
    scan.score_seo = result["seo"]
    scan.vibe_score = result["overall"]
    scan.score_breakdown_computed = True
    return [
        "vibe_score",
        "score_security", "score_legal", "score_seo",
        "score_breakdown_computed",
    ]


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
        client_ip = request.META.get("HTTP_X_REAL_IP") or request.META.get("REMOTE_ADDR")
        ephemeral = form.cleaned_data.get("ephemeral", False)
        scan = ScanResult.objects.create(
            url=form.cleaned_data["url"],
            ephemeral=ephemeral,
            client_ip=client_ip,
        )
        ScanLog.objects.create(
            url=form.cleaned_data["url"],
            client_ip=client_ip,
            ephemeral=ephemeral,
        )
        run_scan.delay(str(scan.id))
        if ephemeral:
            scan.deep_scan_status = "skipped"
            scan.save(update_fields=["deep_scan_status"])
        else:
            run_lighthouse_scan.delay(str(scan.id))
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
    run_lighthouse_scan.delay(str(scan.id))
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


def build_export_txt(scan):
    """Render the AI export markdown for a finished scan and return it as a string."""
    from django.template.loader import render_to_string
    from .score import (
        _superseded_ids,
        _resolve_tier,
        resolve_accessibility_tier_from_findings,
    )

    category = ScoreCategory.from_score(scan.vibe_score)

    # Deep scan data (only used when status=done)
    deep_active = []
    deep_dismissed = []
    superseded = set()
    if scan.deep_scan_status == "done":
        for f in (scan.deep_scan_findings or []):
            (deep_dismissed if f.get("dismissed") else deep_active).append(f)
        superseded = _superseded_ids(scan.deep_scan_findings or [])

    # Fast findings, with superseded ones excluded
    active = [f for f in scan.findings if not f.get("dismissed") and f.get("id") not in superseded]
    dismissed = [f for f in scan.findings if f.get("dismissed")]

    # Combined counts: fast (post-supersede, non-dismissed) + deep (non-dismissed)
    combined = active + deep_active
    combined_counts = {
        "critical": sum(1 for f in combined if f.get("severity") == "critical"),
        "warning":  sum(1 for f in combined if f.get("severity") == "warning"),
        "info":     sum(1 for f in combined if f.get("severity") == "info"),
        "ok":       sum(1 for f in combined if f.get("severity") == "ok"),
    }

    def _group(findings):
        cats = {}
        for f in findings:
            cats.setdefault(f.get("category", "other"), []).append(f)
        return sorted(cats.items())

    # Per-tier grouping (jen pokud má scan breakdown computed)
    breakdown_ok = bool(getattr(scan, "score_breakdown_computed", False))
    findings_by_tier = {"security": [], "legal": [], "seo": []}
    deep_findings_by_tier = {"security": [], "legal": [], "seo": []}
    tier_counts = {
        "security": {"critical": 0, "warning": 0, "info": 0, "ok": 0},
        "legal":    {"critical": 0, "warning": 0, "info": 0, "ok": 0},
        "seo":      {"critical": 0, "warning": 0, "info": 0, "ok": 0},
    }
    if breakdown_ok:
        acc_tier = resolve_accessibility_tier_from_findings(
            (scan.findings or []) + (scan.deep_scan_findings or []),
            classification=getattr(scan, "accessibility_classification", "auto"),
        )
        for f in active:
            tier = _resolve_tier(f.get("category", ""), acc_tier)
            findings_by_tier[tier].append(f)
            sev = f.get("severity", "")
            if sev in tier_counts[tier]:
                tier_counts[tier][sev] += 1
        for f in deep_active:
            tier = _resolve_tier(f.get("category", ""), acc_tier)
            deep_findings_by_tier[tier].append(f)
            sev = f.get("severity", "")
            if sev in tier_counts[tier]:
                tier_counts[tier][sev] += 1

    return render_to_string("scanner/export_txt.md", {
        "scan": scan,
        "category": {"label": category.value},
        "findings_by_category": _group(active),
        "deep_findings_by_category": _group(deep_active),
        "deep_categories": scan.deep_scan_categories or {},
        "deep_status": scan.deep_scan_status,
        "deep_error": scan.deep_scan_error,
        "dismissed": dismissed,
        "deep_dismissed": deep_dismissed,
        "combined_counts": combined_counts,
        "breakdown_ok": breakdown_ok,
        "findings_by_tier": findings_by_tier,
        "deep_findings_by_tier": deep_findings_by_tier,
        "tier_counts": tier_counts,
        "score_security": getattr(scan, "score_security", None),
        "score_legal": getattr(scan, "score_legal", None),
        "score_seo": getattr(scan, "score_seo", None),
        "tier_pairs": [
            ("security", "Bezpečnost"),
            ("legal", "Právní"),
            ("seo", "SEO a výkon"),
        ],
    })


@require_http_methods(["GET"])
def scan_export_txt(request, pk):
    scan = get_object_or_404(ScanResult, pk=pk, status=ScanStatus.DONE)
    content = build_export_txt(scan)
    domain = urlparse(scan.url).hostname or "scan"
    response = HttpResponse(content, content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="vibescan-report-{domain}.txt"'
    return response


@require_http_methods(["GET"])
def scan_export_pdf(request, pk):
    import weasyprint
    scan = get_object_or_404(ScanResult, pk=pk, status=ScanStatus.DONE)

    from .score import _superseded_ids
    superseded = _superseded_ids(scan.deep_scan_findings or []) if scan.deep_scan_status == "done" else set()
    active = [f for f in scan.findings if not f.get("dismissed") and f.get("id") not in superseded]

    deep_active = [f for f in (scan.deep_scan_findings or []) if not f.get("dismissed")]

    def _group(findings):
        cats = {}
        for f in findings:
            cats.setdefault(f.get("category", "other"), []).append(f)
        return sorted(cats.items())

    ctx = {
        "scan": scan,
        "findings_by_category": _group(active),
        "deep_findings_by_category": _group(deep_active),
        "deep_categories": scan.deep_scan_categories or {},
        "deep_status": scan.deep_scan_status,
        "deep_error": scan.deep_scan_error,
        "active_findings_filtered": active,
    }
    html_string = render(request, "scanner/export_pdf.html", ctx).content.decode("utf-8")
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

    # Search both fast and deep findings
    finding = None
    is_deep = False
    for f in scan.findings:
        if f.get("id") == finding_id:
            finding = f
            break
    if finding is None:
        for f in (scan.deep_scan_findings or []):
            if f.get("id") == finding_id:
                finding = f
                is_deep = True
                break
    if finding is None:
        raise Http404("Finding not found")

    finding["dismissed"] = True
    finding["dismiss_reason"] = reason

    update_fields = _apply_tiered_scores(scan)
    if is_deep:
        update_fields.append("deep_scan_findings")
    else:
        update_fields.append("findings")
    scan.save(update_fields=update_fields)
    return render(request, "scanner/partials/results.html", {"scan": scan})


@require_http_methods(["POST"])
def restore_finding(request, pk, finding_id):
    scan = get_object_or_404(
        ScanResult, pk=pk, status=ScanStatus.DONE, ephemeral=False
    )

    # Search both fast and deep findings
    finding = None
    is_deep = False
    for f in scan.findings:
        if f.get("id") == finding_id:
            finding = f
            break
    if finding is None:
        for f in (scan.deep_scan_findings or []):
            if f.get("id") == finding_id:
                finding = f
                is_deep = True
                break
    if finding is None:
        raise Http404("Finding not found")

    finding.pop("dismissed", None)
    finding.pop("dismiss_reason", None)

    update_fields = _apply_tiered_scores(scan)
    if is_deep:
        update_fields.append("deep_scan_findings")
    else:
        update_fields.append("findings")
    scan.save(update_fields=update_fields)
    return render(request, "scanner/partials/results.html", {"scan": scan})


VALID_ACCESSIBILITY_CLASSIFICATIONS = {"auto", "legal", "seo"}


@require_http_methods(["POST"])
def set_accessibility_classification(request, pk):
    scan = get_object_or_404(
        ScanResult, pk=pk, status=ScanStatus.DONE, ephemeral=False
    )
    classification = request.POST.get("classification", "")
    if classification not in VALID_ACCESSIBILITY_CLASSIFICATIONS:
        return HttpResponseBadRequest("Invalid classification")

    scan.accessibility_classification = classification
    update_fields = _apply_tiered_scores(scan)
    update_fields.append("accessibility_classification")
    scan.save(update_fields=update_fields)
    return render(request, "scanner/partials/results.html", {"scan": scan})


def deep_scan_status(request, pk):
    scan = get_object_or_404(ScanResult, pk=pk)
    # Terminal states need a FULL refresh — vibe score, severity counts, finding
    # sections, export preview all live outside #deep-scan-section. Use HTMX
    # retargeting to swap the entire #scan-content instead.
    if scan.deep_scan_status in ("done", "failed", "timeout"):
        response = render(request, "scanner/partials/results.html", {"scan": scan})
        response["HX-Reswap"] = "outerHTML"
        response["HX-Retarget"] = "#scan-content"
        return response
    return render(
        request,
        "scanner/partials/deep_scan_section.html",
        {"scan": scan, "include_oob": True},
    )


@require_http_methods(["POST"])
def deep_scan_retry(request, pk):
    scan = get_object_or_404(ScanResult, pk=pk)
    if scan.deep_scan_status not in ("failed", "timeout"):
        return HttpResponse("Hluboký sken nelze restartovat v aktuálním stavu", status=409)
    if scan.deep_scan_retry_count >= 3:
        return HttpResponse("Překročen limit opakování (3×)", status=429)
    scan.deep_scan_status = "pending"
    scan.deep_scan_error = ""
    scan.deep_scan_started_at = None
    scan.deep_scan_finished_at = None
    scan.deep_scan_retry_count += 1
    scan.save(update_fields=[
        "deep_scan_status", "deep_scan_error",
        "deep_scan_started_at", "deep_scan_finished_at", "deep_scan_retry_count",
    ])
    run_lighthouse_scan.delay(str(scan.id))
    return redirect("scanner:scan_detail", pk=pk)

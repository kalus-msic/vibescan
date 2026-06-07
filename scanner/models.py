import uuid
from django.db import models


class ScanStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    RUNNING = "running", "Running"
    DONE = "done", "Done"
    FAILED = "failed", "Failed"


class DeepScanStatus(models.TextChoices):
    PENDING = "pending", "Čeká"
    RUNNING = "running", "Probíhá"
    DONE = "done", "Dokončen"
    FAILED = "failed", "Selhal"
    TIMEOUT = "timeout", "Vypršel"
    SKIPPED = "skipped", "Přeskočen"


class ScanResult(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    url = models.URLField(max_length=2000)
    status = models.CharField(
        max_length=10, choices=ScanStatus.choices, default=ScanStatus.PENDING
    )
    vibe_score = models.IntegerField(null=True, blank=True)
    findings = models.JSONField(default=list)
    progress = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True, default="")
    ephemeral = models.BooleanField(default=False)
    client_ip = models.GenericIPAddressField(null=True, blank=True)

    deep_scan_status = models.CharField(
        max_length=10,
        choices=DeepScanStatus.choices,
        default=DeepScanStatus.PENDING,
    )
    deep_scan_findings = models.JSONField(default=list, blank=True)
    deep_scan_categories = models.JSONField(default=dict, blank=True)
    deep_scan_started_at = models.DateTimeField(null=True, blank=True)
    deep_scan_finished_at = models.DateTimeField(null=True, blank=True)
    deep_scan_error = models.TextField(blank=True, default="")
    deep_scan_retry_count = models.PositiveSmallIntegerField(default=0)
    pre_deep_scan_score = models.IntegerField(null=True, blank=True)
    score_security = models.PositiveSmallIntegerField(default=100)
    score_legal = models.PositiveSmallIntegerField(default=100)
    score_seo = models.PositiveSmallIntegerField(default=100)
    accessibility_classification = models.CharField(
        max_length=10,
        choices=[
            ("auto", "Automaticky"),
            ("legal", "Spadá pod zákon"),
            ("seo", "Nespadá pod zákon"),
        ],
        default="auto",
    )
    score_breakdown_computed = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.url} — {self.status} ({self.vibe_score})"


class ScanLog(models.Model):
    """Lightweight audit log — tracks every scan including ephemeral ones."""
    url = models.URLField(max_length=2000)
    client_ip = models.GenericIPAddressField(null=True, blank=True)
    ephemeral = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        tag = "jednorázový" if self.ephemeral else "uložený"
        return f"{self.url} — {self.client_ip} ({tag})"

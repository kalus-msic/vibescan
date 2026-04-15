import uuid
from django.db import models


class ScanStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    RUNNING = "running", "Running"
    DONE = "done", "Done"
    FAILED = "failed", "Failed"


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

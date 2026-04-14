from django.contrib import admin
from django_celery_results.models import GroupResult
from scanner.models import ScanResult

admin.site.unregister(GroupResult)


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ("url", "status", "vibe_score", "created_at")
    list_filter = ("status",)
    search_fields = ("url",)
    ordering = ("-created_at",)
    readonly_fields = ("id", "created_at", "completed_at")

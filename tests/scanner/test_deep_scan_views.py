import pytest
from django.urls import reverse
from scanner.models import ScanResult


@pytest.mark.django_db
def test_deep_status_renders_running(client):
    scan = ScanResult.objects.create(url="https://example.com", status="done", deep_scan_status="running")
    response = client.get(reverse("scanner:deep_status", kwargs={"pk": scan.id}))
    assert response.status_code == 200
    assert b"prob" in response.content.lower() or b"Prob" in response.content


@pytest.mark.django_db
def test_deep_status_renders_done(client):
    scan = ScanResult.objects.create(
        url="https://example.com", status="done",
        deep_scan_status="done",
        deep_scan_categories={"performance": 87, "accessibility": 90, "best-practices": 80, "seo": 95},
    )
    response = client.get(reverse("scanner:deep_status", kwargs={"pk": scan.id}))
    assert response.status_code == 200
    assert b"87" in response.content


@pytest.mark.django_db
def test_deep_status_renders_failed(client):
    scan = ScanResult.objects.create(
        url="https://example.com", status="done",
        deep_scan_status="failed", deep_scan_error="Chrome crashed",
    )
    response = client.get(reverse("scanner:deep_status", kwargs={"pk": scan.id}))
    assert response.status_code == 200
    assert b"selhal" in response.content.lower()


@pytest.mark.django_db
def test_deep_status_404_on_missing(client):
    import uuid
    response = client.get(reverse("scanner:deep_status", kwargs={"pk": uuid.uuid4()}))
    assert response.status_code == 404

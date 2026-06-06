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


@pytest.mark.django_db
def test_deep_retry_resets_status_and_redispatches(client):
    from unittest.mock import patch
    scan = ScanResult.objects.create(
        url="https://example.com", status="done",
        deep_scan_status="failed", deep_scan_error="boom",
    )
    with patch("scanner.views.run_lighthouse_scan.delay") as delay:
        response = client.post(reverse("scanner:deep_retry", kwargs={"pk": scan.id}))
    assert response.status_code == 302
    delay.assert_called_once_with(str(scan.id))
    scan.refresh_from_db()
    assert scan.deep_scan_status == "pending"
    assert scan.deep_scan_retry_count == 1
    assert scan.deep_scan_error == ""


@pytest.mark.django_db
def test_deep_retry_rate_limited_after_3(client):
    from unittest.mock import patch
    scan = ScanResult.objects.create(
        url="https://example.com", status="done",
        deep_scan_status="failed", deep_scan_retry_count=3,
    )
    with patch("scanner.views.run_lighthouse_scan.delay") as delay:
        response = client.post(reverse("scanner:deep_retry", kwargs={"pk": scan.id}))
    delay.assert_not_called()
    scan.refresh_from_db()
    assert scan.deep_scan_retry_count == 3
    # 429 or message — we'll use 429
    assert response.status_code == 429


@pytest.mark.django_db
def test_deep_retry_only_post(client):
    scan = ScanResult.objects.create(url="https://example.com", status="done", deep_scan_status="failed")
    response = client.get(reverse("scanner:deep_retry", kwargs={"pk": scan.id}))
    assert response.status_code == 405


@pytest.mark.django_db
def test_deep_retry_only_for_failed_or_timeout(client):
    """Don't allow retry while still running."""
    scan = ScanResult.objects.create(url="https://example.com", status="done", deep_scan_status="running")
    response = client.post(reverse("scanner:deep_retry", kwargs={"pk": scan.id}))
    assert response.status_code == 409  # conflict — already running

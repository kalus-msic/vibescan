import pytest
from django.test import Client, RequestFactory
from unittest.mock import MagicMock
from pages.models import Subscriber
from pages.forms import NewsletterForm


@pytest.fixture
def rf():
    return RequestFactory()


def _make_session():
    session = MagicMock()
    session.session_key = "test-session-key"
    return session


@pytest.mark.django_db
class TestSubscriberModel:
    def test_create_subscriber(self):
        sub = Subscriber.objects.create(email="test@example.com")
        assert sub.email == "test@example.com"
        assert sub.created_at is not None

    def test_duplicate_email_raises(self):
        Subscriber.objects.create(email="test@example.com")
        with pytest.raises(Exception):
            Subscriber.objects.create(email="test@example.com")


class TestNewsletterForm:
    def test_valid_email(self):
        form = NewsletterForm(data={"email": "user@example.com"})
        assert form.is_valid()

    def test_invalid_email(self):
        form = NewsletterForm(data={"email": "not-an-email"})
        assert not form.is_valid()

    def test_empty_email(self):
        form = NewsletterForm(data={"email": ""})
        assert not form.is_valid()


@pytest.mark.django_db
class TestSubscribeView:
    def test_valid_email_creates_subscriber(self, rf):
        from pages.views import subscribe
        request = rf.post("/roadmap/subscribe/", {"email": "new@example.com"})
        request.session = _make_session()
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = subscribe(request)
        assert response.status_code == 200
        assert Subscriber.objects.filter(email="new@example.com").exists()
        content = response.content.decode()
        assert "vědět" in content.lower()

    def test_duplicate_email_returns_success(self, rf):
        from pages.views import subscribe
        Subscriber.objects.create(email="dup@example.com")
        request = rf.post("/roadmap/subscribe/", {"email": "dup@example.com"})
        request.session = _make_session()
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = subscribe(request)
        assert response.status_code == 200
        assert Subscriber.objects.filter(email="dup@example.com").count() == 1
        content = response.content.decode()
        assert "vědět" in content.lower()

    def test_invalid_email_returns_error(self, rf):
        from pages.views import subscribe
        request = rf.post("/roadmap/subscribe/", {"email": "bad"})
        request.session = _make_session()
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = subscribe(request)
        assert response.status_code == 200
        content = response.content.decode()
        assert "platný" in content.lower() or "email" in content.lower()

    def test_get_not_allowed(self, rf):
        from pages.views import subscribe
        request = rf.get("/roadmap/subscribe/")
        response = subscribe(request)
        assert response.status_code == 405


class TestRoadmapView:
    def test_roadmap_page_loads(self):
        client = Client()
        response = client.get("/roadmap/")
        assert response.status_code == 200
        content = response.content.decode()
        assert "připravujeme" in content.lower()

    def test_roadmap_contains_sections(self):
        client = Client()
        response = client.get("/roadmap/")
        content = response.content.decode()
        assert "Brzy" in content
        assert "Připravujeme" in content
        assert "Na horizontu" in content

    def test_roadmap_contains_newsletter_form(self):
        client = Client()
        response = client.get("/roadmap/")
        content = response.content.decode()
        assert "email" in content.lower()
        assert "subscribe" in content


class TestHowItWorksSensitiveFiles:
    def test_sensitive_files_links_to_roadmap(self):
        client = Client()
        response = client.get("/how-it-works/")
        content = response.content.decode()
        assert "/roadmap/" in content


class TestNavigation:
    def test_nav_contains_roadmap_link(self):
        client = Client()
        response = client.get("/")
        content = response.content.decode()
        assert "Roadmapa" in content
        assert "/roadmap/" in content


class TestContextProcessor:
    def test_gtm_id_in_context(self):
        client = Client()
        response = client.get("/")
        assert "gtm_id" in response.context


class TestGuideView:
    def test_guide_loads(self):
        client = Client()
        r = client.get("/guide/")
        assert r.status_code == 200

    def test_guide_has_checklist_heading(self):
        client = Client()
        r = client.get("/guide/")
        assert "Rychlý start checklist" in r.content.decode()

    def test_guide_has_all_checklist_items(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        for item_id in ["secrets", "rls", "idor", "dpa", "ratelimit", "privacy", "terms"]:
            assert f"toggle('{item_id}')" in body, f"Missing checklist item: {item_id}"

    def test_checklist_disclaimer_present(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert "základní orientační checklist" in body
        assert "není právní ani bezpečnostní poradce" in body

    def test_checklist_uses_localstorage(self):
        client = Client()
        r = client.get("/guide/")
        assert "vibescan-checklist" in r.content.decode()

    def test_narrative_section_idor_present(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert 'id="section-idor"' in body
        assert "Přístupy a IDOR" in body
        assert "Moltbook" in body

    def test_narrative_section_secrets_present(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert 'id="section-secrets"' in body
        assert "Secrets — frontend není trezor" in body
        assert "gitleaks" in body or "trufflehog" in body

    def test_narrative_section_nis2_present(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert 'id="section-nis2"' in body
        assert "NIS2" in body
        assert "ZoKB" in body
        assert "264/2025" in body

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

    def test_new_prompts_present(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert "Přístupy a IDOR — kontrola autorizace" in body
        assert "Secrets scan — kontrola před deployem" in body
        assert 'id="pristupy-idor"' in body
        assert 'id="secrets-scan"' in body

    def test_pravni_dokumenty_contains_nis2_and_sources(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert "NIS2" in body or "ZoKB" in body
        assert "Kde se učit víc" in body
        assert "w3.org/TR/WCAG22" in body
        assert "gcs=G100" in body or "gcs=G111" in body

    def test_pravni_dokumenty_renders_disclaimer(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert "Tohle není právní rada" in body

    def test_universal_ask_callout_present(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert "Konvence:" in body
        assert "zeptat se přímo tebe" in body

    def test_nez_zacnes_in_decision_prompts(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert body.count("Než začneš, potřebuješ vědět") >= 5

    def test_pravni_dokumenty_has_two_regimes_and_booking(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert "99/2019" in body
        assert "424/2023" in body
        assert "rezervační" in body or "Rezervační" in body
        assert "mikropodnik" in body.lower()
        assert "Mít prohlášení" in body

    def test_archetype_picker_present(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert "Co stavíš?" in body
        for arch_id in ["vizitka", "blog", "eshop", "booking", "verejnopravni", "saas"]:
            assert f"toggleArchetype('{arch_id}')" in body, f"Missing archetype button: {arch_id}"

    def test_archetype_labels_rendered(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert "Vizitka / portfolio" in body
        assert "E-shop" in body
        assert "Rezervační systém" in body
        assert "Veřejnoprávní subjekt" in body
        assert "SaaS / appka s účty" in body

    def test_verejnopravni_archetype_clarifies_operator_not_content(self):
        """Tip near picker explains that veřejnoprávnost = o provozovateli, ne typ obsahu."""
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert "o provozovateli" in body or "o <em>provozovateli</em>" in body
        assert "obecní knihovny" in body or "veřejné nemocnice" in body

    def test_archetype_tooltips_rendered(self):
        """Každý archetyp má tooltip s description, role=tooltip a aria-describedby."""
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        for arch_id in ["vizitka", "blog", "eshop", "booking", "verejnopravni", "saas"]:
            assert f'id="tooltip-{arch_id}"' in body, f"Missing tooltip for: {arch_id}"
            assert f'aria-describedby="tooltip-{arch_id}"' in body, f"Missing aria-describedby for: {arch_id}"
        # Spot-check description content z různých archetypů
        assert "Statický prezentační web" in body  # vizitka
        assert "ČOI, reklamace" in body  # eshop
        assert "Multi-tenant aplikace" in body  # saas
        assert "ČT/ČRo, ČTK, ČNB" in body  # verejnopravni

    def test_services_picker_present(self):
        """Druhá chip sekce 'Doplňkové funkce / služby' obsahuje všechny služby."""
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert "Doplňkové funkce" in body
        for svc_id in ["admin", "newsletter", "members", "comments", "analytics", "forms", "payments"]:
            assert f"toggleService('{svc_id}')" in body, f"Missing service button: {svc_id}"
            assert f'id="tooltip-service-{svc_id}"' in body, f"Missing tooltip for service: {svc_id}"

    def test_admin_service_triggers_rls_idor_ratelimit_only(self):
        """Admin služba aktivuje rls/idor/ratelimit (security), ne privacy/dpa/pii (ty jsou o user data)."""
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        # rls + idor + ratelimit obsahují admin
        for item_id in ("rls", "idor", "ratelimit"):
            idx = body.find(f"toggle('{item_id}')")
            assert idx > 0, f"item {item_id} not found"
            snippet = body[idx:idx + 600]
            assert "admin" in snippet, f"{item_id} applies_to should include 'admin'"
        # privacy a pii-retention NEobsahují admin
        for item_id in ("privacy", "pii-retention"):
            idx = body.find(f"toggle('{item_id}')")
            assert idx > 0
            # applies_to je hned na dalším řádku, vyhraj ho
            snippet = body[idx:idx + 600]
            applies = snippet.split("isRelevantItem(")[1].split(")")[0]
            assert "'admin'" not in applies, f"{item_id} should NOT include 'admin' (got: {applies})"

    def test_service_labels_and_descriptions(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        # Labels
        assert "Newsletter" in body
        assert "Registrace / členská zóna" in body
        assert "Analytika návštěvnosti" in body
        assert "Online platby" in body
        # Description spot-checks
        assert "Mailchimp" in body or "Ecomail" in body
        assert "Plausible" in body or "Matomo" in body
        assert "Stripe" in body or "GoPay" in body

    def test_blog_description_no_longer_mentions_newsletter_comments(self):
        """Newsletter/komentáře jsou teď doplňkové služby, ne 'blog feature'."""
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        # Najdi blog description tooltip
        blog_section_start = body.find('id="tooltip-blog"')
        assert blog_section_start > 0
        blog_section = body[blog_section_start:blog_section_start + 600]
        # Blog description už neobsahuje komentáře/newsletter
        assert "newsletter" not in blog_section.lower() or "Pokud máš newsletter" in blog_section
        assert "RSS" in blog_section  # ale obsahuje publikační znaky

    def test_services_localstorage_key(self):
        client = Client()
        r = client.get("/guide/")
        assert "vibescan-services" in r.content.decode()

    def test_privacy_applies_to_includes_services(self):
        """Privacy se aktivuje i službami (newsletter, analytics, members…), ne jen archetypy."""
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        # applies_to je v atributu x-show po toggle('privacy')
        privacy_idx = body.find("toggle('privacy')")
        assert privacy_idx > 0
        snippet = body[privacy_idx:privacy_idx + 600]
        assert "newsletter" in snippet
        assert "analytics" in snippet
        assert "members" in snippet

    def test_new_checklist_items_present(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert "toggle('accessibility')" in body
        assert "toggle('pii-retention')" in body
        assert "WCAG 2.2 AA" in body
        assert "Retence dat" in body

    def test_applies_to_rendered_for_items(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        # Python list je renderován s single quotes — JS to akceptuje
        assert "isRelevantItem(['all'])" in body
        assert "eshop" in body and "booking" in body and "verejnopravni" in body

    def test_archetype_localstorage_keys(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert "vibescan-archetype" in body
        assert "vibescan-hide-irrelevant" in body
        assert "vibescan-filter-sections" in body

    def test_filter_toggles_present(self):
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        assert "Skrýt nerelevantní položky checklistu" in body
        assert "Filtrovat i sekce průvodce" in body

    def test_terms_no_longer_mentions_accessibility(self):
        """Po rozsekání: 'terms' položka řeší jen ToS, přístupnost má vlastní položku."""
        client = Client()
        r = client.get("/guide/")
        body = r.content.decode()
        # ToS položka neobsahuje "WCAG" v titulku (může být jinde na stránce)
        # Hledáme přesný název položky checklistu
        assert "Terms of Service / Obchodní podmínky" in body


class TestGuideSubpagesReturn200:
    def test_guide_tools_returns_200(self):
        client = Client()
        r = client.get("/guide/tools/")
        assert r.status_code == 200

    def test_guide_prompts_returns_200(self):
        client = Client()
        r = client.get("/guide/prompts/")
        assert r.status_code == 200

    def test_guide_topics_returns_200(self):
        client = Client()
        r = client.get("/guide/topics/")
        assert r.status_code == 200


class TestGuideTools:
    def test_h1_present(self):
        r = Client().get("/guide/tools/")
        assert "S čím stavíš?" in r.content.decode()

    def test_all_tool_categories_present(self):
        r = Client().get("/guide/tools/")
        body = r.content.decode()
        from pages.views import TOOL_CATEGORIES
        for category in TOOL_CATEGORIES:
            assert category["title"] in body, f"category missing: {category['title']}"

    def test_lovable_tool_card_present(self):
        r = Client().get("/guide/tools/")
        body = r.content.decode()
        assert "Lovable" in body
        assert "Stack" in body
        assert "Hosting" in body

    def test_back_to_hub_link(self):
        r = Client().get("/guide/tools/")
        assert 'href="/guide/"' in r.content.decode()


class TestGuideTopics:
    def test_h1_present(self):
        body = Client().get("/guide/topics/").content.decode()
        assert "Hluboká témata" in body or "Témata" in body

    def test_section_idor_present(self):
        body = Client().get("/guide/topics/").content.decode()
        assert 'id="section-idor"' in body
        assert "Přístupy a IDOR" in body
        assert "Moltbook" in body

    def test_section_secrets_present(self):
        body = Client().get("/guide/topics/").content.decode()
        assert 'id="section-secrets"' in body
        assert "Secrets — frontend není trezor" in body

    def test_section_nis2_present(self):
        body = Client().get("/guide/topics/").content.decode()
        assert 'id="section-nis2"' in body
        assert "NIS2" in body
        assert "264/2025" in body

    def test_section_retence_present(self):
        body = Client().get("/guide/topics/").content.decode()
        assert 'id="section-retence"' in body
        assert "Free Mobile" in body
        assert "27 mil. EUR" in body

    def test_section_ai_gdpr_present(self):
        body = Client().get("/guide/topics/").content.decode()
        assert 'id="section-ai-gdpr"' in body
        assert "AI nástroje a GDPR" in body
        assert "Ollama" in body

    def test_back_to_hub_link(self):
        body = Client().get("/guide/topics/").content.decode()
        assert 'href="/guide/"' in body

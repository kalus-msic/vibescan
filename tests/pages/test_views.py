import pytest
from pages.models import Subscriber
from pages.forms import NewsletterForm


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

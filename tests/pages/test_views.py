import pytest
from pages.models import Subscriber


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

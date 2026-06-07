"""Testy 3-tier skórovacího engine (Bezpečnost / Právní / SEO)."""
from scanner.modules.base import Finding, Severity
from scanner.score import (
    CATEGORY_TO_TIER,
    TIER_WEIGHTS,
)


def test_category_to_tier_security_categories():
    for cat in ["headers", "cookies", "dns", "forms", "tech", "cors",
                "sri", "secrets", "ssl_check", "tracking", "html",
                "best-practices"]:
        assert CATEGORY_TO_TIER[cat] == "security", f"{cat} should be security"


def test_category_to_tier_legal_categories():
    assert CATEGORY_TO_TIER["legal"] == "legal"


def test_category_to_tier_seo_categories():
    for cat in ["seo", "meta", "performance"]:
        assert CATEGORY_TO_TIER[cat] == "seo"


def test_accessibility_not_in_static_mapping():
    assert "accessibility" not in CATEGORY_TO_TIER


def test_tier_weights_sum_to_one():
    assert abs(sum(TIER_WEIGHTS.values()) - 1.0) < 1e-9
    assert TIER_WEIGHTS["security"] == 0.5
    assert TIER_WEIGHTS["legal"] == 0.3
    assert TIER_WEIGHTS["seo"] == 0.2

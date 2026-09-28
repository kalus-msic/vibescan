"""Tests for cookie consent enforcement evaluation (no browser)."""
import pytest

from scanner.consent_check import (
    classify_cookie,
    evaluate,
    granted_gcs,
    phase_evidence,
)

_UNSET = object()


def _phase(*cookie_names, domain="example.com", requests=()):
    return {
        "cookies": [{"name": n, "domain": domain} for n in cookie_names],
        "requests": list(requests),
    }


def _raw(baseline, after_reject=None, after_accept=_UNSET, reject=True, accept=True, closed=True):
    if after_accept is _UNSET:
        after_accept = _phase() if accept else None
    return {
        "reject_button_found": reject,
        "accept_button_found": accept,
        "reject_banner_closed": closed if after_reject is not None else False,
        "baseline": baseline,
        "after_reject": after_reject,
        "after_accept": after_accept,
        "errors": [],
    }


def _ids(findings):
    return [f["id"] for f in findings]


GA_GRANTED = "https://region1.google-analytics.com/g/collect?v=2&tid=G-X&gcs=G111&en=page_view"
GA_DENIED = "https://region1.google-analytics.com/g/collect?v=2&tid=G-X&gcs=G100&en=page_view"
BOTH = ["tracking-no-consent", "missing-cookie-consent"]


class TestClassifyCookie:
    @pytest.mark.parametrize("name,domain,service", [
        ("_ga", ".example.com", "Google Analytics"),
        ("_ga_ABC123XYZ", ".example.com", "Google Analytics"),
        ("_gid", ".example.com", "Google Analytics"),
        ("_gat_UA-1234-1", ".example.com", "Google Analytics"),
        ("_gcl_au", ".example.com", "Google Ads"),
        ("_gcl_aw", ".example.com", "Google Ads"),
        ("_gcl_dc", ".example.com", "Google Ads"),
        ("_gac_UA-1234-1", ".example.com", "Google Ads"),
        ("_fbp", ".example.com", "Facebook Pixel"),
        ("_fbc", ".example.com", "Facebook Pixel"),
        ("_hjSessionUser_123", "example.com", "Hotjar"),
        ("_hjSession_123", "example.com", "Hotjar"),
        ("_hjid", "example.com", "Hotjar"),
        ("_ttp", ".example.com", "TikTok Pixel"),
        ("_uetvid", ".example.com", "Bing UET"),
        ("ajs_anonymous_id", "example.com", "Segment"),
        ("bcookie", ".linkedin.com", "LinkedIn Insight"),
        ("li_sugr", ".linkedin.com", "LinkedIn Insight"),
        ("_ym_uid", ".example.com", "Yandex Metrica"),
    ])
    def test_tracking(self, name, domain, service):
        assert classify_cookie(name, domain) == service

    @pytest.mark.parametrize("name,domain", [
        ("_galaxy_session", "gitlab.com"),
        ("_gateway", "example.com"),
        ("sessionid", "example.com"),
        ("csrftoken", "example.com"),
        ("cookie-consent", "example.com"),
        ("bcookie", "example.com"),
        ("", ""),
        ([], {}),
        ("_ga", None),
    ])
    def test_not_tracking(self, name, domain):
        assert classify_cookie(name, domain) is None

    def test_service_names_match_tracking_module(self):
        from scanner.consent_check import TRACKING_COOKIE_RULES
        from scanner.modules.tracking import TRACKING_NAMES
        services = {service for _, service, _ in TRACKING_COOKIE_RULES}
        assert services - set(TRACKING_NAMES.values()) == {"Google Ads"}


class TestGrantedGcs:
    @pytest.mark.parametrize("url,expected", [
        (GA_GRANTED, "G111"),
        ("https://www.google-analytics.com/g/collect?gcs=G101", "G101"),
        ("https://www.googleadservices.com/pagead/conversion/1/?gcs=G110", "G110"),
        (GA_DENIED, None),
        ("https://region1.google-analytics.com/g/collect?v=2&tid=G-X", None),
        ("https://example.com/collect?gcs=G111", None),
        ("https://evilgoogle-analytics.com/g/collect?gcs=G111", None),
        ("http://[::1", None),
        (None, None),
        (3, None),
    ])
    def test_gcs(self, url, expected):
        assert granted_gcs(url) == expected


class TestPhaseEvidence:
    def test_groups_cookies_by_service(self):
        ev = phase_evidence(_phase("_ga", "_gid", "_fbp", "sessionid"))
        assert ev.cookies == {"Google Analytics": ["_ga", "_gid"], "Facebook Pixel": ["_fbp"]}
        assert ev.has_tracking is True
        assert ev.count == 3
        assert ev.entries() == ["Facebook Pixel (_fbp)", "Google Analytics (_ga, _gid)"]

    def test_gcs_entry(self):
        ev = phase_evidence(_phase(requests=[GA_GRANTED, GA_GRANTED]))
        assert ev.gcs == ["G111"]
        assert ev.count == 1
        assert ev.entries() == ["Google tag se souhlasem (gcs=G111)"]

    def test_empty_phase(self):
        ev = phase_evidence(_phase())
        assert ev.has_tracking is False
        assert ev.count == 0
        assert ev.entries() == []

    @pytest.mark.parametrize("phase", [
        None, [], "x",
        {"cookies": "nope", "requests": []},
        {"cookies": [], "requests": "nope"},
        {"requests": []},
    ])
    def test_invalid_phase_is_none(self, phase):
        assert phase_evidence(phase) is None


class TestEvaluate:
    def test_clean_reject_path_is_ok(self):
        findings = evaluate(_raw(_phase(), after_reject=_phase(), after_accept=_phase("_ga")))
        assert _ids(findings) == ["consent-enforcement-ok"]
        f = findings[0]
        assert f["severity"] == "ok"
        assert f["supersedes_ids"] == ["missing-cookie-consent"]
        assert "Google Analytics" in f["detail"]

    def test_only_reject_button_clean_is_ok(self):
        findings = evaluate(_raw(_phase(), after_reject=_phase(), accept=False))
        assert _ids(findings) == ["consent-enforcement-ok"]

    def test_tracking_before_consent(self):
        findings = evaluate(_raw(_phase("_ga", "_fbp"), after_reject=_phase()))
        assert _ids(findings) == ["consent-tracking-before-consent"]
        f = findings[0]
        assert f["severity"] == "warning"
        assert f["supersedes_ids"] == BOTH
        assert "(2×)" in f["title"]
        assert f["detail"] == "Facebook Pixel (_fbp), Google Analytics (_ga)"

    def test_count_is_cookie_names_not_services(self):
        findings = evaluate(_raw(_phase("_ga", "_gid"), after_reject=_phase()))
        assert "(2×)" in findings[0]["title"]
        assert findings[0]["detail"] == "Google Analytics (_ga, _gid)"

    def test_reject_ineffective_when_cookies_persist(self):
        findings = evaluate(_raw(_phase("_ga"), after_reject=_phase("_ga")))
        assert _ids(findings) == ["consent-reject-ineffective"]
        assert findings[0]["severity"] == "critical"
        assert findings[0]["supersedes_ids"] == BOTH

    def test_reject_ineffective_when_cookies_appear_after_click(self):
        findings = evaluate(_raw(_phase(), after_reject=_phase("_fbp")))
        assert _ids(findings) == ["consent-reject-ineffective"]

    def test_gcs_granted_after_reject_is_ineffective(self):
        findings = evaluate(_raw(_phase(), after_reject=_phase(requests=[GA_GRANTED])))
        assert _ids(findings) == ["consent-reject-ineffective"]
        assert "gcs=G111" in findings[0]["detail"]

    def test_gcs_granted_in_baseline_is_before_consent(self):
        findings = evaluate(_raw(_phase(requests=[GA_GRANTED]), after_reject=_phase()))
        assert _ids(findings) == ["consent-tracking-before-consent"]

    def test_gcs_denied_after_reject_is_ok(self):
        findings = evaluate(_raw(
            _phase(requests=[GA_DENIED]), after_reject=_phase(requests=[GA_DENIED]),
        ))
        assert _ids(findings) == ["consent-enforcement-ok"]

    def test_no_reject_option(self):
        findings = evaluate(_raw(_phase(), reject=False))
        assert _ids(findings) == ["consent-no-reject-option"]
        assert findings[0]["severity"] == "warning"
        assert findings[0]["supersedes_ids"] == ["missing-cookie-consent"]

    def test_no_reject_option_with_baseline_tracking(self):
        findings = evaluate(_raw(_phase("_ga"), reject=False))
        assert _ids(findings) == ["consent-tracking-before-consent", "consent-no-reject-option"]

    def test_no_buttons_means_no_banner(self):
        assert evaluate(_raw(_phase("_ga"), reject=False, accept=False)) == []

    def test_fatal_yields_nothing(self):
        assert evaluate({"fatal": "deadline"}) == []

    def test_reject_click_failed_clean_baseline_yields_nothing(self):
        assert evaluate(_raw(_phase(), after_reject=None)) == []

    def test_reject_click_failed_tracking_baseline_is_before_consent(self):
        findings = evaluate(_raw(_phase("_ga"), after_reject=None))
        assert _ids(findings) == ["consent-tracking-before-consent"]

    def test_reject_banner_not_closed_ignores_after_reject(self):
        # Click not verified: after_reject evidence must not produce CRITICAL or OK
        assert evaluate(_raw(_phase(), after_reject=_phase("_ga"), closed=False)) == []
        assert evaluate(_raw(_phase(), after_reject=_phase(), closed=False)) == []

    def test_reject_banner_not_closed_tracking_baseline_is_before_consent(self):
        findings = evaluate(_raw(_phase("_ga"), after_reject=_phase("_ga"), closed=False))
        assert _ids(findings) == ["consent-tracking-before-consent"]

    def test_accept_phase_failed_yields_no_ok(self):
        assert evaluate(_raw(_phase(), after_reject=_phase(), after_accept=None)) == []

    def test_accept_phase_failed_keeps_reject_ineffective(self):
        findings = evaluate(_raw(_phase(), after_reject=_phase("_ga"), after_accept=None))
        assert _ids(findings) == ["consent-reject-ineffective"]

    @pytest.mark.parametrize("raw", [
        None, [], "x",
        {"reject_button_found": True, "baseline": None},
        {"reject_button_found": True, "accept_button_found": True,
         "baseline": {"cookies": "nope", "requests": []}, "after_reject": _phase()},
        {"reject_button_found": "false", "accept_button_found": "false",
         "baseline": _phase("_ga"), "after_reject": None, "after_accept": None},
    ])
    def test_malformed_input_yields_nothing(self, raw):
        assert evaluate(raw) == []

    def test_junk_cookie_entries_are_skipped(self):
        after_reject = {
            "cookies": [
                None, 5, {"domain": "x"}, {"name": [], "domain": {}},
                {"name": "_ga", "domain": None},
                {"name": "_ga", "domain": "example.com"},
            ],
            "requests": [None, 3, {"u": 1}],
        }
        findings = evaluate(_raw(_phase(), after_reject=after_reject))
        assert _ids(findings) == ["consent-reject-ineffective"]
        assert "(1×)" in findings[0]["title"]

    def test_finding_shape(self):
        many = [f"_ga_{i:03d}XXXXXXXXXXXXXXXXXXXX" for i in range(20)]
        raws = [
            _raw(_phase(), after_reject=_phase()),
            _raw(_phase(*many), after_reject=_phase()),
            _raw(_phase(), after_reject=_phase(*many)),
            _raw(_phase(), reject=False),
        ]
        for raw in raws:
            for f in evaluate(raw):
                assert set(f) >= {"id", "title", "description", "severity", "category",
                                  "fix_url", "doc_url", "detail", "supersedes_ids"}
                assert f["category"] == "tracking"
                assert len(f["detail"]) <= 160

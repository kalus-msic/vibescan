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
        # gcs joined with ';' alongside other query params (real-world Google pings)
        ("https://www.googleadservices.com/pagead/viewthroughconversion/1/"
         "?random=1&gcs=G111;gcd=13r3;dma=1", "G111"),
        # gcs inside a Floodlight ';'-separated path matrix, not the query string
        ("https://ad.doubleclick.net/activity;src=1;gcs=G111;ord=1?", "G111"),
        # ';'-joined form still respects the "at least one granted '1'" rule
        ("https://www.googleadservices.com/pagead/viewthroughconversion/1/"
         "?random=1&gcs=G100;gcd=13r3;dma=1", None),
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

    def test_cmp_signal_from_cookie_and_request(self):
        assert phase_evidence(_phase("didomi_token")).cmp is True
        assert phase_evidence(_phase("cmplz_banner-status")).cmp is True
        assert phase_evidence(_phase(requests=["https://cdn.cookielaw.org/otSDKStub.js"])).cmp is True
        assert phase_evidence(_phase("_ga", "sessionid")).cmp is False
        assert phase_evidence(_phase(requests=["https://evilcookielaw.org/x.js"])).cmp is False


class TestEvaluate:
    def test_clean_reject_path_is_ok(self):
        findings = evaluate(_raw(_phase(), after_reject=_phase(), after_accept=_phase("_ga")))
        assert _ids(findings) == ["consent-enforcement-ok"]
        f = findings[0]
        assert f["severity"] == "ok"
        assert f["supersedes_ids"] == BOTH
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

    def test_no_banner_with_tracking_is_critical_pair(self):
        findings = evaluate(_raw(_phase("_ga", "_fbp"), reject=False, accept=False))
        assert _ids(findings) == ["consent-tracking-without-banner", "consent-banner-required"]
        f5, f6 = findings
        assert (f5["severity"], f5["category"]) == ("critical", "tracking")
        assert f5["supersedes_ids"] == ["tracking-no-consent"]
        assert "(2×)" in f5["title"]
        assert f5["detail"] == "Facebook Pixel (_fbp), Google Analytics (_ga)"
        assert (f6["severity"], f6["category"]) == ("critical", "legal")
        assert f6["supersedes_ids"] == ["missing-cookie-consent"]

    def test_no_banner_with_granted_gcs_is_critical_pair(self):
        findings = evaluate(_raw(_phase(requests=[GA_GRANTED]), reject=False, accept=False))
        assert _ids(findings) == ["consent-tracking-without-banner", "consent-banner-required"]

    def test_no_banner_without_tracking_is_not_required(self):
        findings = evaluate(_raw(_phase("sessionid"), reject=False, accept=False))
        assert _ids(findings) == ["consent-not-required"]
        f = findings[0]
        assert (f["severity"], f["category"]) == ("ok", "legal")
        assert f["supersedes_ids"] == ["missing-cookie-consent"]

    def test_no_banner_without_tracking_but_static_tracking_yields_nothing(self):
        raw = _raw(_phase(), reject=False, accept=False)
        assert evaluate(raw, fast_ids=frozenset({"tracking-no-consent"})) == []

    def test_no_buttons_with_static_cmp_is_before_consent(self):
        raw = _raw(_phase("_ga"), reject=False, accept=False)
        findings = evaluate(raw, fast_ids=frozenset({"cookie-consent-ok"}))
        assert _ids(findings) == ["consent-tracking-before-consent"]

    @pytest.mark.parametrize("cmp_cookie", ["didomi_token", "cmpsessid", "euconsent-v2", "cmplz_statistics"])
    def test_no_buttons_with_cmp_cookie_is_before_consent(self, cmp_cookie):
        findings = evaluate(_raw(_phase("_ga", cmp_cookie), reject=False, accept=False))
        assert _ids(findings) == ["consent-tracking-before-consent"]

    def test_no_buttons_with_cmp_request_is_before_consent(self):
        baseline = _phase("_ga", requests=["https://sdk.privacy-center.org/loader.js"])
        findings = evaluate(_raw(baseline, reject=False, accept=False))
        assert _ids(findings) == ["consent-tracking-before-consent"]

    def test_no_buttons_with_cmp_signal_and_no_tracking_yields_nothing(self):
        assert evaluate(_raw(_phase("didomi_token"), reject=False, accept=False)) == []
        assert evaluate(_raw(_phase(), reject=False, accept=False),
                        fast_ids=frozenset({"cookie-consent-ok"})) == []

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
        {"reject_button_found": 0, "accept_button_found": 0,
         "baseline": _phase("_ga"), "after_reject": None, "after_accept": None},
        {"reject_button_found": None, "accept_button_found": False,
         "baseline": _phase(), "after_reject": None, "after_accept": None},
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


import json
import subprocess
from unittest.mock import MagicMock, patch

from scanner.consent_check import (
    CONSENT_SCRIPT,
    COLLECTOR_HOST_SUFFIXES,
    GOOGLE_CONSENT_HOST_SUFFIXES,
    run_consent_check,
)


def _proc(stdout="", returncode=0, stderr=""):
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


class TestRunConsentCheck:
    def test_invokes_node_collector_and_evaluates(self):
        raw = _raw(_phase(), after_reject=_phase())
        with patch("scanner.consent_check.subprocess.run", return_value=_proc(json.dumps(raw) + "\n")) as run:
            findings = run_consent_check("https://example.com")
        cmd = run.call_args.args[0]
        assert cmd[:3] == ["node", str(CONSENT_SCRIPT), "https://example.com"]
        assert json.loads(cmd[3]) == {"tracking_host_suffixes": list(COLLECTOR_HOST_SUFFIXES)}
        assert run.call_args.kwargs["timeout"] == 90
        assert _ids(findings) == ["consent-enforcement-ok"]

    @pytest.mark.parametrize("error", [
        subprocess.TimeoutExpired(cmd="node", timeout=90),
        FileNotFoundError("node"),
    ])
    def test_launch_problems_return_empty(self, error):
        with patch("scanner.consent_check.subprocess.run", side_effect=error):
            assert run_consent_check("https://example.com") == []

    def test_nonzero_exit_returns_empty(self):
        with patch("scanner.consent_check.subprocess.run", return_value=_proc(returncode=1, stderr="boom")):
            assert run_consent_check("https://example.com") == []

    def test_invalid_json_returns_empty(self):
        with patch("scanner.consent_check.subprocess.run", return_value=_proc("not json")):
            assert run_consent_check("https://example.com") == []

    def test_fatal_returns_empty(self):
        with patch("scanner.consent_check.subprocess.run", return_value=_proc('{"fatal": "deadline"}')):
            assert run_consent_check("https://example.com") == []

    def test_non_list_errors_do_not_raise(self):
        raw = {**_raw(_phase(), after_reject=_phase()), "errors": "boom"}
        with patch("scanner.consent_check.subprocess.run", return_value=_proc(json.dumps(raw))):
            assert _ids(run_consent_check("https://example.com")) == ["consent-enforcement-ok"]

    def test_passes_fast_ids_to_evaluate(self):
        raw = _raw(_phase(), reject=False, accept=False)
        with patch("scanner.consent_check.subprocess.run", return_value=_proc(json.dumps(raw))):
            assert _ids(run_consent_check("https://example.com")) == ["consent-not-required"]
            assert run_consent_check("https://example.com",
                                     fast_ids=frozenset({"tracking-no-consent"})) == []

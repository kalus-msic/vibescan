"""End-to-end tests of the Node consent collector against local fixture pages.

Skipped unless node, Chromium (CHROME_PATH) and puppeteer-core are available.
Local macOS run:
  npm install --prefix scanner/js
  CHROME_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    pytest tests/scanner/test_consent_browser.py
"""
import functools
import http.server
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from scanner.consent_check import CONSENT_SCRIPT, evaluate, run_consent_check

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "consent"


def _browser_available() -> bool:
    if not shutil.which("node"):
        return False
    if not Path(os.environ.get("CHROME_PATH", "/usr/bin/chromium")).exists():
        return False
    probe = subprocess.run(
        ["node", "-e", "require('puppeteer-core')"],
        cwd=CONSENT_SCRIPT.parent, capture_output=True,
    )
    return probe.returncode == 0


pytestmark = [
    pytest.mark.browser,
    pytest.mark.skipif(not _browser_available(), reason="node/chromium/puppeteer-core missing"),
]


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def base_url():
    handler = functools.partial(_QuietHandler, directory=str(FIXTURES))
    # Bind all loopback names so the iframe fixture can use "localhost"
    httpd = http.server.ThreadingHTTPServer(("", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _collect(url: str) -> dict:
    config = json.dumps({"tracking_host_suffixes": ["127.0.0.1"]})
    proc = subprocess.run(
        ["node", str(CONSENT_SCRIPT), url, config],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _names(phase):
    return {c["name"] for c in phase["cookies"]}


def _ids(findings):
    return [f["id"] for f in findings]


def test_good_banner(base_url):
    raw = _collect(f"{base_url}/good.html")
    assert raw["reject_button_found"] and raw["accept_button_found"]
    assert raw["reject_banner_closed"] is True
    assert "_ga" not in _names(raw["baseline"])
    assert "_ga" not in _names(raw["after_reject"])
    assert "_ga" in _names(raw["after_accept"])  # accept ran in a fresh context and worked
    assert _ids(evaluate(raw)) == ["consent-enforcement-ok"]


def test_tracking_before_consent(base_url):
    raw = _collect(f"{base_url}/before_consent.html")
    assert _ids(evaluate(raw)) == ["consent-tracking-before-consent"]


def test_decorative_reject(base_url):
    raw = _collect(f"{base_url}/decorative_reject.html")
    assert _ids(evaluate(raw)) == ["consent-reject-ineffective"]


def test_no_reject_option(base_url):
    raw = _collect(f"{base_url}/no_reject.html")
    assert raw["accept_button_found"] and not raw["reject_button_found"]
    assert raw["after_reject"] is None
    assert _ids(evaluate(raw)) == ["consent-no-reject-option"]


def test_shadow_dom_buttons(base_url):
    raw = _collect(f"{base_url}/shadow.html")
    assert raw["reject_button_found"] and raw["accept_button_found"]
    assert _ids(evaluate(raw)) == ["consent-enforcement-ok"]


def test_late_banner_is_found(base_url):
    raw = _collect(f"{base_url}/late_banner.html")
    assert raw["reject_button_found"] and raw["accept_button_found"]


def test_requests_after_reject_are_recorded(base_url):
    raw = _collect(f"{base_url}/gcs_reject.html")
    assert any("gcs=G111" in u for u in raw["after_reject"]["requests"])
    assert not any("gcs=G111" in u for u in raw["baseline"]["requests"])


def test_unrelated_dialog_is_not_a_banner(base_url):
    raw = _collect(f"{base_url}/unrelated_dialog.html")
    assert not raw["reject_button_found"] and not raw["accept_button_found"]
    assert evaluate(raw) == []


def test_continue_without_accepting_is_reject(base_url):
    raw = _collect(f"{base_url}/without_accepting.html")
    assert raw["reject_button_found"] and raw["accept_button_found"]
    assert raw["reject_banner_closed"] is True
    assert "_ga" not in _names(raw["after_reject"])
    assert _ids(evaluate(raw)) == ["consent-enforcement-ok"]


def test_hidden_reject_is_not_first_layer(base_url):
    raw = _collect(f"{base_url}/hidden_reject.html")
    assert raw["accept_button_found"] and not raw["reject_button_found"]
    assert _ids(evaluate(raw)) == ["consent-no-reject-option"]


def test_cmp_in_cross_site_iframe(base_url):
    raw = _collect(f"{base_url}/iframe_cmp.html")
    assert raw["reject_button_found"] and raw["accept_button_found"]
    assert raw["reject_banner_closed"] is True
    assert raw["after_accept"] is not None


def test_cmp_in_hidden_iframe_is_not_a_banner(base_url):
    raw = _collect(f"{base_url}/hidden_iframe.html")
    assert not raw["reject_button_found"] and not raw["accept_button_found"]
    assert evaluate(raw) == []


def test_unreachable_site_is_fatal_not_crash():
    raw = _collect("http://127.0.0.1:1/")
    assert raw.get("fatal")
    assert evaluate(raw) == []


def test_run_consent_check_end_to_end(base_url):
    findings = run_consent_check(f"{base_url}/decorative_reject.html")
    assert _ids(findings) == ["consent-reject-ineffective"]

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
import time
from pathlib import Path

import pytest

from scanner.consent_check import CONSENT_SCRIPT, evaluate, run_consent_check

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "consent"
SLOW_RESPONSE_SECONDS = 16  # > NAV_TIMEOUT_MS (15 s), < retry timeout (25 s)


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

    def do_GET(self):
        # /slow/<file> answers after SLOW_RESPONSE_SECONDS (navigation retry test)
        if self.path.startswith("/slow/"):
            time.sleep(SLOW_RESPONSE_SECONDS)
            self.path = self.path[len("/slow"):]
        # /status403/<file> answers with HTTP 403 and the file body (F7 status guard test)
        elif self.path.startswith("/status403/"):
            self.path = self.path[len("/status403"):]
            self._send_with_status(403)
            return
        super().do_GET()

    def _send_with_status(self, status_code):
        path = self.translate_path(self.path)
        try:
            with open(path, "rb") as f:
                body = f.read()
        except OSError:
            self.send_error(404)
            return
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _QuietServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass  # the aborted first slow navigation is expected


@pytest.fixture(scope="module")
def base_url():
    handler = functools.partial(_QuietHandler, directory=str(FIXTURES))
    # Bind all loopback names so the iframe fixture can use "localhost"
    httpd = _QuietServer(("", 0), handler)
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


def test_zamitnout_is_reject(base_url):
    raw = _collect(f"{base_url}/zamitnout.html")
    assert raw["reject_button_found"] and raw["accept_button_found"]
    assert raw["reject_banner_closed"] is True
    assert _ids(evaluate(raw)) == ["consent-enforcement-ok"]


def test_disagree_is_reject_not_agree(base_url):
    raw = _collect(f"{base_url}/disagree.html")
    assert raw["reject_button_found"] and raw["accept_button_found"]
    assert raw["reject_banner_closed"] is True
    assert "_ga" not in _names(raw["after_reject"])
    assert "_ga" in _names(raw["after_accept"])  # proves Accept clicked "Agree", not "Disagree"
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


def test_accept_necessary_alt_phrasing_is_reject(base_url):
    """"Přijmout pouze nezbytné" is an accept-with-necessary-only phrasing - it
    must be treated as reject, distinct from the "Přijmout vše" accept button."""
    raw = _collect(f"{base_url}/accept_necessary.html")
    assert raw["reject_button_found"] and raw["accept_button_found"]
    assert raw["reject_banner_closed"] is True
    assert "_ga" not in _names(raw["after_reject"])
    assert "_ga" in _names(raw["after_accept"])
    assert _ids(evaluate(raw)) == ["consent-enforcement-ok"]


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
    assert _ids(evaluate(raw)) == ["consent-not-required"]


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
    assert _ids(evaluate(raw)) == ["consent-not-required"]


def test_unreachable_site_is_fatal_not_crash():
    raw = _collect("http://127.0.0.1:1/")
    assert raw.get("fatal")
    assert evaluate(raw) == []


def test_run_consent_check_end_to_end(base_url):
    findings = run_consent_check(f"{base_url}/decorative_reject.html")
    assert _ids(findings) == ["consent-reject-ineffective"]


NO_BANNER_PAIR = ["consent-tracking-without-banner", "consent-banner-required"]


def test_no_banner_with_tracking_is_critical_pair(base_url):
    raw = _collect(f"{base_url}/no_banner_tracking.html")
    assert not raw["reject_button_found"] and not raw["accept_button_found"]
    assert {"_ga", "_fbp"} <= _names(raw["baseline"])
    assert _ids(evaluate(raw)) == NO_BANNER_PAIR


def test_no_banner_without_tracking_is_not_required(base_url):
    raw = _collect(f"{base_url}/no_banner_clean.html")
    assert _ids(evaluate(raw)) == ["consent-not-required"]


def test_cmp_cookie_without_buttons_is_not_treated_as_no_banner(base_url):
    raw = _collect(f"{base_url}/cmp_cookie_no_buttons.html")
    assert not raw["reject_button_found"] and not raw["accept_button_found"]
    assert _ids(evaluate(raw)) == ["consent-tracking-before-consent"]


def test_navigation_timeout_is_retried(base_url):
    raw = _collect(f"{base_url}/slow/no_banner_tracking.html")
    assert not raw.get("fatal"), raw.get("fatal")
    assert _ids(evaluate(raw)) == NO_BANNER_PAIR


def test_baseline_status_403_blocks_f7(base_url):
    raw = _collect(f"{base_url}/status403/no_banner_clean.html")
    assert raw["baseline_status"] == 403
    assert evaluate(raw) == []


def test_baseline_status_200_is_recorded(base_url):
    raw = _collect(f"{base_url}/no_banner_clean.html")
    assert raw["baseline_status"] == 200
    assert _ids(evaluate(raw)) == ["consent-not-required"]

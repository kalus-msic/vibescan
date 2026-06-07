"""
Kalibrační regresní testy skeneru.

Vychází z empirických skenů 4 referenčních webů (2026-06-04):
- seznam.cz   →  Vibe Score 36/100 (Rizikový)
- csob.cz     →  Vibe Score 14/100 (Rizikový)  ← největší česká banka
- github.com  →  Vibe Score 42/100 (Rizikový)
- mozilla.org →  Vibe Score 64/100 (Průměrný)

Tyhle hodnoty byly nepřiměřeně nízké kvůli několika systematickým
false positives. Každý test níže reprodukuje jeden konkrétní false
positive a uzamyká očekávané chování PO opravě kalibrace.

Bez těchto testů by každá další recalibrace probíhala naslepo.
"""
from unittest.mock import MagicMock, patch

import pytest

from scanner.modules.base import Finding, Severity
from scanner.modules.dns_check import DNSScanner
from scanner.modules.forms import FormScanner
from scanner.modules.headers import HeaderScanner
from scanner.modules.html_check import HTMLScanner
from scanner.modules.secrets import SecretLeakageScanner
from scanner.modules.seo import SEOScanner
from scanner.modules.sri import SRIScanner
from scanner.score import calculate_vibe_score


def _mock_response(text="", headers=None):
    resp = MagicMock()
    resp.text = text
    resp.headers = headers or {}
    return resp


# --------------------------------------------------------------------------
# Fix #1 — Permissions-Policy missing should be INFO, not WARNING
#
# Empirie: žádný ze 4 referenčních webů (seznam, csob, github, mozilla)
# Permissions-Policy nemá. Když to nemá ani 4/4 top webů, není to
# minimální standard — patří do INFO (-2), ne WARNING (-8).
# --------------------------------------------------------------------------

class TestPermissionsPolicySeverity:
    def setup_method(self):
        self.scanner = HeaderScanner()

    def _base(self, **extra):
        h = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
        }
        h.update(extra)
        return h

    def test_missing_permissions_policy_is_info_not_warning(self):
        """Reálné weby (github, mozilla, csob, seznam) ho nemají → INFO."""
        resp = _mock_response(headers=self._base())
        findings = self.scanner.run("https://example.com", resp)
        perm = [f for f in findings if f.id == "missing-permissions"]
        assert len(perm) == 1
        assert perm[0].severity == Severity.INFO, (
            "Permissions-Policy je advanced feature, ne minimální standard. "
            "WARNING (-8) je nepřiměřené, když to nemá ani GitHub/Mozilla."
        )


# --------------------------------------------------------------------------
# Fix #2 — `target="_blank"` bez `rel="noopener"` je obsoletní
#
# Empirie: GitHub má 11 takových odkazů, ČSOB 3. Od r. 2021 ale prohlížeče
# (Chrome, Firefox, Safari) aplikují noopener implicitně. Tento check je
# zastaralý a nepatří už ani jako WARNING, ani jako INFO.
# --------------------------------------------------------------------------

class TestNoopenerObsolete:
    def setup_method(self):
        self.scanner = HTMLScanner()

    def test_target_blank_without_noopener_is_no_longer_flagged(self):
        """Browser default chrání proti reverse tabnabbing od r. 2021."""
        resp = _mock_response(
            '<a href="https://docs.github.com" target="_blank">docs</a>'
            '<a href="https://github.blog" target="_blank">blog</a>'
        )
        findings = self.scanner.run("https://github.com", resp)
        noopener = [f for f in findings if f.id == "missing-noopener"]
        assert len(noopener) == 0, (
            "target=\"_blank\" bez noopener je obsoletní check — moderní "
            "browsery (od 2021) aplikují noopener automaticky. Penalty -8 "
            "WARNING je dnes nezasloužených."
        )


# --------------------------------------------------------------------------
# Fix #3 — Hash-based CSP (sha256/sha384/sha512) je stejně silná jako nonce
#
# Empirie: GitHub používá hash-based CSP. Skener vyžaduje 'nonce-' nebo
# 'strict-dynamic' v CSP, takže SRI findingy dostávají WARNING místo INFO.
# --------------------------------------------------------------------------

class TestHashBasedCSPIsStrong:
    def setup_method(self):
        self.scanner = SRIScanner()

    def test_sha256_csp_treated_as_strong(self):
        """CSP s sha256 hash je stejně silná XSS ochrana jako nonce."""
        resp = _mock_response(
            '<script src="https://cdn.example.com/lib.js"></script>',
            headers={
                "content-security-policy":
                    "script-src 'sha256-AbCdEf1234567890aaaaaaaaaaaaaaaaaaaaaaaaaaaa=' 'self'"
            },
        )
        findings = self.scanner.run("https://mysite.com", resp)
        sri = [f for f in findings if f.id == "missing-sri-script"]
        assert len(sri) == 1
        assert sri[0].severity == Severity.INFO, (
            "Hash-based CSP je silná ochrana — SRI je už jen bonus → INFO."
        )

    def test_sha384_csp_treated_as_strong(self):
        resp = _mock_response(
            '<script src="https://cdn.example.com/lib.js"></script>',
            headers={
                "content-security-policy":
                    "script-src 'sha384-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=' 'self'"
            },
        )
        findings = self.scanner.run("https://mysite.com", resp)
        sri = [f for f in findings if f.id == "missing-sri-script"]
        assert len(sri) == 1
        assert sri[0].severity == Severity.INFO


# --------------------------------------------------------------------------
# Fix #4 — Same-organization subdomains jsou interní, ne external CDN
#
# Empirie:
# - GitHub.com načítá z github.githubassets.com (73× WARNING)
# - Mozilla.org načítá z www.mozilla.org/media/ (9× WARNING)
# - ČSOB.cz načítá z www.csob.cz/o/pui-theme-pw-ng/js/main.js
#
# Skript ze stejné organizace nepotřebuje SRI — organizace má pod kontrolou
# jak hostname, tak deploy pipeline.
# --------------------------------------------------------------------------

class TestSameOrgSubdomainIsInternal:
    def setup_method(self):
        self.scanner = SRIScanner()

    def test_github_assets_subdomain_is_internal(self):
        """github.githubassets.com je vlastní GitHub origin."""
        resp = _mock_response(
            '<script src="https://github.githubassets.com/assets/app.js"></script>'
        )
        findings = self.scanner.run("https://github.com", resp)
        assert len(findings) == 0, (
            "github.githubassets.com je same-org subdoména — nepotřebuje SRI."
        )

    def test_www_subdomain_is_internal(self):
        """example.com a www.example.com jsou stejná organizace."""
        resp = _mock_response(
            '<script src="https://www.mozilla.org/media/js/site.js"></script>'
        )
        findings = self.scanner.run("https://mozilla.org", resp)
        assert len(findings) == 0

    def test_deep_subdomain_is_internal(self):
        """Více úrovní subdomén stejné registrované domény = interní."""
        resp = _mock_response(
            '<script src="https://cdn.assets.example.com/app.js"></script>'
        )
        findings = self.scanner.run("https://www.example.com", resp)
        assert len(findings) == 0


# --------------------------------------------------------------------------
# Fix #5 — Detekce CSRF tokenu mimo whitelisted jména
#
# Empirie: ČSOB má hidden input `<input name="Token" value="vZb1NY2...">`.
# Forms modul ho nepoznal a flagnul "POST formulář bez CSRF ochrany" (-8),
# ZÁROVEŇ secrets modul ho zachytil jako `Token = '...'` (-8). Tj. -16 ze
# stejné věci.
# --------------------------------------------------------------------------

class TestCSRFDetectionExpanded:
    def setup_method(self):
        self.scanner = FormScanner()

    def test_capitalized_token_field_is_csrf(self):
        """Field `Token` (jako u ČSOB) má být uznán jako CSRF token."""
        resp = _mock_response(
            '<form method="POST" action="/submit">'
            '<input type="hidden" name="Token" value="vZb1NY2abcdef123456">'
            '<input type="text" name="data">'
            '</form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 0, (
            "Capitalized `Token` (běžné u Java/Liferay) musí být uznán jako CSRF."
        )

    def test_meta_csrf_token_is_csrf(self):
        """<meta name="csrf-token"> + AJAX form bez hidden = stále chráněný."""
        resp = _mock_response(
            '<html><head>'
            '<meta name="csrf-token" content="abc123def456">'
            '</head><body>'
            '<form method="POST" action="/submit"><input type="text" name="x"></form>'
            '</body></html>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 0, (
            "Rails/Laravel/Django REST pattern: token v <meta>, vkládá ho JS. "
            "Skener má hledat i v <meta name='csrf-token'>."
        )

    def test_xsrf_naming_convention_is_csrf(self):
        """Angular/Express používá XSRF naming."""
        resp = _mock_response(
            '<form method="POST">'
            '<input type="hidden" name="XSRF-TOKEN" value="abc123">'
            '</form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 0


# --------------------------------------------------------------------------
# Fix #6 — Secrets modul nesmí označit CSRF token jako "hardcoded secret"
#
# Empirie: ČSOB má v HTML `Token = 'vZb1NY2...'` (CSRF). Secrets regex
# `(?:password|secret|token|apikey|api_key)\s*[=:]\s*["'][^"']{8,}["']`
# to chytí jako leak (-8) — false positive.
#
# Ironie: stejný web dostal WARNING za chybějící CSRF token, který tam je.
# --------------------------------------------------------------------------

class TestSecretsCSRFFalsePositive:
    def setup_method(self):
        self.scanner = SecretLeakageScanner()

    def test_csrf_token_in_hidden_input_not_flagged(self):
        """Hidden input s názvem Token nemá být označen za leak."""
        resp = _mock_response(
            '<form method="POST">'
            '<input type="hidden" name="Token" value="vZb1NY2abcdefghij">'
            '</form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        leaks = [f for f in findings if f.id == "secret-hardcoded"]
        assert len(leaks) == 0, (
            "CSRF token v hidden input není hardcoded secret — patří tam."
        )

    def test_csrf_meta_tag_not_flagged(self):
        """<meta name="csrf-token" content="..."> není secret."""
        resp = _mock_response(
            '<meta name="csrf-token" content="abcdefghijklmnop12345">'
        )
        findings = self.scanner.run("https://example.com", resp)
        leaks = [f for f in findings if f.id == "secret-hardcoded"]
        assert len(leaks) == 0

    def test_real_hardcoded_password_still_flagged(self):
        """Skutečný leak password = '...' v JS musí pořád být WARNING."""
        resp = _mock_response(
            '<script>const config = { password: "super_secret_123" };</script>'
        )
        findings = self.scanner.run("https://example.com", resp)
        leaks = [f for f in findings if f.id == "secret-hardcoded"]
        assert len(leaks) == 1, (
            "Po opravě nesmí dojít k regresi — reálné leaks musí dál fungovat."
        )


# --------------------------------------------------------------------------
# Fix #7 — DMARC `p=none` se subdoménovou politikou není slabost
#
# Empirie: seznam.cz má `v=DMARC1; p=none; sp=reject; rua=...`. Skener to
# označuje za WARNING (slabá politika). Ale `sp=reject` znamená, že
# subdomény jsou tvrdě chráněné — root `p=none` je vědomá deployment
# strategie pro monitoring před zapnutím enforcement na root.
# --------------------------------------------------------------------------

class TestDMARCSubdomainPolicy:
    def setup_method(self):
        self.scanner = DNSScanner()

    @patch("scanner.modules.dns_check.dns.resolver.resolve")
    def test_dmarc_pnone_with_sp_reject_is_not_warning(self, mock_resolve):
        """seznam.cz pattern: p=none; sp=reject = monitoring + subdomain enforcement."""
        rdata = MagicMock()
        rdata.strings = [b"v=DMARC1; p=none; sp=reject; rua=mailto:abuse@example.cz"]
        mock_resolve.return_value = [rdata]

        finding = self.scanner._check_dmarc("example.cz", is_sub=False)
        assert finding.severity in (Severity.INFO, Severity.OK), (
            "p=none + sp=reject je vědomá strategie. WARNING -8 je nezasloužené."
        )

    @patch("scanner.modules.dns_check.dns.resolver.resolve")
    def test_dmarc_pnone_alone_remains_warning(self, mock_resolve):
        """Samotné p=none bez sp= je pořád slabost."""
        rdata = MagicMock()
        rdata.strings = [b"v=DMARC1; p=none; rua=mailto:abuse@example.cz"]
        mock_resolve.return_value = [rdata]

        finding = self.scanner._check_dmarc("example.cz", is_sub=False)
        assert finding.severity == Severity.WARNING, (
            "Když není sp=reject, p=none je opravdu slabost — neztratit detekci."
        )


# --------------------------------------------------------------------------
# Fix #8 — robots.txt: /.git/ jako URL prefix v multi-segment paths
#
# Empirie: GitHub.com má v robots.txt `Disallow: /.git/`. Skener to chytá
# jako odhalenou cestu k .git adresáři — ale na github.com jsou /.git/
# legitimní URL paths (např. /user/repo/.git/refs/...).
#
# Lepší detekce: cesta musí mířit přímo na server root, ne být zaseknutá
# jako sub-path v URL struktuře aplikace. Můžeme:
#   - vyžadovat přesný match s prefixem hostu nebo
#   - mít list webů, které tohle používají legitimně
#
# Nejjednodušší fix: cesta musí být v "exact" formátu (přesné `/.git`),
# ne s lomítkem za TLD doménou.
# --------------------------------------------------------------------------

class TestRobotsTxtPathDetection:
    def setup_method(self):
        self.scanner = DNSScanner()

    @patch("scanner.modules.dns_check.httpx.get")
    def test_github_pattern_git_in_robots_not_flagged(self, mock_get):
        """github.com má /.git/ jako legitimní URL pattern v repo paths."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = (
            "User-agent: *\n"
            "Disallow: /*/*/blame/*/*\n"
            "Disallow: /.git/\n"
            "Disallow: /commit/*/branch_commits\n"
        )
        mock_get.return_value = resp

        result = self.scanner._check_robots_txt("https://github.com")
        # Když robots.txt vypadá jako URL pattern (obsahuje i wildcardy
        # nebo deep paths), .git/ jako URL prefix nemá generovat WARNING.
        assert result is None or result.severity != Severity.WARNING, (
            "GitHub-style robots.txt s URL patterny — /.git/ je legitimní path."
        )

    @patch("scanner.modules.dns_check.httpx.get")
    def test_admin_path_in_robots_still_flagged(self, mock_get):
        """Reálný `Disallow: /admin` musí stále generovat WARNING."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "User-agent: *\nDisallow: /admin\nDisallow: /backup\n"
        mock_get.return_value = resp

        result = self.scanner._check_robots_txt("https://example.com")
        assert result is not None
        assert result.severity == Severity.WARNING, (
            "Reálné odhalené citlivé cesty se nesmí přestat detekovat."
        )


# --------------------------------------------------------------------------
# Souhrnný "well-secured site" smoke test
#
# Reprezentuje typický top web (jako github.com) — má hash-based CSP,
# all bezpečnostní hlavičky kromě Permissions-Policy a COOP, externí scripty
# na same-org CDN, target=_blank odkazy a meta CSRF token. Po opravách by
# takový web měl skórovat vysoko, ne 42/100.
# --------------------------------------------------------------------------

class TestWellSecuredSiteCalibration:
    """Jednotlivé moduly aplikované na github.com-like fixture."""

    HEADERS = {
        "Content-Security-Policy":
            "script-src 'sha256-AbCdEf1234567890aaaaaaaaaaaaaaaaaaaaaaaaaaaa=' 'self'; default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Frame-Options": "deny",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "origin-when-cross-origin",
    }

    HTML = (
        '<html lang="en"><head>'
        '<meta name="csrf-token" content="abcdef1234567890">'
        '<title>Example secured site</title>'
        '<meta name="description" content="Demo of a well-secured site fixture.">'
        '<link rel="canonical" href="https://example.com">'
        '<meta property="og:title" content="Example">'
        '<meta property="og:description" content="Example">'
        '</head><body>'
        '<a class="skip-link" href="#main">Skip</a>'
        '<h1>Title</h1>'
        '<a href="https://docs.example.com" target="_blank">Docs</a>'
        '<script src="https://assets.example.com/app.js"></script>'
        '<form method="POST" action="/submit"><input type="text" name="x"></form>'
        '<footer>© 2026 Example</footer>'
        '<a href="/privacy">Ochrana osobních údajů</a>'
        '</body></html>'
    )

    def test_headers_module_only_info_findings(self):
        scanner = HeaderScanner()
        resp = _mock_response(self.HTML, headers=self.HEADERS)
        findings = scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert warnings == [], (
            f"Well-secured site by neměl mít HEADER WARNINGs. Má: "
            f"{[f.title for f in warnings]}"
        )

    def test_html_module_clean(self):
        scanner = HTMLScanner()
        resp = _mock_response(self.HTML, headers=self.HEADERS)
        findings = scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert warnings == [], (
            f"HTML modul nesmí dát WARNING na target=_blank ani na čistém HTML. "
            f"Má: {[f.title for f in warnings]}"
        )

    def test_sri_module_at_most_info(self):
        scanner = SRIScanner()
        resp = _mock_response(self.HTML, headers=self.HEADERS)
        findings = scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert warnings == [], (
            f"Hash-based CSP + same-org subdomain → SRI nesmí být WARNING. "
            f"Má: {[f.title for f in warnings]}"
        )

    def test_forms_module_clean_with_meta_csrf(self):
        scanner = FormScanner()
        resp = _mock_response(self.HTML, headers=self.HEADERS)
        findings = scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert warnings == [], (
            f"Form s <meta csrf-token> v hlavičce nesmí dostat CSRF WARNING. "
            f"Má: {[f.title for f in warnings]}"
        )


# --------------------------------------------------------------------------
# Fix #9 — CSRF token v inline JS proměnné
#
# Empirie: ČSOB renderuje CSRF token jako `<script>var Token = 'IqLR4uq...';
# </script>`. Forms scanner ho nepoznal a flagnul "POST formulář bez CSRF"
# (-8). Stejný hashe je v secrets už vyloučen (capitalized Token), ale forms
# o tom nemá info.
# --------------------------------------------------------------------------

class TestCSRFInlineJSDetection:
    def setup_method(self):
        self.scanner = FormScanner()

    def test_var_token_in_script_is_csrf_signal(self):
        """var Token = '...' v <script> má znamenat, že formuláře CSRF mají."""
        resp = _mock_response(
            '<html><head>'
            '<script>var Token = "IqLR4uqAbCdEfGhIjKlMn";</script>'
            '</head><body>'
            '<form method="POST" action="/submit"><input type="text" name="x"></form>'
            '</body></html>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert warnings == [], (
            "JS proměnná `var Token = '...'` musí být uznána jako CSRF signal "
            "(ČSOB pattern)."
        )

    def test_let_csrf_token_in_script(self):
        resp = _mock_response(
            '<script>let csrfToken = "abc123def456ghi789";</script>'
            '<form method="POST"><input type="text" name="x"></form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert warnings == []

    def test_window_csrf_in_script(self):
        resp = _mock_response(
            '<script>window._csrf = "abc123def456ghi789";</script>'
            '<form method="POST"><input type="text" name="x"></form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert warnings == []

    def test_random_js_var_not_csrf_signal(self):
        """Náhodná JS proměnná jako `var x = '...';` nesmí ošálit detekci."""
        resp = _mock_response(
            '<script>var greeting = "Hello world!";</script>'
            '<form method="POST"><input type="text" name="x"></form>'
        )
        findings = self.scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1, (
            "Bez CSRF signálu se MUSÍ flagnout POST form bez tokenu."
        )


# --------------------------------------------------------------------------
# Fix #10 — DYNAMIC_HOSTS rozšířit o recaptcha a Adobe DTM
#
# Empirie: ČSOB načítá:
#   https://www.google.com/recaptcha/api.js
#   https://assets.adobedtm.com/.../launch-*.min.js
# Oba jsou dynamic CDN endpoints, kde SRI prakticky nelze aplikovat
# (parametrizovaný obsah / verze).
# --------------------------------------------------------------------------

class TestDynamicHostsExpansion:
    def setup_method(self):
        self.scanner = SRIScanner()

    def test_recaptcha_is_dynamic(self):
        resp = _mock_response(
            '<script src="https://www.google.com/recaptcha/api.js?render=KEY"></script>'
        )
        findings = self.scanner.run("https://example.cz", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert warnings == [], (
            "Google reCAPTCHA je dynamic CDN — nepotřebuje SRI."
        )

    def test_recaptcha_gstatic_is_dynamic(self):
        resp = _mock_response(
            '<script src="https://www.gstatic.com/recaptcha/releases/abc/recaptcha__cs.js"></script>'
        )
        findings = self.scanner.run("https://example.cz", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert warnings == []

    def test_adobe_dtm_is_dynamic(self):
        resp = _mock_response(
            '<script src="https://assets.adobedtm.com/0e0/35f/launch-abc.min.js"></script>'
        )
        findings = self.scanner.run("https://example.cz", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert warnings == []


# --------------------------------------------------------------------------
# Fix #11 — Per-module penalty cap
#
# Empirie: ČSOB má 1 cookie TS7e63a684029 bez Secure / HttpOnly / SameSite.
# Aktuálně: 3 separátní WARNINGs = -24 bodů za JEDNU cookie. Plus dalších
# 4× cookies bez SameSite (-8) — celkem cookies modul: -32.
#
# Module cap zabrání tomu, aby jediný špatně nastavený detail dominoval
# celkovému skóre.
# --------------------------------------------------------------------------

class TestModulePenaltyCap:
    """Per-category cap se aplikuje i v tier kontextu."""

    def test_cookies_module_capped(self):
        """3× WARNING/cookies → cap 10, security=90, overall=95."""
        findings = [
            Finding(id="c1", title="t1", description="", severity=Severity.WARNING, category="cookies"),
            Finding(id="c2", title="t2", description="", severity=Severity.WARNING, category="cookies"),
            Finding(id="c3", title="t3", description="", severity=Severity.WARNING, category="cookies"),
        ]
        # cookies → security. 3×5=15, cap 10 → security=90. Overall: 0.5×90 + 0.3×100 + 0.2×100 = 95
        score = calculate_vibe_score(findings)
        assert score == 95

    def test_accessibility_info_capped(self):
        """8× INFO/accessibility → cap 5, legal tier (default auto bez statement = legal) → legal=95."""
        findings = [
            Finding(id=f"a{i}", title=f"t{i}", description="", severity=Severity.INFO, category="accessibility")
            for i in range(8)
        ]
        # accessibility → legal. 8×1=8, cap 5 → legal=95. Overall: 0.5×100 + 0.3×95 + 0.2×100 = 98.5 → 98
        score = calculate_vibe_score(findings)
        assert score == 98

    def test_cap_does_not_increase_score(self):
        """1× WARNING/cookies → security=95, overall=98."""
        findings = [
            Finding(id="x1", title="t", description="", severity=Severity.WARNING, category="cookies"),
        ]
        # cookies → security -5 → 95. Overall: 0.5×95 + 0.3×100 + 0.2×100 = 97.5 → 98 (banker's)
        score = calculate_vibe_score(findings)
        assert score == 98

    def test_different_categories_sum_independently(self):
        """3 WARNING v 3 kategoriích — všechny security tier."""
        findings = [
            Finding(id="c1", title="t", description="", severity=Severity.WARNING, category="cookies"),
            Finding(id="h1", title="t", description="", severity=Severity.WARNING, category="headers"),
            Finding(id="s1", title="t", description="", severity=Severity.WARNING, category="sri"),
        ]
        # security: 3×5=15 → 85. Overall: 0.5×85 + 0.3×100 + 0.2×100 = 92.5 → 92 (banker's)
        score = calculate_vibe_score(findings)
        assert score == 92


# --------------------------------------------------------------------------
# Fix #12 — Multiple <h1> není SEO problém
#
# HTML5 spec povoluje multiple h1 v sectioning roots od r. 2014. Google
# potvrdil, že to neovlivňuje SEO. Penalty -2 je cargo cult.
# --------------------------------------------------------------------------

class TestCSRFBroaderDetection:
    """Univerzálnější CSRF token detection (plain assignment, object property)."""

    def test_plain_assignment_token_is_csrf_signal(self):
        """ČSOB: `Token = '...'` bez var/let/const (implicit global)."""
        scanner = FormScanner()
        resp = _mock_response(
            '<script>'
            'jQuery(document).ready(function(){ alert(1); });'
            'Token = "IqLR4uqAbCdEfGhIjKlMn";'
            '</script>'
            '<form method="POST" action="#"><input type="text" name="x"></form>'
        )
        findings = scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert warnings == [], (
            "Plain assignment `Token = '...'` (ČSOB pattern) musí být CSRF signal."
        )

    def test_object_property_token_is_csrf_signal(self):
        """Liferay/AdobeDTM pattern: `liferay.Token: '...'` v config objektu."""
        scanner = FormScanner()
        resp = _mock_response(
            '<script>var config = {'
            '  url: "/api", '
            '  csrfToken: "abc123def456ghi789", '
            '  debug: false'
            '};</script>'
            '<form method="POST" action="/submit"><input type="text" name="x"></form>'
        )
        findings = scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert warnings == [], (
            "Object property `csrfToken: '...'` v config je CSRF signal."
        )

    def test_window_bracket_csrf_is_signal(self):
        """`window['_csrf'] = '...'` pattern (Express, Koa)."""
        scanner = FormScanner()
        resp = _mock_response(
            '<script>window["_csrf"] = "abc123def456ghi789";</script>'
            '<form method="POST"><input type="text" name="x"></form>'
        )
        findings = scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert warnings == []

    def test_random_assignment_not_csrf_signal(self):
        """Univerzální detekce nesmí false-positivovat."""
        scanner = FormScanner()
        resp = _mock_response(
            '<script>greeting = "Hello world this is long enough text";</script>'
            '<form method="POST"><input type="text" name="x"></form>'
        )
        findings = scanner.run("https://example.com", resp)
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1, (
            "Bez CSRF-like identifier se MUSÍ flagnout POST form."
        )


# --------------------------------------------------------------------------
# Fix #13 — České cookie consent UI patterny
#
# Empirie: ČSOB, KB, Seznam — vlastní cookie consent implementace s
# českým textem. Současný detection najde jen Cookiebot/OneTrust/Klaro
# knihovny + známé ID/class konvence. Vlastní české UI nezachytí.
# --------------------------------------------------------------------------

class TestCzechCookieConsent:
    def setup_method(self):
        from scanner.modules.legal import LegalScanner
        self.scanner = LegalScanner()

    def test_souhlas_s_cookies_button(self):
        resp = _mock_response(
            '<html><body>'
            '<div><p>Stránka používá cookies.</p>'
            '<button>Přijmout cookies</button>'
            '<button>Nastavení cookies</button>'
            '</div></body></html>'
        )
        findings = self.scanner.run("https://example.cz", resp)
        missing = [f for f in findings if f.id == "missing-cookie-consent"]
        assert missing == [], (
            "Tlačítko 'Přijmout cookies' v HTML je consent signal."
        )

    def test_spravovat_cookies_link(self):
        resp = _mock_response(
            '<html><body>'
            '<a href="#cookies">Spravovat cookies</a>'
            '</body></html>'
        )
        findings = self.scanner.run("https://example.cz", resp)
        missing = [f for f in findings if f.id == "missing-cookie-consent"]
        assert missing == []

    def test_no_consent_signal_still_flagged(self):
        """Negative — web bez consent textu pořád dostane INFO."""
        resp = _mock_response('<html><body><p>Žádné cookies tu nejsou</p></body></html>')
        findings = self.scanner.run("https://example.cz", resp)
        missing = [f for f in findings if f.id == "missing-cookie-consent"]
        assert len(missing) == 1


class TestMultipleH1NoPenalty:
    def setup_method(self):
        self.scanner = SEOScanner()

    def test_multiple_h1_not_penalized(self):
        """Stránka s více <h1> nesmí dostat INFO penalty."""
        html = (
            '<html><head><title>Test</title>'
            '<meta name="description" content="x">'
            '<link rel="canonical" href="https://x.com">'
            '<meta property="og:title" content="x">'
            '<meta property="og:description" content="x">'
            '</head><body>'
            '<section><h1>Sekce A</h1></section>'
            '<section><h1>Sekce B</h1></section>'
            '</body></html>'
        )
        resp = _mock_response(html)
        findings = self.scanner.run("https://x.com", resp)
        problems = [f for f in findings if f.severity in (Severity.WARNING, Severity.INFO) and "h1" in f.id]
        assert problems == [], (
            f"Multiple <h1> nepenalizovat — HTML5 to povoluje. "
            f"Má: {[f.title for f in problems]}"
        )


# --------------------------------------------------------------------------
# Fix #14 — EAA (zák. 424/2023): eskalace severity pro covered sectors
#
# Od 28.6.2025 jsou banky, e-shopy, doprava, telekom a audiovizuální media
# povinné zveřejnit prohlášení o přístupnosti (zákon č. 424/2023 Sb.,
# implementace European Accessibility Act). Skener má escalovat
# `missing-accessibility-statement` z INFO (-2) na WARNING (-8) pokud HTML
# obsahuje signály těchto sektorů.
# --------------------------------------------------------------------------

class TestEAACoveredSectorEscalation:
    from scanner.modules.accessibility import AccessibilityScanner  # noqa

    def setup_method(self):
        from scanner.modules.accessibility import AccessibilityScanner
        self.scanner = AccessibilityScanner()

    def test_ecommerce_missing_statement_is_warning(self):
        """E-shop bez prohlášení o přístupnosti → WARNING (EAA)."""
        html = (
            '<html lang="cs"><body>'
            '<a href="/kosik">Košík (2)</a>'
            '<button>Přidat do košíku</button>'
            '<span itemtype="https://schema.org/Product">Produkt</span>'
            '</body></html>'
        )
        resp = _mock_response(html)
        findings = self.scanner.run("https://example.cz", resp)
        stmt = [f for f in findings if f.id == "missing-accessibility-statement"]
        assert len(stmt) == 1
        assert stmt[0].severity == Severity.WARNING, (
            "E-shop pod EAA musí mít accessibility statement — WARNING."
        )

    def test_banking_missing_statement_is_warning(self):
        """Banka bez prohlášení → WARNING."""
        html = (
            '<html lang="cs"><body>'
            '<a href="/internetbanking">Internetové bankovnictví</a>'
            '<form><input name="iban" placeholder="IBAN"></form>'
            '<p>Bankovní účet, platba převodem.</p>'
            '</body></html>'
        )
        resp = _mock_response(html)
        findings = self.scanner.run("https://example-bank.cz", resp)
        stmt = [f for f in findings if f.id == "missing-accessibility-statement"]
        assert stmt[0].severity == Severity.WARNING

    def test_public_sector_domain_is_warning(self):
        """Veřejnoprávní (.gov.cz) bez prohlášení → WARNING (zák. 99/2019)."""
        html = '<html lang="cs"><body><p>Úřad obce</p></body></html>'
        resp = _mock_response(html)
        findings = self.scanner.run("https://mesto.gov.cz", resp)
        stmt = [f for f in findings if f.id == "missing-accessibility-statement"]
        assert stmt[0].severity == Severity.WARNING

    def test_marketing_site_missing_statement_is_info(self):
        """Marketing/blog web bez signálů covered sector → zůstává INFO."""
        html = (
            '<html lang="cs"><body>'
            '<h1>Naše SaaS pro B2B klienty</h1>'
            '<p>Kontaktujte nás pro demo.</p>'
            '</body></html>'
        )
        resp = _mock_response(html)
        findings = self.scanner.run("https://saas-b2b.com", resp)
        stmt = [f for f in findings if f.id == "missing-accessibility-statement"]
        assert stmt[0].severity == Severity.INFO, (
            "Marketing/B2B web mimo EAA — penalty zůstává INFO."
        )

    def test_statement_present_no_finding(self):
        """Pokud web statement má, ne flagne — bez ohledu na sector."""
        html = (
            '<html lang="cs"><body>'
            '<a href="/kosik">Košík</a>'
            '<a href="/prohlaseni-o-pristupnosti">Prohlášení o přístupnosti</a>'
            '</body></html>'
        )
        resp = _mock_response(html)
        findings = self.scanner.run("https://eshop.cz", resp)
        missing = [f for f in findings if f.id == "missing-accessibility-statement"]
        assert missing == []


class TestAccessibilityLegalTextUpdated:
    """Text findingu má odkazovat na 424/2023, ne 99/2019."""

    def test_finding_description_mentions_424_2023(self):
        from scanner.modules.accessibility import AccessibilityScanner
        scanner = AccessibilityScanner()
        resp = _mock_response('<html lang="cs"><body></body></html>')
        findings = scanner.run("https://example.com", resp)
        stmt = [f for f in findings if f.id == "missing-accessibility-statement"][0]
        assert "424/2023" in stmt.description, (
            f"Description by měl odkazovat na 424/2023, ne 99/2019. Má: {stmt.description}"
        )

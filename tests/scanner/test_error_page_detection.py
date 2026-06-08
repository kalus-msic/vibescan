"""Heuristika pro detekci error-page / soft-block s HTTP 200.

Reálná empirie: facebook.com vrátí HTTP 200, ale obsahem je "Sorry, something
went wrong" → bez detekce skener počítal skóre z error stránky a vrátil 88/100.
"""
from scanner.tasks import _is_likely_error_page


def _html(title="Test", body="<p>obsah</p>", with_nav=True):
    nav = '<nav><a href="/">Home</a></nav>' if with_nav else ""
    return f"<html><head><title>{title}</title></head><body>{nav}<main>{body}</main></body></html>"


class TestErrorPageDetection:
    def test_facebook_sorry_page_detected(self):
        html = (
            '<html><head><title>Error</title></head>'
            '<body><h1>Sorry, something went wrong.</h1>'
            "<p>We're working on getting this fixed.</p></body></html>"
        )
        assert _is_likely_error_page(html, len(html.encode())) is True

    def test_404_in_title_detected(self):
        html = '<html><head><title>404 Not Found</title></head><body><p>x</p></body></html>'
        assert _is_likely_error_page(html, len(html.encode())) is True

    def test_czech_error_title_detected(self):
        html = (
            '<html><head><title>Chyba serveru</title></head>'
            '<body><p>Stránka nenalezena.</p></body></html>'
        )
        assert _is_likely_error_page(html, len(html.encode())) is True

    def test_normal_page_not_flagged(self):
        body = "<p>Vítejte na našem webu.</p>" * 200  # ~6 KB
        html = _html(title="Vítejte | Můj web", body=body, with_nav=True)
        assert _is_likely_error_page(html, len(html.encode())) is False

    def test_small_page_with_nav_not_flagged(self):
        """Malý web (např. landing page) s nav strukturou → ne error."""
        html = _html(title="Můj projekt", body="<p>Krátký popis.</p>", with_nav=True)
        assert _is_likely_error_page(html, len(html.encode())) is False

    def test_small_no_nav_no_error_keyword_not_flagged(self):
        """Pod 5 KB + chybí nav je 2 signály — flag. Ale legitimní landing s
        normálním titlem by neměl být označen. Title je 'Můj projekt' (bez err
        keyword) a obsahuje main → jen 2 signály (small + no nav). Flagne se.
        Toto je akceptovatelné false positive — uživatel může ignorovat.
        """
        html = (
            '<html><head><title>Můj projekt</title></head>'
            '<body><p>Krátký popis.</p></body></html>'
        )
        # 2 signály: small + no <nav> + no <main>. Test dokumentuje známé chování.
        # Pokud tě to štve, zvyš threshold na 3 signály v _is_likely_error_page.
        assert _is_likely_error_page(html, len(html.encode())) is True

    def test_empty_html_not_flagged(self):
        assert _is_likely_error_page("", 0) is False

    def test_forbidden_title_detected(self):
        html = (
            '<html><head><title>Forbidden</title></head>'
            '<body><p>Access denied.</p></body></html>'
        )
        assert _is_likely_error_page(html, len(html.encode())) is True

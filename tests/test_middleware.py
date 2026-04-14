from django.test import SimpleTestCase, RequestFactory
from vibescan.middleware import SecurityHeadersMiddleware


class TestCSPMiddleware(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = SecurityHeadersMiddleware(lambda req: self._make_response())

    def _make_response(self):
        from django.http import HttpResponse
        return HttpResponse("OK")

    def test_csp_does_not_contain_tailwind_cdn(self):
        request = self.factory.get("/")
        response = self.middleware(request)
        csp = response.get("Content-Security-Policy", "")
        assert "cdn.tailwindcss.com" not in csp

    def test_csp_contains_unsafe_eval_for_alpinejs(self):
        """Alpine.js requires unsafe-eval for x-data expressions."""
        request = self.factory.get("/")
        response = self.middleware(request)
        csp = response.get("Content-Security-Policy", "")
        assert "'unsafe-eval'" in csp

    def test_csp_contains_self_in_script_src(self):
        request = self.factory.get("/")
        response = self.middleware(request)
        csp = response.get("Content-Security-Policy", "")
        assert "script-src 'self'" in csp

    def test_csp_allows_cdn_jsdelivr(self):
        """Alpine.js is loaded from cdn.jsdelivr.net"""
        request = self.factory.get("/")
        response = self.middleware(request)
        csp = response.get("Content-Security-Policy", "")
        assert "https://cdn.jsdelivr.net" in csp

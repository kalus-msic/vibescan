class SecurityHeadersMiddleware:
    """Add security headers not covered by Django's SecurityMiddleware."""

    CSP = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.tailwindcss.com https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Content-Security-Policy"] = self.CSP
        response["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=(), "
            "display-capture=(), accelerometer=(), gyroscope=()"
        )
        return response

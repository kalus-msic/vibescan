class SecurityHeadersMiddleware:
    """Add security headers not covered by Django's SecurityMiddleware."""

    CSP = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdn.jsdelivr.net https://www.googletagmanager.com https://www.google-analytics.com https://tagassistant.google.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://www.googletagmanager.com https://tagassistant.google.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com; "
        "connect-src 'self' https://www.google-analytics.com https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com https://tagassistant.google.com; "
        "frame-src https://www.googletagmanager.com https://tagassistant.google.com; "
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

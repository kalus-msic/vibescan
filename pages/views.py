from django.shortcuts import render

GUIDE_PROMPTS = [
    {
        "title": "HTTP Security Headers",
        "content": "Přidej HTTP security headers: HSTS, CSP bez unsafe-inline, X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy strict-origin-when-cross-origin. Pro Django použij django-csp.",
    },
    {
        "title": "Secrets & .env",
        "content": "Zkontroluj, že žádné API klíče, hesla ani tokeny nejsou hardcoded. Secrets musí být v .env souboru v .gitignore. Vytvoř .env.example s placeholder hodnotami.",
    },
    {
        "title": "CSRF & Forms",
        "content": "Ověř, že všechny formuláře mají CSRF token. V Django musí být {% verbatim %}{% csrf_token %}{% endverbatim %} v každém <form>. Přidej rate limiting na login přes django-ratelimit.",
    },
    {
        "title": "Debug mode & Error pages",
        "content": "Ověř že DEBUG=False v produkci. Nastav vlastní error stránky pro 404 a 500, které neprozrazují stack trace. Přidej ALLOWED_HOSTS a SECURE_HSTS_SECONDS.",
    },
    {
        "title": "SQL Injection prevence",
        "content": "Nikdy nepoužívej string concatenation v SQL dotazech. Vždy používej Django ORM nebo parametrizované dotazy. Prohledej kód na raw() a execute() volání s uživatelskými daty.",
    },
    {
        "title": "Autentizace & Sessions",
        "content": "Session cookies musí mít HttpOnly=True, Secure=True, SameSite=Strict. Přidej session_regenerate po každém přihlášení. Nikdy neberi user ID z URL parametrů — vždy ze session.",
    },
]


def guide(request):
    return render(request, "pages/guide.html", {"prompts": GUIDE_PROMPTS})

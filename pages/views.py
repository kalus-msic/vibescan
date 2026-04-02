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


SCAN_CHECKS = [
    {
        "icon": "lock",
        "title": "HTTP Security Headers",
        "description": "Kontrolujeme přítomnost a správné nastavení bezpečnostních hlaviček: HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy a Permissions-Policy. Chybějící hlavičky jsou nejčastější problém vibecoded projektů — AI je málokdy přidá automaticky.",
    },
    {
        "icon": "shield",
        "title": "SSL & HTTPS",
        "description": "Ověříme, že web běží na HTTPS a správně přesměrovává HTTP požadavky. Bez HTTPS je veškerá komunikace nešifrovaná a zranitelná vůči odposlouchávání.",
    },
    {
        "icon": "dns",
        "title": "DNS záznamy (SPF, DMARC, DKIM)",
        "description": "Kontrolujeme emailové DNS záznamy, které chrání tvou doménu před spoofingem a phishingem. Ověříme SPF, DMARC (včetně síly politiky p=none vs p=reject) a DKIM přes běžné selektory.",
    },
    {
        "icon": "code",
        "title": "HTML analýza",
        "description": "Parsujeme HTML stránky a hledáme typické chyby: odkazy s target=\"_blank\" bez rel=\"noopener\" (reverse tabnabbing útok), HTML komentáře obsahující TODO, hesla, API klíče nebo debug poznámky.",
    },
    {
        "icon": "eye",
        "title": "Tech leakage",
        "description": "Detekujeme prozrazení technologického stacku přes HTTP hlavičky — X-Powered-By, Server verze a podobně. Útočníci tyto informace využívají k cílení známých zranitelností.",
    },
    {
        "icon": "file",
        "title": "security.txt",
        "description": "Kontrolujeme přítomnost souboru security.txt (RFC 9116) na /.well-known/security.txt. Tento soubor říká bezpečnostním výzkumníkům, kam hlásit nalezené zranitelnosti.",
    },
]

SECURITY_CHECKLIST = [
    {
        "category": "Validace vstupů",
        "items": [
            "Validace a sanitizace všech uživatelských vstupů na backendu — nikdy nedůvěřuj datům z frontendu",
            "Validace na frontendu slouží pouze pro UX, ne jako bezpečnostní opatření",
            "Kontrola typů, délky, formátu a povolených hodnot u každého vstupu",
            "Ochrana proti SQL Injection — používej ORM nebo parametrizované dotazy, nikdy string concatenation",
        ],
    },
    {
        "category": "Autentizace a autorizace",
        "items": [
            "IDOR (Insecure Direct Object Reference) — nikdy nebrat ID uživatele z URL parametrů, vždy ze session",
            "Hashování hesel (bcrypt, argon2) — nikdy neukládat plaintext",
            "Session cookies: HttpOnly, Secure, SameSite=Strict",
            "Rate limiting na login a registraci — ochrana proti brute force útokům",
            "Middleware pro ověření autentizace na chráněných routách",
        ],
    },
    {
        "category": "API bezpečnost",
        "items": [
            "Rate limiting na všech API endpointech — ochrana proti DDoS a zneužití",
            "Security a authorization headers na každém requestu",
            "CORS správně nastavený — žádné wildcard (*) v produkci",
            "IP block list pro veřejné API endpointy",
            "Rozlišení CRUD routes vs. server actions — ne všechno patří do API",
            "Limity na velikost souborů při uploadu",
        ],
    },
    {
        "category": "Secrets a konfigurace",
        "items": [
            "API klíče nikdy v klientském kódu (hardcoded) — vždy server-side",
            "Secrets v .env souboru, .env v .gitignore",
            ".env.example s placeholder hodnotami pro tým",
            "DEBUG=False v produkci, vlastní error stránky (404, 500) bez stack trace",
            "Všechny debug logy odstraněné před deployem",
        ],
    },
    {
        "category": "HTTP a transport",
        "items": [
            "Security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options",
            "Security middleware (Django SecurityMiddleware, Helmet pro Node.js)",
            "HTTPS vynucené, HTTP přesměrováno",
            "Secure cookies v produkci",
        ],
    },
    {
        "category": "Automatizované kontroly",
        "items": [
            "Připoj Snyk nebo Semgrep na GitHub repozitář — automatické skeny při každém PR",
            "Projdi OWASP Top 10 a ověř ochranu proti každé zranitelnosti",
            "Minimálně dvě větve (development + main) — nikdy nepushuj rovnou na main",
            "Před každým commitem spusť build a zkontroluj chyby",
        ],
    },
]


def how_it_works(request):
    return render(request, "pages/how_it_works.html", {
        "scan_checks": SCAN_CHECKS,
        "security_checklist": SECURITY_CHECKLIST,
    })

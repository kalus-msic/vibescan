from django.http import HttpResponse
from django.shortcuts import render
from django.utils.safestring import mark_safe
from django.views.decorators.http import require_POST
from django_ratelimit.decorators import ratelimit
from pages.forms import NewsletterForm
from pages.models import Subscriber

LEGAL_LAST_UPDATED = "14. dubna 2025"


SECURITY_TXT = """\
Contact: mailto:vibescan@michaelkalus.cz
Expires: 2027-04-01T00:00:00.000Z
Preferred-Languages: cs, en
Canonical: https://vibescan.cz/.well-known/security.txt
"""

GUIDE_PROMPTS = [
    {
        "id": "http-security-headers",
        "title": "HTTP Security Headers",
        "content": "Přidej HTTP security headers: HSTS, CSP bez unsafe-inline, X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy strict-origin-when-cross-origin. Pro Django použij django-csp.",
    },
    {
        "id": "secrets-env",
        "title": "Secrets & .env",
        "content": "Zkontroluj, že žádné API klíče, hesla ani tokeny nejsou hardcoded. Secrets musí být v .env souboru v .gitignore. Vytvoř .env.example s placeholder hodnotami.",
    },
    {
        "id": "csrf-forms",
        "title": "CSRF & Forms",
        "content": "Ověř, že všechny formuláře mají CSRF token. V Django musí být {% verbatim %}{% csrf_token %}{% endverbatim %} v každém <form>. Přidej rate limiting na login přes django-ratelimit.",
    },
    {
        "id": "debug-error-pages",
        "title": "Debug mode & Error pages",
        "content": "Ověř že DEBUG=False v produkci. Nastav vlastní error stránky pro 404 a 500, které neprozrazují stack trace. Přidej ALLOWED_HOSTS a SECURE_HSTS_SECONDS.",
    },
    {
        "id": "sql-injection",
        "title": "SQL Injection prevence",
        "content": "Nikdy nepoužívej string concatenation v SQL dotazech. Vždy používej Django ORM nebo parametrizované dotazy. Prohledej kód na raw() a execute() volání s uživatelskými daty.",
    },
    {
        "id": "autentizace-sessions",
        "title": "Autentizace & Sessions",
        "content": "Session cookies musí mít HttpOnly=True, Secure=True, SameSite=Strict. Přidej session_regenerate po každém přihlášení. Nikdy neberi user ID z URL parametrů — vždy ze session.",
    },
    {
        "id": "zavislosti-cve",
        "title": "Závislosti & CVE",
        "content": "Zkontroluj závislosti projektu na známé zranitelnosti. Spusť příslušný audit příkaz pro svůj ekosystém:\n\n- Python: pip audit\n- Node.js: npm audit\n- PHP: composer audit\n\nAktualizuj balíčky s Critical a High CVE na opravenou verzi. Pokud aktualizace není možná (breaking changes), ověř zda se zranitelnost týká tvého use-case. Pokud ne, zdokumentuj důvod v komentáři. Nastav automatické kontroly závislostí v CI/CD (Dependabot, Renovate nebo Snyk).",
    },
    {
        "id": "pravni-dokumenty",
        "title": "Právní dokumenty a přístupnost",
        "content": """Vygeneruj právní dokumenty a základní prvky přístupnosti pro můj web:

1. **Cookie consent lišta** — Zobraz lištu se souhlasem s cookies před načtením jakýchkoliv tracking skriptů. Tlačítka "Přijmout" a "Odmítnout" musí mít stejnou vizuální váhu (stejná velikost, stejný styl). Tracking skripty (GA, GTM, Facebook Pixel) se smí načíst až po souhlasu.

2. **Stránka ochrany osobních údajů** — Vytvoř stránku /ochrana-osobnich-udaju/ s informacemi: kdo data zpracovává (název, IČO, adresa, kontakt), jaká data sbíráme, proč a na jakém právním základě (GDPR čl. 6), jak dlouho data uchováváme, práva návštěvníků (přístup, výmaz, přenositelnost, námitka), kontakt na DPO (pokud existuje), odkaz na podání stížnosti u ÚOOÚ.

3. **Patička webu** — V patičce musí být: © rok a název provozovatele, odkaz na ochranu osobních údajů, IČO provozovatele.

4. **Přístupnost** — Přidej odkaz pro přeskočení navigace (<a href="#main" class="sr-only focus:not-sr-only">Přeskočit na obsah</a>) jako první prvek v <body>. V CSS přidej @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; } } pro uživatele s vestibulárními potížemi.

Poznámka: Vygenerované texty jsou šablony — uprav je podle skutečných údajů o provozovateli a zpracování dat.""",
    },
]


SECURITY_BLOCKS = [
    {
        "id": "starter",
        "title": "Starter prompt",
        "subtitle": "Zkopíruj na začátek projektu. Řekni AI jaká pravidla má dodržovat od prvního řádku kódu.",
        "content": """Vytvářím webovou aplikaci. Dodržuj tyto bezpečnostní pravidla od začátku:

1. Všechny secrets (API klíče, hesla, tokeny) patří do .env souboru, nikdy do kódu. Vytvoř .env.example s placeholder hodnotami.
2. Nastav HTTP security headers: HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
3. Nastav CORS — povol pouze konkrétní domény, nikdy wildcard (*) v produkci.
4. Použij security middleware (Django SecurityMiddleware, helmet pro Node.js, Rack::Protection pro Rails).
5. Každý POST formulář musí mít CSRF ochranu.
6. Session cookies: HttpOnly=true, Secure=true, SameSite=Lax. Hesla vždy hashuj (bcrypt/argon2), nikdy neukládej plain text.
7. Žádný debug mód v produkci. Vlastní error stránky pro 404 a 500 — nesmí prozrazovat stack trace. Odstraň debug logy.
8. Vstup od uživatele validuj na frontendu I backendu. Používej ORM nebo parametrizované dotazy — nikdy string concatenation v SQL.
9. API endpointy: každý endpoint musí kontrolovat autentizaci I autorizaci. Nikdy neberi user ID z URL — vždy ze session (prevence IDOR). Odděluj CRUD routy od server actions.
10. Rate limiting na login a citlivé endpointy. Pro veřejné API nastav IP block list proti zneužití.
11. Nastav limity pro upload souborů (velikost, typ, počet). Ověřuj skutečný obsah souboru (magic bytes), nespoléhej jen na příponu nebo MIME typ.
12. HTTPS vždy, HTTP přesměruj na HTTPS.
13. Tracking skripty (Google Analytics, Facebook Pixel) načítej až po souhlasu uživatele (cookie consent).
14. Externí skripty z CDN musí mít integrity atribut (Subresource Integrity) kde je to možné.""",
    },
    {
        "id": "rules-file",
        "title": "Security pravidla pro projekt",
        "subtitle": "Ulož jako CLAUDE.md (Claude Code), .cursorrules (Cursor) nebo do system promptu. AI nástroj je načte automaticky při každé session.",
        "content": """# Security pravidla

## Secrets
- Žádné API klíče, hesla ani tokeny v kódu — vše do .env
- .env musí být v .gitignore
- .env.example obsahuje pouze placeholder hodnoty

## HTTP Security
- Content-Security-Policy: bez unsafe-inline kde je to možné
- Strict-Transport-Security: max-age=31536000; includeSubDomains
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy: camera=(), microphone=(), geolocation=()
- CORS: povol pouze konkrétní domény, nikdy wildcard (*) v produkci

## Middleware
- Použij security middleware svého frameworku (Django SecurityMiddleware, helmet pro Node.js, Rack::Protection pro Rails)

## Formuláře a vstup
- Každý POST formulář má CSRF token
- Uživatelský vstup validuj na frontendu I backendu
- SQL dotazy pouze přes ORM nebo parametrizované dotazy
- Limity pro upload souborů (velikost, typ, počet). Ověřuj obsah (magic bytes), nespoléhej na příponu

## API & autorizace
- Každý endpoint kontroluje autentizaci I autorizaci
- Nikdy nebrat user ID z URL parametrů — vždy ze session (prevence IDOR)
- CRUD routy oddělené od server actions
- Rate limiting + IP block list na veřejné API endpointy

## Cookies, session a hesla
- HttpOnly=true, Secure=true, SameSite=Lax
- Session regenerace po přihlášení
- Hesla hashuj přes bcrypt nebo argon2, nikdy plain text

## Produkce
- DEBUG=false, vlastní error stránky (404, 500)
- ALLOWED_HOSTS nastaveny explicitně
- Odstraň debug logy a console.log

## Před každým commitem
- Zkontroluj, že v kódu nejsou hardcoded secrets
- Zkontroluj, že nové endpointy mají autorizaci""",
    },
    {
        "id": "self-review",
        "title": "Self-review prompt",
        "subtitle": "Zadej poté co AI vygeneruje kód. Výzkum ukazuje, že self-review snižuje zranitelnosti až 10×.",
        "content": """Zkontroluj kód, který jsi právě vygeneroval. Projdi ho z pohledu OWASP Top 10:

1. Jsou všechny vstupy od uživatele validované na frontendu I backendu?
2. Jsou SQL dotazy parametrizované nebo přes ORM (žádná string concatenation)?
3. Jsou formuláře chráněné CSRF tokenem?
4. Nejsou v kódu hardcoded secrets (API klíče, hesla, tokeny)?
5. Jsou error stránky bezpečné (neprozrazují stack trace)? Jsou debug logy odstraněny?
6. Jsou cookies nastaveny s HttpOnly, Secure a SameSite?
7. Jsou hesla hashovaná (bcrypt/argon2), nikdy plain text?
8. Mají endpointy kontrolu autentizace I autorizace? Není možný IDOR (přístup k cizím datům přes ID v URL)?
9. Je rate limiting na citlivých endpointech? Je nastaven CORS?
10. Jsou limity pro upload souborů (velikost, typ)? Je ověřen skutečný obsah (magic bytes)?
11. Je security middleware aktivní?

Pokud najdeš problém, oprav ho a vysvětli co jsi změnil.""",
    },
]


TOOL_CATEGORIES = [
    {
        "id": "no-code",
        "title": "Vizuální buildery (bez kódu)",
        "subtitle": "Ideální pro vizitky, landing pages a jednoduché aplikace. Hosting v ceně, nemusíš řešit server.",
        "tools": [
            {
                "name": "Lovable",
                "url": "lovable.dev",
                "stack": "React + Vite + Tailwind + Supabase",
                "hosting": "V ceně — Lovable Cloud (GCP + Cloudflare), nebo export na GitHub",
                "audience": "Úplní začátečníci, nontechnical founders",
                "price": "Zdarma / od ~$20/měs",
                "security_notes": "Auth přes Supabase (OAuth, email). Row-level security musíš nastavit sám. HTTPS a HSTS automaticky. Na Lovable Cloud nelze nastavit vlastní security headers (CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy) ani přidat security.txt — pro plnou kontrolu exportuj na Netlify/Vercel.",
                "vibescan_limits": [
                    "CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy — nelze nastavit na Lovable Cloud",
                    "security.txt — nelze přidat",
                    "Rate limiting — platformový, nekonfigurovatelný pro tvou aplikaci",
                    "CORS — řeší se kódem přes Supabase Edge Functions",
                ],
                "pros": ["Nejrychlejší cesta od nápadu k fungující aplikaci", "Hosting v ceně", "Supabase integrace pro auth a DB"],
                "cons": ["Pouze React — žádné jiné frameworky", "Backend omezen na Supabase", "Složitější logika je problém"],
            },
            {
                "name": "Bolt",
                "url": "bolt.new",
                "stack": "Node.js (React, Next.js, Astro…) — v prohlížeči",
                "hosting": "Deploy přes Netlify (jedním klikem)",
                "audience": "Začátečníci až středně pokročilí",
                "price": "Zdarma / od ~$20/měs",
                "security_notes": "Žádné automatické zabezpečení. HTTPS přes Netlify automaticky. Security headers, rate limiting, cookie hardening ani security.txt negeneruje — musíš přidat ručně přes Netlify _headers soubor nebo netlify.toml.",
                "vibescan_limits": [
                    "Security headers — negeneruje se; přidej přes Netlify _headers soubor nebo netlify.toml",
                    "security.txt — musíš vytvořit ručně",
                    "Rate limiting — Netlify nenabízí; potřebuješ backend (Edge Functions) nebo externí službu",
                    "Cookie hardening — musíš nastavit v kódu aplikace",
                ],
                "pros": ["Běží v prohlížeči — nic neinstaluješ", "Flexibilnější stack než Lovable", "Podporuje i backend (Express)"],
                "cons": ["WebContainer má omezení (žádné nativní binárky)", "PostgreSQL/Redis složitější", "Velké projekty mohou být pomalé"],
            },
            {
                "name": "v0",
                "url": "v0.dev",
                "stack": "React + Tailwind + shadcn/ui (UI komponenty)",
                "hosting": "Ne — integruje se do Vercel ekosystému",
                "audience": "Vývojáři a designéři pro rychlé prototypování UI",
                "price": "Zdarma / od ~$20/měs",
                "security_notes": "Generuje pouze frontend komponenty — žádný backend, auth ani security. Při deployi na Vercel můžeš nastavit headers přes vercel.json nebo next.config.js, ale v0 to neudělá za tebe.",
                "vibescan_limits": [
                    "Security headers — v0 negeneruje; na Vercelu nastavíš přes vercel.json (headers) nebo next.config.js",
                    "Backend, auth, cookies, rate limiting — v0 neřeší; je to čistě frontend nástroj",
                ],
                "pros": ["Výborné UI komponenty", "Tight integrace s Vercelem a Next.js"],
                "cons": ["Není full-stack builder", "Pouze React/Next.js", "Nevhodné pro kompletní aplikace"],
            },
            {
                "name": "Replit",
                "url": "replit.com",
                "stack": "Libovolný jazyk (Python, Node, Go, Java…)",
                "hosting": "V ceně (Replit Deployments)",
                "audience": "Začátečníci, studenti, prototypování",
                "price": "Zdarma / od ~$25/měs",
                "security_notes": "Replit Secrets pro env vars. Sdílené kontejnery — ne pro produkční bezpečnost. Kód na free tieru může být veřejně viditelný. HTTPS automaticky. Security headers musíš nastavit v kódu aplikace.",
                "vibescan_limits": [
                    "Security headers (CSP, X-Frame-Options, Referrer-Policy…) — musíš nastavit v kódu aplikace",
                    "security.txt — musíš vytvořit ručně v /public nebo servovat přes kód",
                    "Rate limiting — žádný platformový; musíš implementovat v aplikaci",
                    "Cookie hardening — musíš nastavit v kódu",
                    "CORS — musíš nakonfigurovat v kódu serveru",
                ],
                "pros": ["Vše v jednom — editor, běh, deploy", "Podpora mnoha jazyků", "Nejmenší třecí plocha od nápadu k deploy"],
                "cons": ["Výkon omezený (cold starts)", "Nevhodné pro produkci", "Omezené DB možnosti"],
            },
            {
                "name": "Macaly",
                "url": "macaly.com",
                "stack": "React + Tailwind (vizuální builder s AI)",
                "hosting": "V ceně — Macaly hosting (vlastní doména možná na placeném plánu)",
                "audience": "Designéři, nontechnical founders, prototypování",
                "price": "Zdarma / od ~$19/měs",
                "security_notes": "Zaměřeno na design a prototypování. HTTPS automaticky. Platformový hosting bez možnosti nastavit vlastní security headers, security.txt ani server-side logiku. Pro produkční aplikaci exportuj kód a nasaď na vlastní hosting.",
                "vibescan_limits": [
                    "Security headers (CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy) — nelze nastavit na Macaly hostingu",
                    "security.txt — nelze přidat",
                    "Backend, auth, cookies — Macaly je frontend-only; musíš řešit externě",
                    "Rate limiting — žádný; potřebuješ vlastní backend",
                ],
                "pros": ["Vizuální editor s AI — ideální pro design-first přístup", "Export kódu do Reactu", "Rychlé prototypování bez kódování"],
                "cons": ["Pouze frontend — žádný backend ani databáze", "Menší komunita než Lovable/Bolt", "Omezené možnosti pro komplexní aplikace"],
            },
        ],
    },
    {
        "id": "dev-tools",
        "title": "Vývojářské AI nástroje",
        "subtitle": "Plná kontrola nad stackem. Potřebuješ vlastní hosting (VPS, Vercel, AWS…) a základní znalost vývoje.",
        "tools": [
            {
                "name": "Claude Code",
                "url": "claude.ai/claude-code",
                "stack": "Libovolný — pracuje s tvým projektem na disku",
                "hosting": "Žádný — potřebuješ vlastní server/hosting",
                "audience": "Vývojáři kteří chtějí plnou kontrolu",
                "price": "Claude Pro/Max předplatné ($20–$200/měs)",
                "security_notes": "Největší flexibilita — můžeš implementovat cokoliv. Ale nic se neděje automaticky — musíš vědět co chceš.",
                "pros": ["Plná kontrola nad stackem a architekturou", "CLI — pracuje přímo s tvými soubory a gitem", "Nejlepší pro komplexní projekty"],
                "cons": ["Vyžaduje znalost terminálu a deploymentu", "Žádné GUI", "Musíš si zajistit hosting, DB, CI/CD"],
            },
            {
                "name": "Cursor",
                "url": "cursor.com",
                "stack": "Libovolný — VS Code fork s AI",
                "hosting": "Žádný — potřebuješ vlastní hosting",
                "audience": "Vývojáři (začátečníci až pokročilí)",
                "price": "Zdarma / Pro ~$20/měs",
                "security_notes": "Žádné automatické zabezpečení. Kód se odesílá na AI providery — pozor na citlivá data v kódu.",
                "pros": ["Známé VS Code prostředí", "Agent mode pro multi-file editing", "Podpora více AI modelů"],
                "cons": ["Kód se posílá na servery AI providera", "Žádný hosting/deploy", "Agent mode může udělat destruktivní změny"],
            },
            {
                "name": "Windsurf",
                "url": "windsurf.com",
                "stack": "Libovolný — VS Code fork s AI (Codeium/OpenAI)",
                "hosting": "Žádný — potřebuješ vlastní hosting",
                "audience": "Vývojáři",
                "price": "Zdarma / Pro ~$15/měs",
                "security_notes": "Stejné jako Cursor — kód se odesílá na AI providery. Žádné automatické security features.",
                "pros": ["Podobné Cursoru s vlastním agentem (Cascade)", "Levnější Pro plán"],
                "cons": ["Budoucnost nejistá po akvizici OpenAI", "Stejné nevýhody jako Cursor"],
            },
        ],
    },
]


def guide(request):
    return render(request, "pages/guide.html", {
        "prompts": GUIDE_PROMPTS,
        "tool_categories": TOOL_CATEGORIES,
        "security_blocks": SECURITY_BLOCKS,
    })


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
        "id": "sensitive-files",
        "icon": "folder",
        "title": "Citlivé soubory",
        "description": "Kontrolujeme veřejnou dostupnost souborů, které by neměly být přístupné zvenčí. Testujeme pouze existenci (HTTP HEAD, status code) — obsah souborů nečteme.",
        "detail_mono": True,
        "detail_footer": mark_safe(
            'Toto není vyčerpávající seznam — pokrývá nejčastější chyby vibecoded projektů. '
            'Připravujeme aktivní probing těchto souborů pro ověřené weby — '
            '<a href="/roadmap/" class="underline hover:text-slate-600">podívejte se, co chystáme</a>.'
        ),
        "detail_list": [
            ".env — proměnné prostředí (hesla, API klíče, DB credentials)",
            ".env.backup — záloha .env se stejnými secrets",
            ".git/config — konfigurace git repozitáře (umožňuje stáhnout zdrojový kód)",
            ".DS_Store — macOS metadata prozrazující strukturu adresářů",
            "phpinfo.php — verze PHP, cesty, rozšíření, konfigurace serveru",
            "server-status — Apache status page s aktivními requesty a IP klientů",
            "wp-config.php.bak — záloha WordPress konfigurace s DB přístupy",
            ".svn/entries — SVN metadata umožňující stáhnout zdrojový kód",
        ],
    },
    {
        "icon": "file",
        "title": "security.txt",
        "description": "Kontrolujeme přítomnost souboru security.txt (RFC 9116) na /.well-known/security.txt. Tento soubor říká bezpečnostním výzkumníkům, kam hlásit nalezené zranitelnosti.",
    },
    {
        "icon": "accessibility",
        "title": "Základní přístupnost",
        "description": "Kontrolujeme vybrané signály přístupnosti webu: přítomnost odkazu pro přeskočení navigace (skip link) pro uživatele klávesnice a hlasových čteček, a respektování systémového nastavení prefers-reduced-motion pro uživatele s vestibulárními potížemi nebo epilepsií. Pokud tyto prvky nenajdeme, upozorníme — ale doporučujeme ověřit i další stránky webu.",
    },
    {
        "icon": "legal",
        "title": "Právní náležitosti",
        "description": "Hledáme základní právní prvky vyžadované českým a evropským právem: mechanismus pro souhlas s cookies (cookie consent lišta), odkaz na stránku ochrany osobních údajů (GDPR) a copyright v patičce. Nekontrolujeme IČO ani adresu provozovatele — tyto údaje bývají na podstránkách, kam se pasivním skenem nedostaneme. Pokud něco nenajdeme, neznamená to porušení zákona — pouze doporučujeme zkontrolovat.",
    },
    {
        "id": "dependency-check",
        "icon": "package",
        "title": "Kontrola závislostí (CVE)",
        "description": "Vložte obsah souboru se závislostmi a zkontrolujeme každý balíček proti databázi známých zranitelností. Automaticky rozpoznáme formát souboru (requirements.txt, package.json, composer.json), extrahujeme názvy a verze balíčků a dotážeme se OSV.dev API. Pro každou nalezenou zranitelnost zobrazíme identifikátor, závažnost podle CVSS skóre, popis a opravenou verzi — pokud existuje.",
        "detail_list": [
            "Databáze: OSV.dev (osv.dev) — open-source agregátor zranitelností provozovaný Googlem",
            "Zdroje dat: NVD (NIST), GitHub Security Advisories, PyPI Advisory, npm Advisory, RustSec, Go Vulnerability Database a další",
            "Ekosystémy: PyPI (Python), npm (Node.js), Packagist (PHP) — další plánujeme",
            "API: OSV.dev querybatch endpoint — jeden hromadný dotaz na všechny závislosti najednou",
            "Závažnost: CVSS v3 skóre — Critical (≥9.0), High (≥7.0), Medium (≥4.0), Low (<4.0)",
            "Aktuálnost: OSV.dev se aktualizuje průběžně, ale u některých CVE může být zpoždění — datum poslední aktualizace zobrazujeme u výsledků",
            "Omezení: kontrolujeme pouze přímé závislosti s uvedenou verzí — tranzitivní závislosti (sub-dependencies) nezachytíme",
        ],
        "detail_footer": mark_safe(
            'Našli jsme zranitelné balíčky? Podívejte se do '
            '<a href="/guide/#zavislosti-cve" class="underline hover:text-slate-600">průvodce opravami</a> '
            'pro konkrétní kroky jak je aktualizovat.'
        ),
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


REVIEW_STEPS = [
    {
        "title": "1. Secrets & klíče",
        "description": "Najdi přihlašovací údaje, které může kdokoliv s přístupem ke kódu nebo frontendu ukrást.",
        "search_commands": 'grep -r "api_key\\|API_KEY\\|secret\\|SECRET\\|password\\|PASSWORD\\|token\\|TOKEN" --include="*.{js,ts,py,env*,yml,yaml,json}"\ngrep -r "sk-proj-\\|sk_live_\\|AKIA\\|ghp_\\|sb_secret_" --include="*.{js,ts,py,jsx,tsx}"',
        "check_items": [
            "Hardcoded API klíče (Stripe, OpenAI, AWS, Supabase) v kódu",
            "Databázové credentials přímo v source code",
            "JWT secrets, session klíče, encryption klíče",
            "Secrets ve frontend kódu nebo bundlech (viditelné v prohlížeči)",
            "Credentials v komentářích (// TODO: remove test key)",
            "Testovací credentials, které fungují v produkci",
        ],
        "bad_example": 'const OPENAI_API_KEY = "sk-proj-abc123...";\nconst supabase = createClient(URL, "eyJhbGci...");',
        "good_example": "Secrets v .env souboru (v .gitignore)\nPřístup přes process.env / os.getenv()\n.env.example s placeholder hodnotami",
    },
    {
        "title": "2. Autentizace & autorizace",
        "description": "Najdi cesty, jak se přihlásit jako někdo jiný nebo eskalovat na admina.",
        "search_commands": 'grep -r "login\\|signup\\|authenticate\\|session\\|jwt\\|oauth" --include="*.{js,ts,py,rb,php}"\ngrep -r "is_admin\\|isAdmin\\|role\\|permission\\|authorize" --include="*.{js,ts,py,rb,php}"\ngrep -r "cookie\\|session\\|localStorage" --include="*.{js,ts,py}"',
        "check_items": [
            "User ID z URL parametrů místo ze session (IDOR)",
            "Role/admin status z request body bez serverové validace",
            "Autorizace pouze na frontendu (API stále přístupné)",
            "JWT bez expirace nebo bez ověření podpisu",
            "Session cookies bez HttpOnly, Secure, SameSite",
            "Admin routy bez serverové kontroly role",
            "Password reset s predikovatelnými tokeny",
        ],
        "bad_example": '// User ID z URL — útočník ho změní!\napp.get("/api/profile", (req, res) => {\n  const userId = req.query.userId;\n  return db.getProfile(userId);\n});',
        "good_example": "// User ID vždy ze session\napp.get(\"/api/profile\", (req, res) => {\n  const userId = req.session.userId;\n  return db.getProfile(userId);\n});",
    },
    {
        "title": "3. Přístup k cizím datům",
        "description": "Najdi endpointy kde změna ID v URL vrátí data jiného uživatele.",
        "search_commands": 'grep -r "GET.*user\\|profile\\|account\\|order\\|payment" --include="*.{js,ts,py,rb,php}"\ngrep -r "WHERE.*user\\|filter.*user\\|findOne\\|findById" --include="*.{js,ts,py,rb,php}"\nfind . -name "*resolvers*" -o -name "*schema*"',
        "check_items": [
            "API routy přijímající record ID bez kontroly vlastnictví",
            "ORM dotazy filtrující jen podle ID, ne podle přihlášeného uživatele",
            "List endpointy bez filtrování na aktuálního uživatele",
            "GraphQL resolvery bez ownership kontroly",
            "Veřejné endpointy vracející citlivá data (PII, finance, zdraví)",
        ],
        "bad_example": '# Vrací JAKOUKOLIV objednávku, ne jen uživatelovu!\n@app.get("/api/orders/{order_id}")\ndef get_order(order_id):\n    return db.query(Order).filter(Order.id == order_id).first()',
        "good_example": '# Ověří vlastnictví záznamu\n@app.get("/api/orders/{order_id}")\ndef get_order(order_id, user=Depends(get_current_user)):\n    return db.query(Order).filter(\n        Order.id == order_id,\n        Order.user_id == user.id\n    ).first()',
    },
    {
        "title": "4. Injection & spuštění kódu",
        "description": "Najdi SQL injection, XSS, prompt injection a RCE zranitelnosti.",
        "search_commands": 'grep -r "SELECT.*+\\|query.*%.*s\\|execute.*format\\|raw.*sql" --include="*.{js,ts,py,rb,php}"\ngrep -r "innerHTML\\|dangerouslySetInnerHTML\\|html.*safe\\|raw.*html" --include="*.{js,ts,jsx,tsx,py,rb}"\ngrep -r "eval\\|exec\\|system\\|popen\\|subprocess\\|spawn" --include="*.{js,ts,py,rb,php}"\ngrep -r "openai\\|anthropic\\|completion\\|prompt\\|llm" --include="*.{js,ts,py}"',
        "check_items": [
            "String concatenation v SQL dotazech (f-stringy, template literals)",
            ".raw() nebo .execute() s user inputem",
            "innerHTML, dangerouslySetInnerHTML s uživatelskými daty",
            "Template filtry |safe nebo |raw na user obsahu",
            "eval(), exec(), Function() s uživatelským vstupem",
            "subprocess/shell commands s user inputem",
            "Uživatelský vstup v system promptech LLM (prompt injection)",
            "Unsafe deserializace (pickle, unserialize, yaml.load)",
        ],
        "bad_example": '# SQL injection\nquery = f"SELECT * FROM users WHERE name = \'{username}\'"\n\n# XSS\nelement.innerHTML = userInput\n\n# RCE\nos.system(f"convert {user_filename} output.jpg")',
        "good_example": "# Parametrizované dotazy\ndb.execute(\"SELECT * FROM users WHERE name = %s\", (username,))\n\n# Bezpečný text\nelement.textContent = userInput\n\n# Bez shell injection\nsubprocess.run(['convert', user_filename, 'output.jpg'])",
    },
    {
        "title": "5. Upload souborů",
        "description": "Najdi možnosti uploadu vedoucí ke spuštění kódu nebo XSS.",
        "search_commands": 'grep -r "upload\\|multer\\|formidable\\|FileStorage\\|multipart" --include="*.{js,ts,py,rb,php}"\ngrep -r "ImageMagick\\|PIL\\|sharp\\|ffmpeg" --include="*.{js,ts,py}"\ngrep -r "s3\\|blob\\|storage\\|bucket" --include="*.{js,ts,py,rb,php}"',
        "check_items": [
            "Žádná validace typu souboru (přijímá .php, .exe, .sh)",
            "Validace pouze na frontendu (obejitelná)",
            "Soubory uložené v executable adresáři",
            "Originální názvy souborů (directory traversal: ../../../etc/passwd)",
            "Žádné limity velikosti (DoS přes obrovské soubory)",
            "Chybí ověření obsahu (magic bytes) — spoléhání jen na příponu",
        ],
        "bad_example": '// Žádná validace — útočník uploadne shell.php\napp.post("/upload", upload.single("file"), (req, res) => {\n  fs.writeFileSync(`./public/${file.originalname}`, file.buffer);\n});',
        "good_example": "Allowlist přípon: ['.jpg', '.png', '.pdf']\nOvěření obsahu přes magic bytes\nPřejmenování na UUID\nUložení mimo web root nebo cloud storage\nLimity velikosti",
    },
    {
        "title": "6. Test vs. produkce",
        "description": "Najdi testovací backdoory a debug funkce ponechané v produkci.",
        "search_commands": 'grep -r "NODE_ENV\\|DEBUG\\|ENVIRONMENT" --include="*.{js,ts,py,env*,yml}"\ngrep -r "test.*user\\|admin.*test\\|debug\\|FIXME\\|TODO.*production" --include="*.{js,ts,py,rb,php}"\nls -la *.env* config/*.yml docker-compose*.yml',
        "check_items": [
            "Testovací účty fungující v produkci (admin@test.com / test123)",
            "Debug mode zapnutý (stack traces, SQL dotazy viditelné)",
            "Debug routy nebo flagy aktivní v produkci",
            "Verbose error messages prozrazující internals",
            "Mock authentication bypass stále aktivní",
            "Logování citlivých dat (hesla, tokeny, PII)",
        ],
        "bad_example": '# Backdoor účet fungující v produkci!\nif username == "admin@test.com" and password == "test123":\n    return create_admin_session()\n\n# Debug mode vždy zapnutý\nDEBUG = True',
        "good_example": "DEBUG řízený env proměnnou (False v produkci)\nVlastní error stránky bez stack traces\nŽádné testovací credentials v kódu\nSeparátní DB pro test a produkci",
    },
    {
        "title": "7. Základní hygiena",
        "description": "Zkontroluj security headers, CORS, rate limiting a HTTPS.",
        "search_commands": 'grep -r "cors\\|CORS\\|helmet\\|security.*header" --include="*.{js,ts,py,rb,php}"\ngrep -r "rate.*limit\\|throttle\\|ratelimit" --include="*.{js,ts,py,rb,php}"\ngrep -r "https\\|ssl\\|tls\\|cert" --include="*.{js,ts,py,yml,yaml}"',
        "check_items": [
            "CORS: Access-Control-Allow-Origin: * s credentials",
            "Chybí CSRF ochrana na state-changing operacích",
            "Login endpoint bez rate limitingu (brute force)",
            "HTTP místo HTTPS v produkci",
            "Chybí security headers (CSP, X-Frame-Options, HSTS)",
            "Chybí security middleware (helmet, SecurityMiddleware)",
        ],
        "bad_example": '// Wide-open CORS\napp.use(cors({ origin: "*", credentials: true }));\n\n// Login bez rate limitingu\napp.post("/login", (req, res) => {\n  checkPassword(req.body.username, req.body.password);\n});',
        "good_example": "CORS: pouze konkrétní domény\nCSRF tokeny na formulářích\nRate limiting na auth endpointech\nSecurity middleware (helmet / SecurityMiddleware)\nHTTPS vynucené",
    },
]


def review(request):
    return render(request, "pages/review.html", {
        "steps": REVIEW_STEPS,
    })


def security_txt(request):
    return HttpResponse(SECURITY_TXT, content_type="text/plain")


def how_it_works(request):
    return render(request, "pages/how_it_works.html", {
        "scan_checks": SCAN_CHECKS,
        "security_checklist": SECURITY_CHECKLIST,
    })


ROADMAP_ITEMS = [
    {
        "label": "Brzy",
        "color": "blue",
        "items": [
            {
                "title": "Registrace a uživatelské účty",
                "description": "Přihlášení, historie skenů a správa projektů na jednom místě.",
            },
            {
                "title": "Vlastní projekty",
                "description": "Přehled závislostí a bezpečnostního stavu vašich projektů.",
            },
            {
                "title": "Automatické hlídání závislostí",
                "description": "Pravidelná kontrola zranitelností (denně, týdně nebo měsíčně) s email notifikací při nalezení nového CVE.",
            },
        ],
    },
    {
        "label": "Připravujeme",
        "color": "violet",
        "items": [
            {
                "title": "Ověření vlastnictví webu",
                "description": "DNS TXT záznam nebo upload souboru — odemkne aktivní bezpečnostní kontroly.",
            },
            {
                "title": "Aktivní probing citlivých souborů",
                "description": "Kontrola dostupnosti .env, .git/config, phpinfo.php, wp-config.php.bak a dalších souborů, které nemají být veřejné.",
            },
            {
                "title": "Hloubkový audit JS bundlů",
                "description": "Analýza JavaScript souborů na hardcoded API klíče, tokeny a secrets.",
            },
            {
                "title": "Dashboard",
                "description": "Přehled všech skenovaných webů a jejich bezpečnostního stavu na jednom místě.",
            },
        ],
    },
    {
        "label": "Na horizontu",
        "color": "slate",
        "items": [
            {
                "title": "Porovnání skenů",
                "description": "Diff view — co se zlepšilo a co zhoršilo mezi dvěma skeny.",
            },
            {
                "title": "Multi-page scan",
                "description": "Kontrola více URL na jedné doméně najednou.",
            },
        ],
    },
]


def roadmap(request):
    return render(request, "pages/roadmap.html", {
        "roadmap_items": ROADMAP_ITEMS,
        "newsletter_form": NewsletterForm(),
    })


@require_POST
@ratelimit(key="ip", rate="10/h")
def subscribe(request):
    form = NewsletterForm(request.POST)
    if form.is_valid():
        email = form.cleaned_data["email"]
        Subscriber.objects.get_or_create(email=email)
        return render(request, "pages/partials/subscribe_success.html")
    return render(request, "pages/partials/subscribe_error.html", {"form": form})


def privacy(request):
    return render(request, "pages/privacy.html", {"last_updated": LEGAL_LAST_UPDATED})


def terms(request):
    return render(request, "pages/terms.html", {"last_updated": LEGAL_LAST_UPDATED})

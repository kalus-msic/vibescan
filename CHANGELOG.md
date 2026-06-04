# Changelog

## v1.2.0 (2026-06-04)

### Scanner — rekalibrace skoringu
Empirický test skeneru proti referenčním webům (seznam.cz, csob.cz, github.com, mozilla.org, kb.cz, idnes.cz, csfd.cz) odhalil systematické false positives. Iterativní opravy:

- **Severity recalibrace:** Permissions-Policy WARNING → INFO (žádný ref. web ho nemá), multiple `<h1>` → OK (HTML5 spec povoluje od 2014), odstraněn obsoletní `target="_blank"` bez `noopener` check (prohlížeče aplikují implicitně od 2021), odstraněn copyright notice check (autorské právo vzniká automaticky — Bernská úmluva, AutZ 121/2000 § 9)
- **CSP & SRI:** uznání hash-based CSP (`sha256-/sha384-/sha512-`) jako strong XSS ochrany; rozšířený `DYNAMIC_HOSTS` o reCAPTCHA, Adobe DTM, HubSpot, Heap, Cloudflare Insights, TikTok, Bing, Yandex, Hotjar; detekce same-org asset domains (`github.com` ↔ `github.githubassets.com` přes suffix patterny assets/cdn/static/media)
- **CSRF detection:** detekce CSRF tokenu v inline JS proměnných (`var Token = '...'`, `let csrfToken = '...'`, `window['_csrf'] = '...'`, object properties `csrfToken: '...'`), `<meta name="csrf-token">` (Rails/Laravel pattern); rozšířený seznam CSRF input jmen + substring detekce (csrf/xsrf/_token/nonce)
- **Cookies & legal:** detekce českého cookie consent UI — text patterny „Přijmout cookies", „Nastavení cookies", „Spravovat cookies", „Souhlas s cookies", „Nastavení soukromí" v `<button>`/`<a>`
- **DNS:** DMARC `p=none + sp=reject/quarantine` rozpoznán jako vědomá strategie (monitoring root, enforcement subdomény) — sníženo z WARNING na INFO; robots.txt s URL pattern wildcardy používá strict-match (řeší false positive `/.git/` na GitHub)
- **Secrets:** CSRF tokeny v hidden inputech, `<meta>` a inline JS jsou vyloučeny z generic secret detekce (řešilo false positive na ČSOB)
- **Per-module penalty cap:** score formula aplikuje max penalty per kategorie (cookies max -16, accessibility max -8, sri max -10, …) — brání tomu, aby jediný špatně nastavený detail (např. cookie bez 3 flagů) dominoval celkovému skóre
- **Forms findings agregace:** N findingů „POST bez CSRF" sloučeno do jednoho s počtem (jako už cookies/sri)

### Accessibility — zákon 424/2023 (EAA)
- Detekce „covered sector" signálů v HTML: e-commerce („Košík", schema.org/Product), banking („IBAN", „internetbanking"), doprava („jízdenka"), veřejnoprávní domény (.gov.cz, .justice.cz, policie.cz, army.cz)
- Eskalace `missing-accessibility-statement` z INFO (-2) na WARNING (-8) pro covered sectors
- Aktualizován text findingu i `/guide/` s odkazy na zákon č. 424/2023 Sb. (implementace European Accessibility Act, platnost od 28.6.2025) a požadavky WCAG 2.2

### Bot challenge detection
- Detekce typických challenge stránek (Cloudflare, Akamai, Imperva, PerimeterX, DDoS-Guard) podle title patternů a body markerů (`/cdn-cgi/challenge-platform/`, `px-captcha`, `akamai-bot-manager`, …)
- Místo počítání falešného skóre z challenge stránky vrátí explicitní chybu „Cílový web vrátil bot challenge"
- Realistický User-Agent (Mozilla/Chrome compatible) místo holého `Vibescan/1.0` — snižuje false-block ratio na webech s WAF

### UX
- „Celková penalizace" v reportech a exportech odpovídá zobrazenému skóre (100 − vibe_score) — dříve ignorovala module caps a vznikal mismatch
- Forms findings agregované do jednoho per-page findingu (místo N samostatných stejných)
- Cookie banner buttons s rovnocennou vizuální váhou (dark pattern fix)

### Infrastruktura
- Refactor: nginx → Caddy s production compose override
- README rozšířen o přehled Docker Compose služeb

### Bugfixes
- CSP a CORS opraveny pro GA4 / Tag Assistant (`crossOrigin` atribut způsoboval CORS block)
- Switch z GTM na direct GA4 gtag.js (řeší ORB blocking)
- YAML folded scalar indentation v `web` command

### Tests
- Nový `tests/scanner/test_calibration.py` — 60 regresních testů založených na empirických scanech referenčních webů (calibration safety net pro budoucí změny)
- Test suite: 226 passed, 0 fail

## v1.1.0 (2026-04-17)

### Scanner
- Google API Key (AIzaSy) preklasifikovan z CRITICAL (-20) na WARNING (-8) — tyto klice jsou zamerne verejne a chranene pres API restrictions
- Prejmenovano z "Firebase API Key" na "Google API Key" — format je spolecny pro vsechny Google sluzby (Firebase, YouTube, Maps aj.)
- Duplicitni nalezy stejneho typu se nyni seskupuji do jednoho findingu s poctem (napr. "Google API Key nalezen v HTML (5×)") misto samostatnych penalizaci za kazdy vyskyt

## v1.0.0 (2026-04-15)

Prvni verejna verze Vibescan.cz.

### Scanner
- 14 bezpecnostnich a SEO kontrol: headers, SSL, DNS, cookies, secrets, CSRF, SRI, meta tagy, CORS, tracking, pristupnost, pravni nalezitosti, HTML analyza, SEO zaklady
- Vibe Score 0-100 s penalizacemi podle zavaznosti (critical -20, warning -8, info -2)
- Moznost zamitnout nalezy jako nerelevantni (false positive, resim jinak, nepouzivam)
- Prepocet skore po zamitnuti nalezu

### Export
- PDF export pres WeasyPrint
- TXT export (Markdown) optimalizovany pro vlozeni do AI nastroju
- Tlacitko "Kopirovat pro AI" u exportu zavislosti

### Pruvodce (/guide/)
- Prehled AI nastroju a jejich bezpecnostnich omezeni
- Starter prompt, security pravidla, self-review prompt
- 14 granularnich promptu pro konkretni oblasti (headers, cookies, DNS, SSL, SRI, HTML, meta, SEO, logovani, pravni dokumenty, zavislosti, CSRF, secrets, sessions)
- Kazdy scan finding odkazuje na konkretni sekci pruvodce

### Kontrola zavislosti (/dependencies/)
- Kontrola requirements.txt, package.json, composer.json proti znamym CVE
- Tlacitko "Kopirovat pro AI" pro export vysledku

### Infrastruktura
- Django 6 / PostgreSQL 16 / Redis 7 / Celery 5.4
- Docker Compose s Nginx, Gunicorn, Celery workerem
- HTMX polling pro realtime progress
- Alpine.js pro interaktivni prvky
- Tailwind CSS (standalone CLI build)
- WhiteNoise pro staticke soubory
- SSRF ochrana, rate limiting, CSP, HSTS
- Podpora Nginx Proxy Manager (reverse proxy)

### Dalsi
- Ceska lokalizace
- Cookie consent lista s podporou GTM
- Responsivni design s mobilnim hamburger menu
- SVG favicon
- SEO meta tagy (Open Graph, canonical, description)
- Custom error stranky (403, 404, 429, 500)
- Django admin s registraci ScanResult a Subscriber

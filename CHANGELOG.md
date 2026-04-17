# Changelog

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

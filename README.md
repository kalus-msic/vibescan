# Vibescan

Open-source web security scanner pro projekty postavene s AI nastroji (Cursor, Lovable, Bolt, Claude Code, Windsurf...) i bez nich.

Zadej URL, Vibescan behem par sekund zkontroluje 14 bezpecnostnich oblasti a vrati "vibe score" (0-100) s konkretnimi navrhy co opravit.

**[vibescan.cz](https://vibescan.cz)**

## Co kontrolujeme

| Oblast | Popis |
|--------|-------|
| HTTP Security Headers | CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| SSL & HTTPS | HTTPS redirect, certifikat |
| DNS & emaily | SPF, DMARC, DKIM, CAA, DNSSEC, security.txt |
| HTML analyza | `target="_blank"` bez `rel="noopener"`, citlive HTML komentare |
| Subresource Integrity | SRI na externich scriptech a stylech |
| Secrets & env | Hardcoded API klice, hesla, tokeny ve zdrojovem kodu |
| CSRF & formulare | CSRF tokeny ve formularich |
| Cookies | HttpOnly, Secure, SameSite atributy |
| Meta tagy | Generator verze (information disclosure) |
| CORS | Wildcard origin, chybejici Vary header |
| Tracking & consent | Tracking skripty bez cookie consent |
| Pravni & pristupnost | Cookie consent lista, ochrana osobnich udaju, copyright, skip link |
| Pristupnost | Alt atributy, html lang, form labels, heading hierarchy |
| SEO zaklady | Title, meta description, canonical, Open Graph, h1 |

## Stack

- **Backend:** Django 6 / PostgreSQL 16 / Redis 7 / Celery 5.4
- **Frontend:** HTMX + Alpine.js + Tailwind CSS
- **Infra:** Docker Compose / Gunicorn / Caddy / WhiteNoise
- **Export:** PDF (WeasyPrint) a TXT (Markdown pro AI)

## Spusteni

```bash
cp .env.example .env
# uprav .env (SECRET_KEY, DB_PASSWORD, REDIS_PASSWORD, ...)
docker-compose up --build
```

Aplikace bezi na `http://localhost:9003`.

### Docker Compose sluzby

| Sluzba | Obraz | Popis |
|--------|-------|-------|
| **db** | postgres:16-alpine | PostgreSQL databaze |
| **redis** | redis:7-alpine | Message broker pro Celery |
| **web** | vlastni build | Django + Gunicorn (migrace + superuser pri startu) |
| **celery** | vlastni build | Celery worker — zpracovava skeny asynchronne |
| **caddy** | caddy:2-alpine | Reverse proxy, servuje statiku, naslouchá na :9003 |

`web` a `celery` sdili stejny Docker image. Pri startu `web` automaticky spusti migrace a vytvori admin ucet (z `.env`).

### Produkcni nasazeni s externi Caddy

Na VPS, kde uz mas Caddy na hostu (servuje vic aplikaci a resi HTTPS),
pouzij `docker-compose.prod.yml` override. Vypne interni Caddy, prida DB
tuning a pripoji `web` na externi Docker sit, kterou sdilis s host Caddy.

```bash
# Jednorazove
docker network create web

# Pri kazdem deployi
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

V host Caddyfile pak nasmeruj domenu na vibescan_web:8000 pres sdilenou sit:

```caddyfile
vibescan.cz {
    handle_path /static/* {
        root * /srv/projects/vibescan/static_volume
        file_server
    }
    reverse_proxy vibescan-web-1:8000
}
```

Pozn.: nazev kontejneru (`vibescan-web-1`) si overit pres `docker ps`.

## Vibe Score

Vazeny prumer tri kategorii skore (0–100):

| Kategorie | Vaha | Co obsahuje |
|-----------|-----:|-------------|
| **Bezpecnost** | 50 % | headers, cookies, dns, forms, tech, cors, sri, secrets, ssl_check, tracking, html, best-practices (Lighthouse) |
| **Pravni** | 30 % | legal (cookie consent, GDPR), accessibility *pro covered sectors EAA — banky, e-shopy, audiovizualni media, doprava, telekom; jinak SEO* |
| **SEO a vykon** | 20 % | seo, meta, performance (Lighthouse), accessibility pro non-covered sectors |

Celkove skore = `0.5 × Bezpecnost + 0.3 × Pravni + 0.2 × SEO`, zaokrouhleno.

### Vypocet skore tieru

1. **Severity → penalizace:**

   | Zavaznost | Penalizace |
   |-----------|-----------:|
   | CRITICAL | -12 bodu |
   | WARNING | -5 bodu |
   | INFO | -1 bod |
   | OK | 0 |

2. **Per-category cap** (jen accessibility a performance — Lighthouse casto generuje vice findings z jednoho root cause):

   | Kategorie | Cap |
   |-----------|----:|
   | accessibility | 25 |
   | performance | 25 |

   Ostatni kategorie cap nemaji — surovy soucet severit jde rovnou do tier total.

3. **Floor per tier:** zadny tier nespadne pod **30/100**. Chrani proti psychologicky kontraproduktivnimu 0/100 u Lighthouse-heavy webu.

   `tier_score = max(30, 100 − sum_capped_penalties)`

### Pristupnost: dynamicke routovani

Web spadajici pod **zakon c. 424/2023 Sb.** (implementace European Accessibility Act, platnost od 28.6.2025) musi mit prohlaseni o pristupnosti — sektory banky, e-shopy, doprava, telekom, audiovizualni media + organy verejne moci (zak. 99/2019 Sb.).

- Detekce: pokud `missing-accessibility-statement` ma severity WARNING (= covered sector), accessibility findings padnou do **Pravniho** tieru.
- Jinak (severity INFO) padnou do **SEO + vykon** tieru.
- Uzivatel muze rucne preklasifikovat scan: „spada pod zakon" / „nespada pod zakon" / „automaticky".

### Dismiss findings

Uzivatel muze oznacit nalez jako nerelevantni (`not_applicable`, `solved_differently`, `false_positive`, `other`). Dismissed findings se vyjmou z vypoctu a tier skore se prepocita.

### Lighthouse deep scan

Po fast scan se spousti `lighthouse` CLI proti URL. Vysledky se mapuji na Vibescan findings pres `LIGHTHOUSE_AUDIT_MAP` (allowlist ~30 auditu). Audity, ktere `supersedes_id` jiny finding, prepisuji puvodni nalez (napr. `lh-document-title` nahradi `missing-title` z `seo.py`).

Per-audit `max_severity` stropy nektere audity (heading-order, html-lang-valid, aria-valid-attr-value) — Lighthouse je oznacuje binarne 0/1, ale realne jsou „moderate" impact, ne blocker.

### Detekce error-page

Pokud cilovy server vrati HTTP 200, ale obsah vypada jako chybova stranka (title obsahuje error/4xx/sorry, body markery, < 5 KB, chybi `<nav>`/`<main>`), ulozi se `scan_warning` a UI zobrazi amber banner. Skore se pocita dal — uzivatel sam posoudi.

### Bot challenge

Pokud server vrati Cloudflare/Akamai/Imperva/PerimeterX challenge, scan skonci jako FAILED s vysvetlujici hlaskou. Falesne skore z challenge stranky tak neprosakne.

## Pruvodce zabezpecenim

Na [vibescan.cz/guide/](https://vibescan.cz/guide/) najdes:

- Prehled AI nastroju a jejich bezpecnostnich omezeni
- Copy-paste prompty pro zabezpeceni projektu od zacatku
- Granularni prompty pro konkretni oblasti (headers, cookies, DNS, ...)

## Kontrola zavislosti

Primo na [vibescan.cz](https://vibescan.cz/) vloz obsah `requirements.txt`, `package.json` nebo `composer.json` — Vibescan zkontroluje zname CVE a navrhne opravene verze.

## Licence

MIT

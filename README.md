# Vibescan

Open-source web security scanner pro projekty postavene s AI nastroji (Cursor, Lovable, Bolt, Claude Code, Windsurf...) i bez nich.

Zadej URL, Vibescan behem par sekund zkontroluje 12 bezpecnostnich oblasti a vrati "vibe score" (0-100) s konkretnimi navrhy co opravit.

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

## Stack

- **Backend:** Django 6 / PostgreSQL 16 / Redis 7 / Celery 5.4
- **Frontend:** HTMX + Alpine.js + Tailwind CSS
- **Infra:** Docker Compose / Gunicorn / Nginx / WhiteNoise
- **Export:** PDF (WeasyPrint) a TXT (Markdown pro AI)

## Spusteni

```bash
cp .env.example .env
# uprav .env (SECRET_KEY, DB_PASSWORD, ...)
docker-compose up --build
```

Aplikace bezi na `http://localhost`.

## Vibe Score

Score = 100 minus penalizace za nalezene problemy:

| Zavaznost | Penalizace |
|-----------|------------|
| CRITICAL | -20 bodu |
| WARNING | -8 bodu |
| INFO | -2 body |
| OK | 0 |

Uzivatel muze zamitnou nalezeni jako nerelevantni (false positive, resim jinak, ...) — score se prepocita.

## Pruvodce zabezpecenim

Na [vibescan.cz/guide/](https://vibescan.cz/guide/) najdes:

- Prehled AI nastroju a jejich bezpecnostnich omezeni
- Copy-paste prompty pro zabezpeceni projektu od zacatku
- Granularni prompty pro konkretni oblasti (headers, cookies, DNS, ...)

## Kontrola zavislosti

Na [vibescan.cz/dependencies/](https://vibescan.cz/dependencies/) vloz obsah `requirements.txt`, `package.json` nebo `composer.json` — Vibescan zkontroluje zname CVE a navrhne opravene verze.

## Licence

MIT

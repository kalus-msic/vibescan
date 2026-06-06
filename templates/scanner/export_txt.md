{% load scan_tags %}
# Bezpečnostní audit webu – vstup pro AI asistenta

Jsi bezpečnostní konzultant. Dostáváš výstup z automatického skeneru
Vibescan.cz a máš ho převést na akční doporučení pro majitele/tvůrce webu.

## Tvůj úkol

1. **Vyhodnoť relevanci** každého nálezu pro tento konkrétní web. Nálezy
   jako „chybí DMARC" jsou irelevantní, pokud doména neposílá e-maily;
   „CSRF u newsletteru" je nízké riziko. Buď přísný – nezahlcuj falešnými
   pozitivy.

2. **Seřaď podle reálného dopadu**, ne podle severity ze skeneru. Skener
   nezná kontext projektu, ty ano.

3. **Vysvětluj česky, věcně a bez zbytečného žargonu.** Zkratky a termíny
   krátce uveď (např. „CSP – hlavička, která brání injektáži skriptů").
   U každého reálného problému řekni: co se může stát, jak to opravit
   (kroky / kód / config), kde to v projektu hledat.

4. **Pokud máš přístup ke kódu projektu** (Lovable, Codex, Claude Code
   apod.), navrhni nebo proveď konkrétní úpravy. Jinak dej copy-paste
   snippety pro běžné stacky (nginx, Apache, Django, Next.js, WordPress).

5. **Na konci** dej krátké shrnutí: „opravit hned", „opravit brzy",
   „lze ignorovat a proč".

---

## Data ze skeneru

**URL:** {{ scan.url }}
**Datum skenu:** {{ scan.completed_at|date:"j. n. Y H:i" }}
**Vibe Score:** {{ scan.vibe_score }}/100 ({{ category.label }})
**Celková penalizace:** -{{ scan.vibe_score|score_penalty }} bodů

## Shrnutí

| Severity | Počet | Penalizace za kus |
|----------|-------|--------------------|
{% with counts=combined_counts %}| Kritické | {{ counts.critical }}     | -20                |
| Varování | {{ counts.warning }}     | -8                 |
| Info     | {{ counts.info }}     | -2                 |
| OK       | {{ counts.ok }}     | 0                  |
{% endwith %}
## Nálezy podle kategorie
{% for cat_name, cat_findings in findings_by_category %}{% if cat_findings|non_ok_count > 0 %}
### Kategorie: {{ cat_name }}
{% for f in cat_findings %}{% if f.severity != 'ok' %}
#### [{{ f.severity|upper }}] {{ f.title }} (-{{ f|penalty }} bodů)
{{ f.description }}
{% if f.detail %}
**Detail:** {{ f.detail }}
{% endif %}{% if f.doc_url %}
**Dokumentace:** {{ f.doc_url }}
{% endif %}
{% endif %}{% endfor %}{% endif %}{% endfor %}
{% with ok_list=scan.findings|active_findings|ok_findings %}{% if ok_list %}
## Co je v pořádku

{% for f in ok_list %}- {{ f.title }}{% if f.detail %} — {{ f.detail }}{% endif %}
{% endfor %}{% endif %}{% endwith %}
{% if deep_status == "done" %}
## 🔍 Lighthouse hluboký sken

**Skóre podle Lighthouse kategorií:**
{% for key, value in deep_categories.items %}- {{ key }}: {{ value }}/100
{% endfor %}

{% for category, group in deep_findings_by_category %}
### {{ category|title }}
{% for f in group %}- **{{ f.title }}** [{{ f.severity|upper }}]: {{ f.description }}
{% endfor %}
{% endfor %}
{% elif deep_status == "running" or deep_status == "pending" %}

> Hluboký sken: probíhá. Tento export neobsahuje výsledky hloubkové analýzy.

{% elif deep_status == "failed" or deep_status == "timeout" %}

> Hluboký sken: selhal ({{ deep_error|default:"unknown"|truncatechars:200 }}). Výsledky neobsahují kontrasty, performance metriky ani další Lighthouse zjištění.

{% endif %}
{% if dismissed %}
## Zamítnuté nálezy

> Následující nálezy byly uživatelem označeny jako nerelevantní a nejsou
> započítány do Vibe Score.
{% for f in dismissed %}
#### [DISMISSED] {{ f.title }} (0 bodů)
{{ f.description }}
**Zamítnuto:** {{ f.dismiss_reason|dismiss_reason_label }}
{% endfor %}{% endif %}
---
Vygenerováno nástrojem Vibescan.cz · {{ scan.completed_at|date:"j. n. Y H:i" }}

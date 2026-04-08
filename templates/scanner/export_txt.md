{% load scan_tags %}
# Vibescan – Bezpečnostní report

> Toto je výstup automatického bezpečnostního skeneru. Některé nálezy
> nemusí být problém v kontextu konkrétního webu (např. chybějící MX
> záznamy pro doménu, která nepoužívá e-mail). Vyhodnoť relevanci
> nálezů v kontextu daného projektu.

**URL:** {{ scan.url }}
**Datum skenu:** {{ scan.completed_at|date:"j. n. Y H:i" }}
**Vibe Score:** {{ scan.vibe_score }}/100 ({{ category.label }})
**Celková penalizace:** -{{ scan.findings|active_findings|total_penalty }} bodů

## Shrnutí

| Severity | Počet | Penalizace za kus |
|----------|-------|--------------------|
{% with counts=scan.findings|active_findings|finding_counts %}| Kritické | {{ counts.critical }}     | -20                |
| Varování | {{ counts.warning }}     | -8                 |
| Info     | {{ counts.info }}     | -2                 |
| OK       | {{ counts.ok }}     | 0                  |
{% endwith %}
## Nálezy podle kategorie
{% for cat_name, cat_findings in findings_by_category %}
### Kategorie: {{ cat_name }}
{% for f in cat_findings %}
#### [{{ f.severity|upper }}] {{ f.title }} (-{{ f|penalty }} bodů)
{{ f.description }}
{% if f.detail %}
**Detail:** {{ f.detail }}
{% endif %}{% if f.doc_url %}
**Dokumentace:** {{ f.doc_url }}
{% endif %}
{% endfor %}{% endfor %}
{% if dismissed %}
## Zamítnuté nálezy

> Následující nálezy byly uživatelem označeny jako nerelevantní a nejsou
> započítány do Vibe Score.
{% for f in dismissed %}
#### [DISMISSED] {{ f.title }} (0 bodů)
{{ f.description }}
**Zamítnuto:** {{ f.dismiss_reason|dismiss_reason_label }}
{% endfor %}{% endif %}

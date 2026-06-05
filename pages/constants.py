"""Shared constants for the pages app.

Kept separate from pages.views to avoid importing view functions
from scanner.modules — clean separation of data from view code.
"""

# Kotva → název podstránky pod /guide/. Používá:
#   - pages.views.guide() pro link_url u checklist itemů
#   - pages.views.guide() pro JS hash redirect kotev na hubu
#   - scanner.modules.base.guide_url() pro routování fix_url
GUIDE_ANCHOR_PAGE = {
    # GUIDE_PROMPTS ids → prompts page
    "http-security-headers": "prompts",
    "secrets-env": "prompts",
    "csrf-forms": "prompts",
    "debug-error-pages": "prompts",
    "sql-injection": "prompts",
    "autentizace-sessions": "prompts",
    "zavislosti-cve": "prompts",
    "ssl-https": "prompts",
    "html-bezpecnost": "prompts",
    "sri-integrita": "prompts",
    "dns-emaily": "prompts",
    "meta-informace": "prompts",
    "pravni-dokumenty": "prompts",
    "logovani-monitoring": "prompts",
    "seo-zaklady": "prompts",
    "rychlost-a-indexace": "prompts",
    "pristupy-idor": "prompts",
    "secrets-scan": "prompts",
    # NARRATIVE_SECTIONS ids → topics page
    "section-idor": "topics",
    "section-secrets": "topics",
    "section-ai-gdpr": "topics",
    "section-nis2": "topics",
    "section-retence": "topics",
}

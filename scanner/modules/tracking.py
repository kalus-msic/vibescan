from urllib.parse import urlparse
from bs4 import BeautifulSoup
from .base import BaseScanModule, Finding, Severity


TRACKING_HOSTS = {
    "www.googletagmanager.com",
    "googletagmanager.com",
    "www.google-analytics.com",
    "google-analytics.com",
    "connect.facebook.net",
    "static.hotjar.com",
    "cdn.segment.com",
    "snap.licdn.com",
    "analytics.tiktok.com",
    "bat.bing.com",
    "mc.yandex.ru",
}

TRACKING_NAMES = {
    "www.googletagmanager.com": "Google Tag Manager",
    "googletagmanager.com": "Google Tag Manager",
    "www.google-analytics.com": "Google Analytics",
    "google-analytics.com": "Google Analytics",
    "connect.facebook.net": "Facebook Pixel",
    "static.hotjar.com": "Hotjar",
    "cdn.segment.com": "Segment",
    "snap.licdn.com": "LinkedIn Insight",
    "analytics.tiktok.com": "TikTok Pixel",
    "bat.bing.com": "Bing UET",
    "mc.yandex.ru": "Yandex Metrica",
}


class TrackingConsentScanner(BaseScanModule):
    name = "tracking"
    step_label = "Tracking & cookie consent"

    def run(self, url: str, response=None) -> list[Finding]:
        if not response:
            return []

        html = response.text or ""
        soup = BeautifulSoup(html, "html.parser")
        findings = []
        seen_hosts = set()

        for script in soup.find_all("script", src=True):
            src = script["src"]
            if not src.startswith(("http://", "https://")):
                continue
            host = urlparse(src).hostname
            if host not in TRACKING_HOSTS:
                continue
            if host in seen_hosts:
                continue
            seen_hosts.add(host)

            service_name = TRACKING_NAMES.get(host, host)
            findings.append(Finding(
                id=f"tracking-no-consent-{host.replace('.', '-')}",
                title=f"{service_name} se načítá bez cookie consent",
                description=f"Tracking skript {service_name} se načítá přímo v HTML bez ohledu na souhlas uživatele. Skript by měl být načten až po udělení souhlasu přes cookie consent mechanismus (GDPR).",
                severity=Severity.WARNING,
                category="tracking",
                detail=src,
            ))

        return findings

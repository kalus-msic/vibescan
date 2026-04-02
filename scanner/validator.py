import ipaddress
import socket
from urllib.parse import urlparse


class SSRFError(ValueError):
    pass


PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def validate_scan_url(url: str) -> str:
    if not url:
        raise ValueError("URL nesmí být prázdná.")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL musí začínat http:// nebo https://")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL neobsahuje platný hostname.")

    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
    except socket.gaierror:
        raise ValueError(f"Nelze přeložit hostname: {hostname}")

    for network in PRIVATE_RANGES:
        if ip in network:
            raise SSRFError(f"Skenování privátní IP adresy není povoleno: {ip}")

    return url

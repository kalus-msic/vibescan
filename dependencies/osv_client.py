import logging
from dataclasses import dataclass

import httpx
from httpx import TimeoutException, HTTPStatusError

from .parsers import Dependency

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
TIMEOUT = 10


class OsvError(Exception):
    """Raised when OSV.dev API call fails."""
    pass


@dataclass
class Vulnerability:
    id: str
    summary: str
    package_name: str
    package_version: str
    severity_score: float | None
    severity_label: str
    fixed_version: str | None
    osv_url: str


def _extract_severity(vuln_data: dict) -> tuple[float | None, str]:
    """Extract CVSS score and label from vulnerability data."""
    for sev in vuln_data.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            score_str = sev.get("score", "")
            try:
                score = float(score_str)
            except ValueError:
                continue
            if score >= 9.0:
                return score, "Critical"
            if score >= 7.0:
                return score, "High"
            if score >= 4.0:
                return score, "Medium"
            return score, "Low"

    for key in ("ecosystem_specific", "database_specific"):
        specific = vuln_data.get(key, {})
        if isinstance(specific, dict):
            sev_str = specific.get("severity", "").upper()
            mapping = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}
            if sev_str in mapping:
                score = mapping[sev_str]
                label = sev_str.capitalize()
                if label == "Moderate":
                    label = "Medium"
                return score, label

    return None, "Unknown"


def _extract_fixed_version(vuln_data: dict) -> str | None:
    """Extract the first fixed version from vulnerability data."""
    for affected in vuln_data.get("affected", []):
        for range_info in affected.get("ranges", []):
            if range_info.get("type") == "ECOSYSTEM":
                for event in range_info.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return None


@dataclass
class CheckResult:
    vulnerabilities: list[Vulnerability]
    last_modified: str | None  # ISO date of most recently modified vuln


def check_vulnerabilities(deps: list[Dependency]) -> CheckResult:
    """Query OSV.dev for vulnerabilities in the given dependencies."""
    if not deps:
        return CheckResult(vulnerabilities=[], last_modified=None)

    queries = [
        {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
        for d in deps
    ]

    try:
        batch_resp = httpx.post(OSV_BATCH_URL, json={"queries": queries}, timeout=TIMEOUT)
        batch_resp.raise_for_status()
    except TimeoutException:
        raise OsvError("Služba OSV.dev neodpovídá, zkuste to prosím později.")
    except HTTPStatusError:
        raise OsvError("Služba OSV.dev vrátila chybu, zkuste to prosím později.")
    except Exception:
        raise OsvError("Nepodařilo se spojit s OSV.dev, zkuste to prosím později.")

    batch_data = batch_resp.json()
    results = batch_data.get("results", [])

    vuln_packages: dict[str, Dependency] = {}
    modified_dates: list[str] = []
    for i, result in enumerate(results):
        if i >= len(deps):
            break
        for vuln in result.get("vulns", []):
            vuln_id = vuln.get("id")
            if vuln_id and vuln_id not in vuln_packages:
                vuln_packages[vuln_id] = deps[i]
            modified = vuln.get("modified")
            if modified:
                modified_dates.append(modified)

    last_modified = max(modified_dates)[:10] if modified_dates else None

    if not vuln_packages:
        return CheckResult(vulnerabilities=[], last_modified=last_modified)

    vulnerabilities = []
    for vuln_id, dep in vuln_packages.items():
        try:
            vuln_resp = httpx.get(f"{OSV_VULN_URL}/{vuln_id}", timeout=TIMEOUT)
            vuln_resp.raise_for_status()
            vuln_data = vuln_resp.json()
        except (TimeoutException, HTTPStatusError):
            logger.warning("Failed to fetch vulnerability details for %s", vuln_id)
            continue

        score, label = _extract_severity(vuln_data)
        fixed = _extract_fixed_version(vuln_data)

        # Prefer CVE-* ID over GHSA-* for display (sortable, standard)
        display_id = vuln_id
        for alias in vuln_data.get("aliases", []):
            if alias.startswith("CVE-"):
                display_id = alias
                break

        vulnerabilities.append(Vulnerability(
            id=display_id,
            summary=vuln_data.get("summary", "Bez popisu"),
            package_name=dep.name,
            package_version=dep.version,
            severity_score=score,
            severity_label=label,
            fixed_version=fixed,
            osv_url=f"https://osv.dev/vulnerability/{vuln_id}",
        ))

    # Newest CVE first within same severity (stable sort: ID desc, then severity)
    vulnerabilities.sort(key=lambda v: v.id, reverse=True)
    vulnerabilities.sort(key=lambda v: (v.severity_score is None, -(v.severity_score or 0)))
    return CheckResult(vulnerabilities=vulnerabilities, last_modified=last_modified)

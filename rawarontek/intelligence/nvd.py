from __future__ import annotations

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def lookup_nvd(product: str, version: str, timeout: int = 15) -> list[dict[str, object]]:
    """Find CVE candidates by product/version keyword.

    Keyword matching is intentionally treated as candidate enrichment only.
    Exact CPE applicability must be verified before calling a finding confirmed.
    """
    try:
        response = requests.get(
            NVD_URL,
            params={"keywordSearch": f"{product} {version}", "resultsPerPage": 20},
            timeout=timeout,
            headers={"User-Agent": "RawaRontek/2.0"},
        )
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        return []

    results: list[dict[str, object]] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                break
        results.append({
            "cve": cve.get("id"),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "cvss": cvss,
            "description": (cve.get("descriptions") or [{}])[0].get("value", ""),
            "source": "NVD keyword search",
            "confidence": "POTENTIAL",
        })
    return results


def load_kev(timeout: int = 15) -> set[str]:
    try:
        response = requests.get(KEV_URL, timeout=timeout, headers={"User-Agent": "RawaRontek/2.0"})
        response.raise_for_status()
        data = response.json()
        return {
            item.get("cveID")
            for item in data.get("vulnerabilities", [])
            if item.get("cveID")
        }
    except (requests.RequestException, ValueError):
        return set()


def enrich_with_kev(findings: list[dict[str, object]], timeout: int = 15) -> list[dict[str, object]]:
    kev = load_kev(timeout)
    for finding in findings:
        cve = finding.get("cve")
        finding["cisa_kev"] = cve in kev if cve else False
    return findings

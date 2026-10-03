from __future__ import annotations

from typing import Any

from .correlation import extract_products
from .nvd import enrich_with_kev, lookup_nvd


def build_cve_intelligence(scan_results: dict[str, Any], timeout: int = 15) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []

    for candidate in extract_products(scan_results):
        product = candidate["product"]
        version = candidate["version"]
        for cve in lookup_nvd(product, version, timeout):
            findings.append({
                "product": product,
                "version": version,
                "source": candidate["source"],
                **cve,
                "confidence": "POTENTIAL",
                "status": "REQUIRES_EXACT_CPE_VALIDATION",
            })

    return enrich_with_kev(findings, timeout)

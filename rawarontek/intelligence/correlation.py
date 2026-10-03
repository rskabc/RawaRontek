from __future__ import annotations

import re
from typing import Any


VERSION_RE = re.compile(r"(?P<product>[A-Za-z][A-Za-z0-9_.-]{1,40}).*?(?P<version>\d+(?:\.\d+){1,3})")


def extract_products(scan_results: dict[str, Any]) -> list[dict[str, str]]:
    """Extract conservative product/version candidates from scanner text.

    This is intentionally evidence collection, not a vulnerability verdict.
    """
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for source, value in scan_results.items():
        if not isinstance(value, str):
            continue
        for match in VERSION_RE.finditer(value):
            product = match.group("product")
            version = match.group("version")
            key = (product.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            candidates.append({
                "product": product,
                "version": version,
                "source": source,
            })
    return candidates


def build_cve_candidates(scan_results: dict[str, Any]) -> list[dict[str, str]]:
    """Return version evidence for later NVD/CPE enrichment.

    The result is deliberately marked POTENTIAL until an authoritative
    vulnerability source confirms CPE applicability.
    """
    return [
        {
            **candidate,
            "confidence": "POTENTIAL",
            "status": "REQUIRES_CPE_NVD_VALIDATION",
        }
        for candidate in extract_products(scan_results)
    ]

from __future__ import annotations

from ..core import ScanContext
from .external import run_external


def nmap_service(ctx: ScanContext, timeout: int = 180) -> str:
    return run_external(ctx, "Nmap Service Detection", ["nmap", "-sV", "-T3", ctx.target], timeout)


def nmap_safe(ctx: ScanContext, timeout: int = 180) -> str:
    return run_external(ctx, "Nmap Safe NSE", ["nmap", "--script", "safe", "-sV", ctx.target], timeout)


def nuclei(ctx: ScanContext, timeout: int = 240) -> str:
    return run_external(ctx, "Nuclei", ["nuclei", "-u", f"https://{ctx.target}"], timeout)


def zap(ctx: ScanContext, timeout: int = 300) -> str:
    return run_external(ctx, "OWASP ZAP", ["zaproxy", "-quickurl", f"https://{ctx.target}"], timeout)

from __future__ import annotations

from ..core import ScanContext
from .external import run_external


def subfinder(ctx: ScanContext, timeout: int = 120) -> str:
    return run_external(ctx, "Subdomains", ["subfinder", "-d", ctx.target, "-silent"], timeout)


def dnsx(ctx: ScanContext, timeout: int = 120) -> str:
    return run_external(ctx, "DNSx", ["dnsx", "-d", ctx.target, "-silent"], timeout)


def amass(ctx: ScanContext, timeout: int = 180) -> str:
    return run_external(ctx, "Amass", ["amass", "enum", "-passive", "-d", ctx.target], timeout)


def naabu(ctx: ScanContext, timeout: int = 180) -> str:
    return run_external(ctx, "Naabu", ["naabu", "-host", ctx.target, "-silent"], timeout)


def httpx(ctx: ScanContext, timeout: int = 180) -> str:
    return run_external(
        ctx,
        "HTTPx",
        ["httpx", "-u", ctx.target, "-status-code", "-title", "-tech-detect", "-follow-redirects"],
        timeout,
    )


def katana(ctx: ScanContext, timeout: int = 180) -> str:
    return run_external(ctx, "Katana", ["katana", "-u", f"https://{ctx.target}", "-silent"], timeout)

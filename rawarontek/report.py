from __future__ import annotations

from pathlib import Path

from .core import ScanContext


def write_report(ctx: ScanContext, output_dir: str = ".") -> Path:
    safe_target = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in ctx.target)
    output_path = Path(output_dir) / f"{safe_target}_hasil.txt"
    with output_path.open("w", encoding="utf-8") as handle:
        handle.write("RawaRontek Scan Report\n")
        handle.write(f"Target: {ctx.target}\n")
        handle.write("=" * 72 + "\n\n")
        for key, value in ctx.summary.items():
            handle.write(f"[+] {key}: {value}\n")
    return output_path

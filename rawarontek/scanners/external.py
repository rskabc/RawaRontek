from __future__ import annotations

from ..core import ScanContext, command_available, run_command


def run_external(
    ctx: ScanContext,
    module: str,
    command: list[str],
    timeout: int = 120,
) -> str:
    if not command_available(command[0]):
        result = f"{command[0]} tidak tersedia"
        ctx.set(module, result)
        return result

    code, output = run_command(command, timeout=timeout)
    if code != 0:
        result = output or f"{command[0]} selesai dengan exit code {code}"
        ctx.set(module, result)
        return result

    ctx.set(module, output or "Tidak ada output")
    return output or "Tidak ada output"

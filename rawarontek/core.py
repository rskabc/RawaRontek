from __future__ import annotations

import shutil
import socket
import subprocess
from dataclasses import dataclass
from typing import Iterable


@dataclass
class ScanContext:
    target: str
    summary: dict[str, object]

    def set(self, key: str, value: object) -> None:
        self.summary[key] = value


def command_available(command: str) -> bool:
    return shutil.which(command) is not None


def run_command(command: list[str], timeout: int = 90) -> tuple[int, str]:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
        output = completed.stdout or ""
        if completed.stderr:
            output += completed.stderr
        return completed.returncode, output.strip()
    except subprocess.TimeoutExpired:
        return 124, f"Command timeout setelah {timeout} detik"
    except OSError as exc:
        return 127, f"Command gagal dijalankan: {exc}"


def quick_port_scan(host: str, ports: Iterable[int] = (21, 22, 80, 443)) -> list[int]:
    open_ports: list[int] = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7)
        try:
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
        except OSError:
            pass
        finally:
            sock.close()
    return open_ports

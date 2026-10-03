from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import yaml


@dataclass
class ScanConfig:
    timeout: int = 10
    command_timeout: int = 120
    output_dir: str = "reports"
    ports: list[int] = field(default_factory=lambda: [21, 22, 80, 443, 8080, 8443])
    user_agent: str = "RawaRontek/2.0"


def load_config(path: str = "config/default.yaml") -> ScanConfig:
    config = ScanConfig()
    file_path = Path(path)
    if not file_path.exists():
        return config

    data = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    scan = data.get("scan", {})
    output = data.get("output", {})
    ports = data.get("ports", {}).get("list", config.ports)

    config.timeout = int(scan.get("timeout", config.timeout))
    config.command_timeout = int(scan.get("command_timeout", config.command_timeout))
    config.output_dir = str(output.get("directory", config.output_dir))
    config.ports = [int(port) for port in ports]
    return config

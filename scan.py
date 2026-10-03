#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from rawarontek.config import load_config
from rawarontek.core import ScanContext
from rawarontek.intelligence.correlation import build_cve_candidates
from rawarontek.recon import (
    dns_enum, ftp_anonymous_check, historical_exposure, http_headers,
    quick_ports, security_headers_check, tls_check, whois_lookup,
    directory_scan,
)
from rawarontek.scanners.assessment import nmap_safe, nmap_service, nuclei, zap
from rawarontek.scanners.discovery import amass, dnsx, httpx, katana, naabu, subfinder
from rawarontek.reports.json_report import write_json
from rawarontek.reports.html_report import write_html
from rawarontek.report import write_report

VERSION = "2.0.0"

BANNER = """
============================================================
 RawaRontek 2.0 — Security Assessment Orchestrator
============================================================
 Use only against assets you own or are authorized to test.
============================================================
"""

BASE_STEPS = {
    "whois": whois_lookup,
    "dns": dns_enum,
    "dnsx": dnsx,
    "ports": quick_ports,
    "naabu": naabu,
    "http": http_headers,
    "headers": security_headers_check,
    "tls": tls_check,
    "wayback": historical_exposure,
    "ffuf": directory_scan,
    "subdomains": subfinder,
    "amass": amass,
    "httpx": httpx,
    "katana": katana,
    "nmap": nmap_service,
    "nmap_safe": nmap_safe,
    "nuclei": nuclei,
    "ftp": ftp_anonymous_check,
    "zap": zap,
}

PROFILES = {
    "quick": ["dns", "http", "ports", "tls"],
    "standard": ["whois", "dns", "subdomains", "naabu", "httpx", "nmap", "headers", "tls"],
    "full": [
        "whois", "dns", "dnsx", "subdomains", "amass", "naabu", "httpx",
        "nmap", "headers", "tls", "katana", "ffuf", "wayback", "ftp",
        "nmap_safe", "nuclei",
    ],
    "web": ["httpx", "headers", "tls", "katana", "ffuf", "nuclei"],
}


def normalize_target(target: str) -> str:
    return target.strip().removeprefix("https://").removeprefix("http://").split("/")[0]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="RawaRontek security assessment orchestrator")
    parser.add_argument("-t", "--target", help="Domain/host target")
    parser.add_argument("-p", "--profile", choices=sorted(PROFILES), default="standard")
    parser.add_argument("-o", "--output", default=None, help="Output directory")
    parser.add_argument("--dry-run", action="store_true", help="Show modules without running scanners")
    parser.add_argument("--version", action="version", version=f"RawaRontek {VERSION}")
    return parser.parse_args()


def print_result(title: str, result: object) -> None:
    print(f"\n[=] {title}")
    print(result)


def main() -> int:
    args = parse_args()
    print(BANNER)

    config = load_config()
    target = normalize_target(args.target or input("Masukkan domain target: "))
    if not target:
        print("[!] Domain target wajib diisi.")
        return 2

    modules = PROFILES[args.profile]
    print(f"[+] Target : {target}")
    print(f"[+] Profile: {args.profile}")
    print(f"[+] Modules: {', '.join(modules)}")

    if args.dry_run:
        print("\n[DRY RUN] Tidak ada scanner yang dijalankan.")
        return 0

    started = datetime.now(timezone.utc)
    ctx = ScanContext(target=target, summary={})

    for module in modules:
        scanner = BASE_STEPS.get(module)
        if scanner is None:
            print(f"[!] Modul belum tersedia: {module}")
            continue
        try:
            print_result(module.upper(), scanner(ctx))
        except KeyboardInterrupt:
            print("\n[!] Scan dihentikan pengguna.")
            break
        except Exception as exc:
            print(f"[!] {module} gagal: {exc}")
            ctx.set(module, f"ERROR: {exc}")

    cve_candidates = build_cve_candidates(ctx.summary)
    ctx.set("CVE Candidates", cve_candidates)

    output_root = Path(args.output or config.output_dir)
    run_id = started.strftime("%Y%m%d_%H%M%S")
    report_dir = output_root / target / run_id
    report_dir.mkdir(parents=True, exist_ok=True)

    data = {
        "tool": "RawaRontek",
        "version": VERSION,
        "target": target,
        "profile": args.profile,
        "started_at": started.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "summary": ctx.summary,
        "cve_candidates": cve_candidates,
    }

    write_json(data, report_dir / "report.json")
    write_html(target, ctx.summary, cve_candidates, report_dir / "report.html")
    write_report(ctx, str(report_dir))

    print("\n============================================================")
    print("SCAN COMPLETED")
    print(f"TXT : {report_dir / (target + '_hasil.txt')}")
    print(f"JSON: {report_dir / 'report.json'}")
    print(f"HTML: {report_dir / 'report.html'}")
    print(f"CVE candidates: {len(cve_candidates)}")
    print("============================================================")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

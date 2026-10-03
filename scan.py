#!/usr/bin/env python3
from __future__ import annotations

from rawarontek.core import ScanContext, command_available
from rawarontek.recon import (
    directory_scan, dns_enum, ftp_anonymous_check, historical_exposure,
    http_headers, nuclei_scan, quick_ports, security_headers_check,
    subdomain_enum, tls_check, whois_lookup,
)
from rawarontek.report import write_report

BANNER = """
============================================================
 RawaRontek 2.0 — Reconnaissance & Security Assessment
============================================================
 Gunakan hanya pada aset yang Anda miliki atau yang telah
 memberi izin pengujian. Hasil scanner perlu divalidasi.
============================================================
"""

TOOLS = ("nmap", "ffuf", "nuclei", "subfinder")


def check_dependencies() -> None:
    print("[=] Memeriksa dependensi...")
    missing = [tool for tool in TOOLS if not command_available(tool)]
    if missing:
        print(f"[!] Tool belum tersedia: {', '.join(missing)}")
        print("    Modul terkait akan dilewati secara otomatis.")
    else:
        print("[+] Semua CLI tools utama tersedia.")


def print_result(title: str, result: object) -> None:
    print(f"\n[=] {title}")
    print(result)


def main() -> int:
    print(BANNER)
    check_dependencies()

    target = input("Masukkan domain target: ").strip()
    if not target:
        print("[!] Domain target wajib diisi.")
        return 2

    target = target.removeprefix("https://").removeprefix("http://").split("/")[0]
    ctx = ScanContext(target=target, summary={})

    steps = [
        ("WHOIS", whois_lookup),
        ("DNS Enumeration", dns_enum),
        ("Quick Port Scan", quick_ports),
        ("HTTP Headers", http_headers),
        ("Security Headers", security_headers_check),
        ("TLS/SSL", tls_check),
        ("Historical Exposure", historical_exposure),
        ("Directory Scan", directory_scan),
        ("Subdomain Enumeration", subdomain_enum),
        ("Nuclei", nuclei_scan),
        ("FTP Anonymous", ftp_anonymous_check),
    ]

    for title, scanner in steps:
        try:
            print_result(title, scanner(ctx))
        except KeyboardInterrupt:
            print("\n[!] Dibatalkan pengguna.")
            break
        except Exception as exc:
            print(f"[!] {title} gagal: {exc}")

    report = write_report(ctx)
    print("\n[=] RINGKASAN")
    for key, value in ctx.summary.items():
        print(f"[+] {key}: {value}")
    print(f"\n[+] Laporan tersimpan: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

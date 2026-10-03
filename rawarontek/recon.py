from __future__ import annotations

import ftplib
import socket
from pathlib import Path

import dns.resolver
import requests
import whois

from .core import ScanContext, command_available, quick_port_scan, run_command

REQUEST_TIMEOUT = 8
USER_AGENT = "RawaRontek/2.0"


def whois_lookup(ctx: ScanContext) -> str:
    try:
        result = whois.whois(ctx.target)
        registrar = result.get("registrar", "Tidak diketahui")
        ctx.set("Registrar", registrar)
        return str(result)
    except Exception as exc:
        return f"WHOIS gagal: {exc}"


def dns_enum(ctx: ScanContext) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    for record_type in ("A", "MX", "NS"):
        try:
            answers = resolver.resolve(ctx.target, record_type)
            records[record_type] = [answer.to_text() for answer in answers]
        except Exception as exc:
            records[record_type] = [f"Error: {exc}"]
    ctx.set("DNS Records", records)
    return records


def http_headers(ctx: ScanContext) -> dict[str, str] | str:
    try:
        response = requests.get(f"https://{ctx.target}", timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT}, allow_redirects=True)
        headers = dict(response.headers)
        ctx.set("HTTP Status", response.status_code)
        ctx.set("Server Header", headers.get("Server", "Tidak diketahui"))
        ctx.set("Final URL", response.url)
        return headers
    except requests.RequestException as exc:
        return f"HTTP request gagal: {exc}"


def security_headers_check(ctx: ScanContext) -> dict[str, str] | str:
    try:
        response = requests.get(f"https://{ctx.target}", timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        headers = response.headers
        checks = {
            "Content-Security-Policy": headers.get("Content-Security-Policy", "Tidak ada"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Tidak ada"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Tidak ada"),
            "X-Frame-Options": headers.get("X-Frame-Options", "Tidak ada"),
            "Referrer-Policy": headers.get("Referrer-Policy", "Tidak ada"),
            "Permissions-Policy": headers.get("Permissions-Policy", "Tidak ada"),
            "Access-Control-Allow-Origin": headers.get("Access-Control-Allow-Origin", "Tidak ada"),
        }
        for key, value in checks.items():
            ctx.set(key, value)
        return checks
    except requests.RequestException as exc:
        return f"Security header check gagal: {exc}"


def tls_check(ctx: ScanContext) -> str:
    if not command_available("nmap"):
        result = "nmap tidak tersedia"
        ctx.set("SSL/TLS Info", result)
        return result
    _, output = run_command(["nmap", "--script", "ssl-cert,ssl-enum-ciphers", "-p", "443", ctx.target], timeout=90)
    status = "Tersedia" if output and "ssl" in output.lower() else "Tidak ditemukan / gagal"
    ctx.set("SSL/TLS Info", status)
    return output or status


def historical_exposure(ctx: ScanContext) -> list[str] | str:
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url={ctx.target}/*&output=text&fl=original&collapse=urlkey&filter=statuscode:200"
        response = requests.get(url, timeout=12, headers={"User-Agent": USER_AGENT})
        response.raise_for_status()
        urls = [line.strip() for line in response.text.splitlines() if line.strip()][:20]
        ctx.set("Wayback URLs", urls)
        return urls
    except requests.RequestException as exc:
        return f"Wayback check gagal: {exc}"


def directory_scan(ctx: ScanContext) -> str:
    if not command_available("ffuf"):
        result = "ffuf tidak tersedia"
        ctx.set("Directory Scan", result)
        return result
    wordlist = Path("/usr/share/wordlists/dirb/common.txt")
    if not wordlist.exists():
        result = f"Wordlist tidak ditemukan: {wordlist}"
        ctx.set("Directory Scan", result)
        return result
    _, output = run_command(["ffuf", "-u", f"https://{ctx.target}/FUZZ", "-w", str(wordlist), "-mc", "200,204,301,302,307,401,403", "-s"], timeout=120)
    ctx.set("Directory Scan", "Selesai" if output else "Tidak ada output")
    return output or "Tidak ada hasil"


def subdomain_enum(ctx: ScanContext) -> str:
    if not command_available("subfinder"):
        ctx.set("Subdomains Found", [])
        return "subfinder tidak tersedia"
    _, output = run_command(["subfinder", "-d", ctx.target, "-silent"], timeout=120)
    subdomains = [line.strip() for line in output.splitlines() if line.strip()]
    ctx.set("Subdomains Found", subdomains)
    return "\\n".join(subdomains) or "Tidak ditemukan"


def nuclei_scan(ctx: ScanContext) -> str:
    if not command_available("nuclei"):
        ctx.set("Nuclei Scan", "nuclei tidak tersedia")
        return "nuclei tidak tersedia"
    _, output = run_command(["nuclei", "-u", f"https://{ctx.target}"], timeout=180)
    ctx.set("Nuclei Scan", output.splitlines())
    return output or "Tidak ada temuan / output"


def ftp_anonymous_check(ctx: ScanContext) -> str:
    ftp = ftplib.FTP()
    try:
        ftp.connect(ctx.target, 21, timeout=5)
        ftp.login(user="anonymous", passwd="")
        ctx.set("FTP Anonymous", "Diperbolehkan")
        return "[!] FTP Anonymous Login Diperbolehkan"
    except (socket.gaierror, TimeoutError, OSError, ftplib.all_errors):
        ctx.set("FTP Anonymous", "Ditolak / Tidak tersedia")
        return "[+] FTP Anonymous Login Ditolak / Tidak tersedia"
    finally:
        try:
            ftp.quit()
        except Exception:
            pass


def quick_ports(ctx: ScanContext) -> list[int]:
    ports = quick_port_scan(ctx.target)
    ctx.set("Open Ports", ports)
    return ports

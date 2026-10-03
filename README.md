# RawaRontek

Toolkit Python ringan untuk reconnaissance dan security assessment terhadap aset yang Anda miliki atau yang Anda berwenang untuk uji.

## Struktur

```text
RawaRontek/
├── scan.py                  # entry point
├── rawarontek/
│   ├── core.py              # context, command runner, port check
│   ├── recon.py             # modul reconnaissance
│   ├── report.py            # output laporan
│   └── __init__.py
├── requirements.txt
└── README.md
```

## Fitur

- WHOIS
- DNS A/MX/NS
- Quick port check: 21, 22, 80, 443
- HTTP response/header inspection
- Security headers: CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, dan CORS
- TLS/SSL inspection via Nmap
- Historical exposure via Wayback Machine
- Directory discovery via FFUF
- Subdomain enumeration via Subfinder
- Vulnerability template scan via Nuclei
- FTP anonymous login check
- Laporan otomatis ke `<target>_hasil.txt`

## Instalasi

Python dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

External tools (`nmap`, `ffuf`, `nuclei`, `subfinder`) dipasang sesuai distro/lingkungan Anda. Aplikasi tidak lagi menjalankan `apt install` otomatis.

## Menjalankan

```bash
python3 scan.py
```

Masukkan `example.com` atau URL sederhana seperti `https://example.com`; input akan dinormalisasi menjadi hostname.

## Catatan

Jalankan hanya terhadap aset yang Anda miliki atau yang telah memberikan izin pengujian. Hasil scanner adalah indikator awal dan perlu divalidasi sebelum dijadikan temuan keamanan.

## Changelog

### 2.0.0
- Memisahkan scanner dari entry point menjadi package `rawarontek/`.
- Menambahkan timeout dan penanganan error untuk external command.
- Menambah security header checks yang lebih relevan.
- Menghapus auto-install package OS dari program.
- Output laporan menggunakan UTF-8 dan nama file target dinormalisasi.

## Kredit

Orchestrator Script by [@rskabc](https://github.com/rskabc)

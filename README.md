# RawaRontek v2

**Security Assessment Orchestrator berbasis Python untuk asset discovery, reconnaissance, web discovery, vulnerability assessment, CVE intelligence, correlation, dan reporting.**

RawaRontek mengorkestrasi beberapa tool security menjadi satu alur kerja yang lebih mudah digunakan. Fokus v2 bukan membuat scanner baru dari nol, tetapi mengumpulkan evidence dari berbagai scanner, menghubungkannya, lalu menghasilkan laporan yang dapat ditindaklanjuti.

> **Authorization notice:** gunakan RawaRontek hanya terhadap sistem, domain, IP, dan aplikasi yang Anda miliki atau yang secara eksplisit memberi Anda izin pengujian.

## 1. Tujuan RawaRontek v2

RawaRontek v2 dirancang untuk menjawab:

1. Aset apa saja yang terlihat dari sebuah domain?
2. Subdomain dan service apa yang ditemukan?
3. Port dan teknologi apa yang terdeteksi?
4. Endpoint web apa yang dapat ditemukan?
5. Security header dan konfigurasi apa yang perlu diperhatikan?
6. Apakah scanner menemukan indikasi vulnerability?
7. Software/version apa yang dapat dikorelasikan dengan CVE?
8. Apakah CVE tersebut tercatat pada CISA Known Exploited Vulnerabilities (KEV)?
9. Evidence apa yang mendukung sebuah finding?
10. Bagaimana hasil scan dibandingkan dan dilaporkan?

RawaRontek bukan exploit framework. Fokusnya:

```text
Discovery → Enumeration → Assessment → Evidence → CVE Intelligence → Correlation → Reporting
```

## 2. Arsitektur

```text
RawaRontek/
├── scan.py
├── rawarontek/
│   ├── __init__.py
│   ├── core.py
│   ├── config.py
│   ├── recon.py
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── external.py
│   │   ├── discovery.py
│   │   └── assessment.py
│   ├── intelligence/
│   │   ├── __init__.py
│   │   ├── correlation.py
│   │   ├── nvd.py
│   │   └── engine.py
│   └── reports/
│       ├── __init__.py
│       ├── json_report.py
│       └── html_report.py
├── config/
│   └── default.yaml
├── tests/
│   ├── test_core.py
│   └── test_correlation.py
├── requirements.txt
├── .gitignore
└── README.md
```

### Komponen

| Komponen | Fungsi |
|---|---|
| `scan.py` | Entry point CLI |
| `core.py` | Context dan external command runner |
| `config.py` | Membaca konfigurasi YAML |
| `recon.py` | Scanner reconnaissance dasar |
| `scanners/discovery.py` | Adapter Subfinder, DNSx, Amass, Naabu, HTTPx, Katana |
| `scanners/assessment.py` | Adapter Nmap, Nuclei, ZAP |
| `intelligence/correlation.py` | Ekstraksi evidence product/version |
| `intelligence/nvd.py` | NVD CVE candidate lookup dan CISA KEV enrichment |
| `intelligence/engine.py` | Menggabungkan evidence dan vulnerability intelligence |
| `reports/` | JSON dan HTML reporting |
| `tests/` | Regression/unit tests |

## 3. Scanner

### Discovery

- Subfinder — subdomain discovery
- DNSx — DNS resolution/discovery
- Amass — passive attack-surface discovery
- Naabu — port discovery
- HTTPx — HTTP probing dan technology detection
- Katana — web crawling dan endpoint discovery

### Network / service

- Nmap — service/version detection, TLS, safe NSE
- FTP check — anonymous FTP check

### Web

- FFUF — directory/content discovery
- Nuclei — template-based vulnerability assessment
- OWASP ZAP — web assessment profile

## 4. Scan Profile

### Quick

```text
DNS
HTTP
Common Ports
TLS
```

```bash
python3 scan.py --target example.com --profile quick
```

### Standard

```text
WHOIS
DNS
Subfinder
Naabu
HTTPx
Nmap
Security Headers
TLS
```

```bash
python3 scan.py --target example.com --profile standard
```

### Full

```text
WHOIS → DNS → DNSx → Subfinder → Amass → Naabu → HTTPx → Nmap
→ Headers → TLS → Katana → FFUF → Wayback → FTP → Nmap Safe NSE
→ Nuclei → CVE Intelligence
```

```bash
python3 scan.py --target example.com --profile full
```

### Web

```text
HTTPx → Headers → TLS → Katana → FFUF → Nuclei → CVE Intelligence
```

```bash
python3 scan.py --target example.com --profile web
```

## 5. Instalasi

Gunakan Python 3 dan virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Dependencies Python:

- dnspython
- python-whois
- requests
- PyYAML

External tools:

```text
nmap, subfinder, dnsx, amass, naabu, httpx, katana, ffuf, nuclei, zaproxy
```

Tidak semua tool wajib tersedia. Modul yang membutuhkan tool yang tidak ada akan dilewati dengan pesan yang jelas.

RawaRontek tidak lagi menjalankan `apt install` otomatis.

## 6. Menjalankan

Interactive:

```bash
python3 scan.py
```

CLI:

```bash
python3 scan.py --target example.com --profile standard
```

Dry run:

```bash
python3 scan.py --target example.com --profile full --dry-run
```

Custom output:

```bash
python3 scan.py --target example.com --profile standard -o /opt/rawarontek/reports
```

## 7. Output

```text
reports/
└── example.com/
    └── 20261003_183012/
        ├── example.com_hasil.txt
        ├── report.json
        └── report.html
```

TXT cocok untuk dibaca langsung. JSON disiapkan untuk dashboard/SIEM/integrasi. HTML cocok untuk review dan laporan assessment.

## 8. CVE Intelligence

Alurnya:

```text
Scanner
   ↓
Product / Version Evidence
   ↓
Correlation
   ↓
NVD
   ↓
CVE Candidates
   ↓
CISA KEV enrichment
   ↓
Report
```

### Penting

RawaRontek tidak menganggap product/version match sebagai bukti vulnerability yang terkonfirmasi.

Contoh:

```text
Detected: nginx 1.24.0
CVE candidate: ditemukan
Confidence: POTENTIAL
Status: REQUIRES_EXACT_CPE_VALIDATION
```

Exact CPE applicability dan vendor advisory tetap harus diverifikasi sebelum finding disebut confirmed.

## 9. CISA KEV

Candidate CVE dapat diperkaya dengan status:

```text
CISA KEV: YES / NO
```

YES berarti CVE terdapat pada CISA Known Exploited Vulnerabilities Catalog. Status tersebut bukan bukti bahwa target tertentu vulnerable; versi dan applicability tetap harus divalidasi.

## 10. Correlation Engine

Correlation menggabungkan evidence dari scanner:

```text
Nmap
  └── nginx 1.24.0

HTTPx
  └── nginx

Nuclei
  └── finding

NVD
  └── CVE candidate
```

Menjadi satu evidence record yang lebih mudah ditindaklanjuti.

## 11. Security Headers

RawaRontek memeriksa antara lain:

- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- Access-Control-Allow-Origin

Missing header tidak otomatis berarti vulnerability dengan severity tertentu; konteks aplikasi harus diperiksa.

## 12. Configuration

Default configuration berada di `config/default.yaml`.

```yaml
scan:
  timeout: 10
  command_timeout: 120

ports:
  list:
    - 21
    - 22
    - 80
    - 443
    - 8080
    - 8443

output:
  directory: reports
```

Konfigurasi sengaja dibuat sederhana agar mudah dipelihara.

## 13. Testing

Basic tests tersedia di `tests/`.

```bash
python -m pytest
```

Test saat ini mencakup ScanContext, command detection, dan aturan bahwa correlation candidate tidak boleh otomatis berstatus confirmed.

## 14. Security Design

- External command menggunakan argument list, bukan shell string.
- External command memiliki timeout.
- Kegagalan satu scanner tidak harus menghentikan seluruh pipeline.
- Target dinormalisasi sebelum dipakai.
- Nama file output disanitasi.
- Tidak ada automatic OS package installation.
- CVE keyword match tidak diperlakukan sebagai confirmed vulnerability.
- Target hanya boleh diuji dengan authorization yang sesuai.

## 15. Recommended Workflow

```text
1. Tentukan scope
2. Dry run
3. Quick scan
4. Standard scan
5. Full/Web assessment bila diperlukan
6. Review evidence
7. Review CVE candidates
8. Validasi CPE/vendor advisory
9. Generate report
```

## 16. Roadmap

### Foundation
- [x] Modular package
- [x] Scanner adapters
- [x] Configuration
- [x] Profiles
- [x] Timeout handling
- [x] Error isolation
- [x] TXT/JSON/HTML report
- [x] Basic tests

### Discovery
- [x] Subfinder
- [x] DNSx
- [x] Amass
- [x] Naabu
- [x] HTTPx
- [x] Katana

### Assessment
- [x] Nmap service detection
- [x] Nmap safe NSE adapter
- [x] Nuclei
- [x] FFUF
- [x] TLS checks
- [x] Security headers

### Intelligence
- [x] Product/version evidence extraction
- [x] NVD lookup
- [x] CVE candidates
- [x] CISA KEV enrichment
- [x] Confidence model
- [ ] Exact CPE resolver
- [ ] Vendor advisory correlation
- [ ] Better version normalization

### Reporting
- [x] TXT
- [x] JSON
- [x] HTML
- [ ] Executive summary
- [ ] Remediation section
- [ ] Finding deduplication
- [ ] Risk aggregation
- [ ] Scan comparison

### Continuous Assessment
- [ ] Scan history
- [ ] Diff engine
- [ ] New asset detection
- [ ] New vulnerability detection
- [ ] Scheduled scans
- [ ] Notification integration

## 17. Prinsip Desain

**Simple to run, modular to maintain.**

RawaRontek menjaga satu entry point yang sederhana, tetapi memisahkan scanner, intelligence, configuration, dan reporting sehingga masing-masing komponen dapat dikembangkan tanpa membuat `scan.py` menjadi monolithic.

## 18. Batasan Saat Ini

1. NVD lookup menggunakan keyword product/version sebagai candidate discovery, bukan exact CPE matching.
2. CISA KEV adalah enrichment, bukan bukti target vulnerable.
3. Product/version extraction masih dapat menghasilkan false candidate dan perlu validasi.
4. ZAP membutuhkan instalasi ZAP yang sesuai.
5. Full scan dapat membutuhkan waktu dan traffic lebih besar.
6. Hasil scanner tetap harus divalidasi assessor.

## 19. Target Akhir v2

```text
Asset Discovery
      ↓
Network Discovery
      ↓
Web Discovery
      ↓
Vulnerability Assessment
      ↓
CVE Intelligence
      ↓
Correlation / Evidence
      ↓
TXT + JSON + HTML
      ↓
Security Assessment Report
```

RawaRontek diarahkan menjadi orchestrator assessment yang mengubah banyak output scanner menjadi satu hasil yang lebih terstruktur, dapat ditelusuri evidence-nya, dan dapat dikembangkan menuju dashboard atau vulnerability management di masa depan.

## 20. Kredit

Orchestrator Script by [@rskabc](https://github.com/rskabc)

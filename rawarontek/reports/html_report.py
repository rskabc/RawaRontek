from __future__ import annotations

from html import escape
from pathlib import Path


def write_html(target: str, summary: dict[str, object], findings: list[dict[str, object]], path: Path) -> Path:
    rows = []
    for item in findings:
        rows.append(
            "<tr>"
            f"<td>{escape(str(item.get('severity', 'INFO')))}</td>"
            f"<td>{escape(str(item.get('cve', '-')))}</td>"
            f"<td>{escape(str(item.get('product', '-')))}</td>"
            f"<td>{escape(str(item.get('version', '-')))}</td>"
            f"<td>{escape(str(item.get('cvss', '-')))}</td>"
            f"<td>{'YES' if item.get('cisa_kev') else 'NO'}</td>"
            f"<td>{escape(str(item.get('confidence', '-')))}</td>"
            "</tr>"
        )
    body = "".join(rows) or "<tr><td colspan='7'>No CVE correlations.</td></tr>"
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RawaRontek Report - {escape(target)}</title>
<style>body{{font-family:Arial,sans-serif;max-width:1200px;margin:40px auto;padding:0 20px}}table{{width:100%;border-collapse:collapse}}th,td{{border:1px solid #ddd;padding:9px;text-align:left;font-size:14px}}th{{background:#f4f4f4}}pre{{white-space:pre-wrap;background:#f7f7f7;padding:15px;overflow:auto}}.note{{padding:12px;background:#fff8e1;border-left:4px solid #d99b00}}</style>
</head><body><h1>RawaRontek Security Report</h1><p><strong>Target:</strong> {escape(target)}</p>
<div class="note"><strong>Important:</strong> CVE correlations are candidates. A matching product/version does not by itself prove that the target is vulnerable. Validate exact CPE applicability and vendor advisory before remediation or reporting.</div>
<h2>Summary</h2><pre>{escape(str(summary))}</pre>
<h2>CVE Intelligence</h2><table><thead><tr><th>Severity</th><th>CVE</th><th>Product</th><th>Version</th><th>CVSS</th><th>CISA KEV</th><th>Confidence</th></tr></thead><tbody>{body}</tbody></table>
</body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path

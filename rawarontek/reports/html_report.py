from __future__ import annotations

from html import escape
from pathlib import Path


def write_html(target: str, summary: dict[str, object], findings: list[dict[str, object]], path: Path) -> Path:
    rows = []
    for item in findings:
        rows.append(
            "<tr>"
            f"<td>{escape(str(item.get('severity', 'INFO')))}</td>"
            f"<td>{escape(str(item.get('product', '-')))}</td>"
            f"<td>{escape(str(item.get('version', '-')))}</td>"
            f"<td>{escape(str(item.get('confidence', '-')))}</td>"
            "</tr>"
        )
    body = "".join(rows) or "<tr><td colspan='4'>No correlated CVE candidates.</td></tr>"
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>RawaRontek Report - {escape(target)}</title>
<style>body{{font-family:Arial,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px}}table{{width:100%;border-collapse:collapse}}th,td{{border:1px solid #ddd;padding:10px;text-align:left}}th{{background:#f4f4f4}}code{{background:#f5f5f5;padding:2px 4px}}</style>
</head><body><h1>RawaRontek Security Report</h1><p><strong>Target:</strong> {escape(target)}</p>
<h2>Summary</h2><pre>{escape(str(summary))}</pre>
<h2>Potential CVE Correlations</h2><table><thead><tr><th>Severity</th><th>Product</th><th>Version</th><th>Confidence</th></tr></thead><tbody>{body}</tbody></table>
</body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path

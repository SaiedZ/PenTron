"""HTML report generation (standalone dark-themed single-file report)."""

from html import escape

from markdown_it import MarkdownIt

from . import common


def export_html(data: dict, output_dir: str) -> str:
    sl, tgt, date, risk, ai = common.session_summary(data)
    rc = common.RISK_COLORS.get(risk.upper(), "#7f8c8d")
    filename = common.safe_filename(output_dir, sl, tgt, "html")
    tgt, date, risk = escape(str(tgt)), escape(str(date)), escape(str(risk))

    vuln_rows = ""
    for v in data["vulns"]:
        sc = common.SEVERITY_COLORS.get((v[3] or "unknown").lower(), "#7f8c8d")
        name, description = escape(str(v[2] or "")), escape(str(v[6] or ""))
        severity = escape(str((v[3] or "unknown").upper()))
        port, service = escape(str(v[4] or "-")), escape(str(v[5] or "-"))
        vuln_rows += (
            f"<tr><td>{v[0]}</td>"
            f"<td><strong>{name}</strong><br><small>{description}</small></td>"
            f"<td><span style='color:{sc};font-weight:bold'>"
            f"{severity}</span></td><td>{port}</td><td>{service}</td></tr>"
        )

    fix_rows = ""
    for f in data["fixes"]:
        fix_text, source = escape(str(f[3] or "-")), escape(str(f[4] or "ai"))
        fix_rows += (
            f"<tr><td>{f[0]}</td><td>vuln #{f[2]}</td>"
            f"<td><code>{fix_text}</code></td><td>{source}</td></tr>"
        )

    exp_rows = ""
    for e in data["exploits"]:
        name, tool = escape(str(e[2] or "-")), escape(str(e[3] or "-"))
        payload = escape(str(e[4] or "-")[:80])
        result = escape(str(e[5] or "-"))
        exp_rows += (
            f"<tr><td>{e[0]}</td><td>{name}</td><td>{tool}</td>"
            f"<td><code>{payload}</code></td><td>{result}</td></tr>"
        )

    ai_html = MarkdownIt("commonmark", {"html": False, "linkify": False}).render(
        str(ai)
    )
    suggestion_rows = "".join(
        "<tr><td>"
        + escape(str(row[2] or ""))
        + "</td><td>"
        + escape(str(row[3] or ""))
        + "</td><td>"
        + escape(str(row[4] or "-"))
        + "</td></tr>"
        for row in data.get("suggestions", [])
    )
    call_rows = "".join(
        "<tr><td>"
        + escape(str(row[2] or ""))
        + "</td><td><code>"
        + escape(str(row[3] or ""))
        + "</code></td><td>"
        + ("blocked" if row[5] else "executed")
        + "</td></tr>"
        for row in data.get("tool_calls", [])
    )
    suggestions_html = (
        f"<table><tbody>{suggestion_rows}</tbody></table>"
        if suggestion_rows
        else '<p style="color:#888">None recorded.</p>'
    )
    calls_html = (
        f"<table><tbody>{call_rows}</tbody></table>"
        if call_rows
        else '<p style="color:#888">None executed.</p>'
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PenTron Report — {tgt}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',sans-serif;background:#0d0d0d;color:#e0e0e0;padding:30px}}
.container{{max-width:960px;margin:auto}}
.header{{border-left:5px solid #c0392b;padding-left:16px;margin-bottom:30px}}
.header h1{{font-size:2.2em;color:#c0392b}}
.header p{{color:#888;font-size:.95em}}
.meta-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:30px}}
.meta-card{{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:14px}}
.meta-card .label{{font-size:.75em;color:#888;text-transform:uppercase;
                   margin-bottom:4px}}
.meta-card .value{{font-size:1.1em;font-weight:bold}}
.risk{{color:{rc}}}
section{{margin-bottom:30px}}
section h2{{font-size:1.2em;color:#c0392b;border-bottom:1px solid #333;
            padding-bottom:8px;margin-bottom:14px}}
table{{width:100%;border-collapse:collapse;font-size:.88em}}
th{{background:#1e1e1e;color:#aaa;text-align:left;padding:10px;
    font-size:.8em;text-transform:uppercase;border-bottom:2px solid #333}}
td{{padding:10px;border-bottom:1px solid #222;vertical-align:top}}
tr:hover td{{background:#1a1a1a}}
code{{background:#1e1e1e;padding:2px 6px;border-radius:3px;
      font-family:monospace;font-size:.85em;color:#e74c3c}}
.ai-box{{background:#111;border:1px solid #333;border-radius:6px;
         padding:16px;font-size:.9em;line-height:1.7;color:#ccc}}
.ai-box p{{margin-bottom:8px}}
.footer{{text-align:center;color:#444;font-size:.78em;
         margin-top:40px;border-top:1px solid #222;padding-top:16px}}
a{{color:#555}}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1>🔱 PENTRON</h1>
  <p>AI Penetration Testing Report</p>
</div>

<div class="meta-grid">
  <div class="meta-card">
    <div class="label">Target</div>
    <div class="value">{tgt}</div>
  </div>
  <div class="meta-card">
    <div class="label">Session</div>
    <div class="value">SL# {sl}</div>
  </div>
  <div class="meta-card">
    <div class="label">Scan Date</div>
    <div class="value">{date}</div>
  </div>
  <div class="meta-card">
    <div class="label">Risk Level</div>
    <div class="value risk">{risk}</div>
  </div>
</div>

<section>
  <h2>Vulnerabilities</h2>
  {
        (
            "<table><thead><tr><th>#</th><th>Vulnerability</th>"
            "<th>Severity</th><th>Port</th><th>Service</th></tr></thead><tbody>"
            + vuln_rows
            + "</tbody></table>"
        )
        if data["vulns"]
        else '<p style="color:#888">None recorded.</p>'
    }
</section>

<section>
  <h2>Fixes &amp; Mitigations</h2>
  {
        (
            "<table><thead><tr><th>#</th><th>Vuln</th><th>Fix</th>"
            "<th>Source</th></tr></thead><tbody>" + fix_rows + "</tbody></table>"
        )
        if data["fixes"]
        else '<p style="color:#888">None recorded.</p>'
    }
</section>

<section>
  <h2>Exploits Attempted</h2>
  {
        (
            "<table><thead><tr><th>#</th><th>Exploit</th><th>Tool</th>"
            "<th>Payload</th><th>Result</th></tr></thead><tbody>"
            + exp_rows
            + "</tbody></table>"
        )
        if data["exploits"]
        else '<p style="color:#888">None recorded.</p>'
    }
</section>

<section>
  <h2>AI Analysis Summary</h2>
  <div class="ai-box">
    {ai_html if ai_html else '<p style="color:#888">None recorded.</p>'}
  </div>
</section>

<section>
  <h2>Suggested Exploit Paths</h2>
  {suggestions_html}
</section>

<section>
  <h2>AI-dispatched Tool Calls</h2>
  {calls_html}
</section>

<div class="footer">
  Generated by PENTRON &mdash;
  <a href="https://github.com/SaiedZ/PenTron">github.com/SaiedZ/PenTron</a>
  &mdash; For authorized use only.
</div>

</div>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)
    return filename

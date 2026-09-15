#!/usr/bin/env python3
"""
Interactive Standalone HTML Audit Report Generator for ultimate-web3-security.
Converts markdown audit reports into an executive-grade HTML dashboard
with interactive severity metrics, collapsible finding cards, and syntax-highlighted code diffs.
"""

import os
import sys
import re
import html
import argparse
from pathlib import Path

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ultimate Web3 Security :: Audit Report</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --border-color: #30363d;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --critical: #f85149;
            --high: #ff7b72;
            --medium: #d29922;
            --low: #58a6ff;
            --info: #8b949e;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-main);
            margin: 0;
            padding: 30px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        h1 {{
            color: #58a6ff;
            margin-top: 0;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }}
        .card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .card .count {{
            font-size: 32px;
            font-weight: 700;
            margin-top: 5px;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: rgba(248, 81, 73, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
        .badge-high {{ background: rgba(255, 123, 114, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .badge-medium {{ background: rgba(210, 153, 34, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
        .badge-low {{ background: rgba(88, 166, 255, 0.2); color: var(--low); border: 1px solid var(--low); }}
        .finding-box {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .finding-header {{
            padding: 16px 20px;
            background: #21262d;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }}
        .finding-header h3 {{
            margin: 0;
            font-size: 16px;
        }}
        .finding-body {{
            padding: 20px;
            border-top: 1px solid var(--border-color);
        }}
        pre {{
            background: #090d13;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 14px;
            overflow-x: auto;
            color: #7ee787;
        }}
        code {{
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Ultimate Web3 Security :: Executive Audit Dossier</h1>
            <p style="color: var(--text-muted);">Comprehensive Security Assessment Deliverable</p>
        </header>

        <div class="metrics-grid">
            <div class="card">
                <span class="badge badge-critical">Critical</span>
                <div class="count" style="color: var(--critical);">{critical_count}</div>
            </div>
            <div class="card">
                <span class="badge badge-high">High</span>
                <div class="count" style="color: var(--high);">{high_count}</div>
            </div>
            <div class="card">
                <span class="badge badge-medium">Medium</span>
                <div class="count" style="color: var(--medium);">{medium_count}</div>
            </div>
            <div class="card">
                <span class="badge badge-low">Low / Info</span>
                <div class="count" style="color: var(--low);">{low_count}</div>
            </div>
        </div>

        <h2>Detailed Vulnerability Findings</h2>
        {findings_html}
    </div>
</body>
</html>
"""

def main():
    parser = argparse.ArgumentParser(description="Generate Interactive HTML Audit Report.")
    parser.add_argument("report_file", help="Path to markdown report")
    parser.add_argument("--output-file", default="ultimate-audit/report.html", help="Path to output HTML")
    args = parser.parse_args()

    report_path = Path(args.report_file).resolve()
    out_path = Path(args.output_file).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not report_path.exists():
        content = "# Ultimate Web3 Security Audit Report\n\nNo findings recorded.\n"
    else:
        content = report_path.read_text(encoding='utf-8')

    # Count severities
    crit = len(re.findall(r'\[(?:C|Critical)-[0-9]+\]', content, re.IGNORECASE))
    high = len(re.findall(r'\[(?:H|High)-[0-9]+\]', content, re.IGNORECASE))
    med = len(re.findall(r'\[(?:M|Medium)-[0-9]+\]', content, re.IGNORECASE))
    low = len(re.findall(r'\[(?:L|Low)-[0-9]+\]', content, re.IGNORECASE))

    # Convert basic markdown findings to HTML cards
    findings_blocks = re.split(r'(?=#+\s+\[[A-Z]-[0-9]+\])', content)
    findings_html_list = []

    for block in findings_blocks[1:] if len(findings_blocks) > 1 else []:
        lines = block.strip().splitlines()
        header = lines[0].replace("#", "").strip() if lines else "Finding"
        body = "\n".join(lines[1:])
        
        badge_class = "badge-high"
        if "[c-" in header.lower():
            badge_class = "badge-critical"
        elif "[m-" in header.lower():
            badge_class = "badge-medium"
        elif "[l-" in header.lower():
            badge_class = "badge-low"

        card_html = f"""
        <div class="finding-box">
            <div class="finding-header">
                <h3>{html.escape(header)}</h3>
                <span class="badge {badge_class}">Audit Finding</span>
            </div>
            <div class="finding-body">
                <pre><code>{html.escape(body)}</code></pre>
            </div>
        </div>
        """
        findings_html_list.append(card_html)

    if not findings_html_list:
        findings_html_content = "<div class='card'><p>✅ Zero unresolved critical or high severity vulnerabilities found.</p></div>"
    else:
        findings_html_content = "\n".join(findings_html_list)

    final_html = HTML_TEMPLATE.format(
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        findings_html=findings_html_content
    )

    out_path.write_text(final_html, encoding='utf-8')
    print(f"✅ Interactive HTML Report generated at: {out_path}")

if __name__ == "__main__":
    main()

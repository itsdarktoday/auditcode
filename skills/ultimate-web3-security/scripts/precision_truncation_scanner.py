#!/usr/bin/env python3
"""
Precision Truncation & Division-Before-Multiplication Scanner for ultimate-web3-security.
Scans Solidity source code for intermediate integer division preceding multiplication,
which causes severe precision loss / zero-value results for low-decimal tokens (USDC, WBTC).
"""

import os
import sys
import re
import argparse
from pathlib import Path

def scan_precision_truncation(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    findings = []
    
    # Patterns detecting division before multiplication
    # 1. (a / b) * c
    # 2. x / y * z
    div_mul_patterns = [
        (r'\([^\)]+\s*/\s*[^\)]+\)\s*\*+\s*[a-zA-Z0-9_\.]+', "Explicit parenthesized division before multiplication: `(a / b) * c`"),
        (r'\b[a-zA-Z0-9_\.]+\s*/\s*[a-zA-Z0-9_\.]+\s*\*\s*[a-zA-Z0-9_\.]+', "Unparenthesized division before multiplication: `a / b * c`")
    ]

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        # Skip import and pragma lines
        if "import" in stripped or "pragma" in stripped:
            continue

        for pat, desc in div_mul_patterns:
            matches = re.findall(pat, stripped)
            if matches:
                findings.append({
                    "line": line_num,
                    "expression": matches[0],
                    "description": desc,
                    "code_snippet": stripped,
                    "remediation": "Re-order operations to multiply before dividing: `(a * c) / b` or use `mulDiv(a, c, b)`."
                })

    return findings

def main():
    parser = argparse.ArgumentParser(description="Division-Before-Multiplication Precision Scanner.")
    parser.add_argument("target_dir", help="Path to project repository")
    parser.add_argument("--output-file", default="ultimate-audit/precision_truncation.md", help="Output report")
    args = parser.parse_args()

    target_path = Path(args.target_dir).resolve()
    out_path = Path(args.output_file).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    all_findings = []
    for sol_file in target_path.rglob("*.sol"):
        if any(x in sol_file.parts for x in ["test", "tests", "mocks", "mock", "lib", "node_modules"]):
            continue
        findings = scan_precision_truncation(sol_file)
        if findings:
            all_findings.append((sol_file.relative_to(target_path), findings))

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("# Precision Truncation & Division-Before-Multiplication Report\n\n")
        if not all_findings:
            f.write("✅ Zero division-before-multiplication precision hazards detected.\n")
        else:
            for rel_path, items in all_findings:
                f.write(f"## Contract: `{rel_path}`\n\n")
                f.write("| Line | Vulnerable Expression | Code Snippet | Remediation |\n")
                f.write("|---|---|---|---|\n")
                for item in items:
                    f.write(f"| L{item['line']} | `{item['expression']}` | `{item['code_snippet'][:45]}` | {item['remediation']} |\n")
                f.write("\n")

    print(f"✅ Precision Truncation Scan complete. Report saved to {out_path}")

if __name__ == "__main__":
    main()

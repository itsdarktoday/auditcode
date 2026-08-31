#!/usr/bin/env python3
"""
EIP-150 63/64 Gas Forwarding & Silent Subcall Revert Scanner for ultimate-web3-security.
Detects low-level external calls and try/catch blocks that ignore return status or fail
to enforce minimum gas boundaries, enabling attacker gas griefing.
"""

import os
import sys
import re
import argparse
from pathlib import Path

def scan_eip150_gas_hazards(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    findings = []
    content = "".join(lines)

    # 1. Detect unchecked low-level calls: (bool success, ) = target.call(...) without require(success)
    call_matches = re.finditer(r'\(\s*bool\s+([a-zA-Z0-9_]+)\s*,[^\)]*\)\s*=\s*[a-zA-Z0-9_\.]+\.call\{[^\}]*\}\([^\)]*\);', content)
    for match in call_matches:
        var_name = match.group(1)
        subsequent_text = content[match.end():match.end()+300]
        # Check if require(var_name) or if (!var_name) revert exists
        has_check = bool(re.search(rf'require\s*\(\s*{var_name}\b|if\s*\(\s*!{var_name}\b', subsequent_text))
        if not has_check:
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                "line": line_num,
                "severity": "HIGH",
                "hazard": "Unchecked Low-Level Call (Return Value Ignored)",
                "description": f"External low-level call result `{var_name}` is not validated. If call fails, execution silently continues!",
                "remediation": f"Add `require({var_name}, 'External call failed');`."
            })

    # 2. Detect try/catch blocks without gasleft() validation
    try_blocks = re.finditer(r'try\s+[a-zA-Z0-9_\.]+\s*\([^\)]*\)[^{]*\{[\s\S]*?\}\s*catch\s*\{', content)
    for match in try_blocks:
        preceding_text = content[max(0, match.start()-200):match.start()]
        has_gas_check = bool(re.search(r'gasleft\(\)\s*>=', preceding_text))
        if not has_gas_check:
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                "line": line_num,
                "severity": "MEDIUM",
                "hazard": "try/catch Subcall Vulnerable to 63/64 Gas Griefing",
                "description": "Subcall wrapped in try/catch without `require(gasleft() >= MIN_GAS)`. Attacker can supply restricted gas to force subcall revert while parent tx succeeds.",
                "remediation": "Validate `require(gasleft() >= MIN_GAS, 'Insufficient gas');` before executing try/catch subcalls."
            })

    return findings

def main():
    parser = argparse.ArgumentParser(description="EIP-150 63/64 Gas Rule Hazard Scanner.")
    parser.add_argument("target_dir", help="Path to project repository")
    parser.add_argument("--output-file", default="ultimate-audit/gas_griefing_hazards.md", help="Output report")
    args = parser.parse_args()

    target_path = Path(args.target_dir).resolve()
    out_path = Path(args.output_file).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    all_findings = []
    for sol_file in target_path.rglob("*.sol"):
        if any(x in sol_file.parts for x in ["test", "tests", "mocks", "mock", "lib", "node_modules"]):
            continue
        findings = scan_eip150_gas_hazards(sol_file)
        if findings:
            all_findings.append((sol_file.relative_to(target_path), findings))

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("# EIP-150 Gas Forwarding & Griefing Hazard Report\n\n")
        if not all_findings:
            f.write("✅ Zero EIP-150 gas griefing or unchecked subcall hazards detected.\n")
        else:
            for rel_path, items in all_findings:
                f.write(f"## Contract: `{rel_path}`\n\n")
                f.write("| Line | Severity | Hazard Type | Description | Remediation |\n")
                f.write("|---|---|---|---|---|\n")
                for item in items:
                    f.write(f"| L{item['line']} | {item['severity']} | {item['hazard']} | {item['description']} | {item['remediation']} |\n")
                f.write("\n")

    print(f"✅ EIP-150 Gas Scan complete. Report saved to {out_path}")

if __name__ == "__main__":
    main()

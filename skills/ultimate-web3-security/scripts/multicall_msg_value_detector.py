#!/usr/bin/env python3
"""
Payable Multicall & msg.value Loop Reuse Detector for ultimate-web3-security.
Scans for batching/multicall functions that are marked 'payable' or accept msg.value
and iterate over delegatecalls, subcalls, or state mutations reusing msg.value.
(The landmark SushiSwap Trident / Opyn / OpenSea bug class).
"""

import os
import sys
import re
import argparse
from pathlib import Path

def scan_multicall_msg_value(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    findings = []
    
    # 1. Detect multicall functions with payable visibility
    multicall_pattern = r'(function\s+(multicall|batch|aggregate|executeBatch)\s*\([^\)]*\)\s*[^\{]*payable[^{]*\{([\s\S]*?)\n\s*\})'
    matches = re.findall(multicall_pattern, content, re.IGNORECASE)

    for full_match, func_name, _, func_body in matches:
        # Check if msg.value or delegatecall is used inside a loop
        has_loop = bool(re.search(r'\b(for|while)\s*\(', func_body))
        has_msg_value = bool(re.search(r'\bmsg\.value\b', func_body))
        has_delegatecall = bool(re.search(r'\bdelegatecall\b', func_body))

        if has_loop and (has_msg_value or has_delegatecall):
            findings.append({
                "function": func_name,
                "severity": "CRITICAL",
                "hazard": "Payable Multicall with Loop / msg.value Reuse",
                "description": (
                    f"Function `{func_name}()` is marked `payable` and executes a loop with `msg.value` or `delegatecall`. "
                    "An attacker can pass 1 ETH and execute 10 sub-actions, each reusing the same 1 ETH deposit value (10x deposit inflation)!"
                ),
                "remediation": "Do not allow payable multicalls, or track spent msg.value per iteration and assert balance."
            })

    # 2. Detect msg.value used inside loops in any payable function
    loop_functions = re.findall(r'(function\s+([a-zA-Z0-9_]+)\s*\([^\)]*\)\s*[^\{]*payable[^{]*\{([\s\S]*?)\n\s*\})', content)
    for full_match, func_name, _, func_body in loop_functions:
        if func_name in [f["function"] for f in findings]:
            continue
        for_loop_with_msg_val = re.search(r'for\s*\([^\)]*\)\s*\{[\s\S]*?\bmsg\.value\b[\s\S]*?\}', func_body)
        if for_loop_with_msg_val:
            findings.append({
                "function": func_name,
                "severity": "HIGH",
                "hazard": "msg.value Read Inside Loop",
                "description": f"`msg.value` is read inside a loop in payable function `{func_name}()`. Each iteration uses the initial total msg.value.",
                "remediation": "Deduct spent value per loop or use an internal tracking variable."
            })

    return findings

def main():
    parser = argparse.ArgumentParser(description="Payable Multicall msg.value Loop Reuse Detector.")
    parser.add_argument("target_dir", help="Path to project repository")
    parser.add_argument("--output-file", default="ultimate-audit/multicall_hazards.md", help="Output markdown report")
    args = parser.parse_args()

    target_path = Path(args.target_dir).resolve()
    out_path = Path(args.output_file).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    all_findings = []
    for sol_file in target_path.rglob("*.sol"):
        if any(x in sol_file.parts for x in ["test", "tests", "mocks", "mock", "lib", "node_modules"]):
            continue
        findings = scan_multicall_msg_value(sol_file)
        if findings:
            all_findings.append((sol_file.relative_to(target_path), findings))

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("# Payable Multicall & msg.value Reuse Report\n\n")
        f.write("Scans for batch functions reusing msg.value across loop iterations (Sushi Trident / Opyn exploit class).\n\n")

        if not all_findings:
            f.write("✅ Zero payable multicall msg.value reuse hazards detected.\n")
        else:
            for rel_path, items in all_findings:
                f.write(f"## Contract: `{rel_path}`\n\n")
                for item in items:
                    f.write(f"### Function: `{item['function']}()` — **{item['severity']}: {item['hazard']}**\n\n")
                    f.write(f"- **Impact:** {item['description']}\n")
                    f.write(f"- **Remediation:** {item['remediation']}\n\n")

    print(f"✅ Multicall msg.value scan complete. Report written to {out_path}")

if __name__ == "__main__":
    main()

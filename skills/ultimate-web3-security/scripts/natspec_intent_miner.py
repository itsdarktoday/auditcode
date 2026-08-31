#!/usr/bin/env python3
"""
Semantic NatSpec Intent-vs-Code Contradiction Miner for ultimate-web3-security.
Extracts developer intent from NatSpec comments (@notice, @dev, @custom:invariant)
and verifies whether the Solidity implementation contradicts its documented promises.
"""

import os
import sys
import re
import argparse
from pathlib import Path

INTENT_RULES = [
    {
        "claim_regex": r"(only\s+admin|only\s+owner|governance\s+only|restricted\s+to\s+authorized|must\s+be\s+owner)",
        "required_guard": r"onlyOwner|onlyRole|onlyAdmin|msg\.sender\s*==\s*owner|msg\.sender\s*==\s*admin|_checkOwner",
        "category": "Access Control Intent Violation",
        "description": "NatSpec states function is restricted to admin/owner, but no access modifier or caller check exists in code!"
    },
    {
        "claim_regex": r"(cannot\s+be\s+zero|must\s+be\s+(non-zero|positive|greater\s+than\s+0)|amount\s+>\s+0)",
        "required_guard": r"require\s*\([^;]*>\s*0|revert\s+Zero|if\s*\([^;]*==\s*0\)\s*revert",
        "category": "Zero-Value Guard Intent Violation",
        "description": "NatSpec specifies parameter cannot be zero, but zero-check assertion is omitted in function body!"
    },
    {
        "claim_regex": r"(non-reentrant|cannot\s+be\s+re-entered|protected\s+against\s+reentrancy)",
        "required_guard": r"nonReentrant|_nonReentrantAfter|TLOAD|TSTORE",
        "category": "Reentrancy Guard Intent Violation",
        "description": "NatSpec claims reentrancy protection, but no reentrancy modifier or transient lock exists!"
    }
]

def analyze_natspec_contradictions(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Regex to capture NatSpec block + function signature and body
    pattern = r'(/\*\*[\s\S]*?\*/)\s*(function\s+([a-zA-Z0-9_]+)\s*\([^\)]*\)[^{]*\{([\s\S]*?)\n\s*\})'
    matches = re.findall(pattern, content)

    contradictions = []
    for doc, func_full, func_name, func_body in matches:
        doc_lower = doc.lower()
        for rule in INTENT_RULES:
            if re.search(rule["claim_regex"], doc_lower):
                # Intent claimed in NatSpec
                if not re.search(rule["required_guard"], func_full):
                    contradictions.append({
                        "function": func_name,
                        "category": rule["category"],
                        "description": rule["description"],
                        "natspec_excerpt": doc.strip()
                    })

    return contradictions

def main():
    parser = argparse.ArgumentParser(description="NatSpec Intent-vs-Code Contradiction Miner.")
    parser.add_argument("target_dir", help="Path to project repository")
    parser.add_argument("--output-file", default="ultimate-audit/natspec_contradictions.md", help="Output report")
    args = parser.parse_args()

    target_path = Path(args.target_dir).resolve()
    out_path = Path(args.output_file).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    all_contradictions = []
    for sol_file in target_path.rglob("*.sol"):
        if any(x in sol_file.parts for x in ["test", "tests", "mocks", "mock", "lib", "node_modules"]):
            continue
        findings = analyze_natspec_contradictions(sol_file)
        if findings:
            all_contradictions.append((sol_file.relative_to(target_path), findings))

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("# NatSpec Intent-vs-Code Contradiction Report\n\n")
        f.write("Identifies silent logic discrepancies where code violates developer NatSpec promises.\n\n")

        if not all_contradictions:
            f.write("✅ Zero NatSpec intent contradictions detected.\n")
        else:
            for rel_path, items in all_contradictions:
                f.write(f"## Contract: `{rel_path}`\n\n")
                for c in items:
                    f.write(f"### Function: `{c['function']}()` — **{c['category']}**\n\n")
                    f.write(f"**Discrepancy:** {c['description']}\n\n")
                    f.write("```solidity\n// Documented NatSpec:\n" + c['natspec_excerpt'] + "\n```\n\n")

    print(f"✅ NatSpec Contradiction Scan complete. Report saved to {out_path}")

if __name__ == "__main__":
    main()

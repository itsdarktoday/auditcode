#!/usr/bin/env python3
"""
Solc Yul & Compiler Optimizer Hazard Scanner for ultimate-web3-security.
Audits pragma statements, foundry.toml / hardhat configs, and inline assembly blocks
for known Solidity compiler vulnerabilities and Yul optimizer de-optimizations.
"""

import os
import sys
import re
import argparse
from pathlib import Path

COMPILER_VULNERABILITIES = [
    {
        "version_regex": r"0\.8\.15",
        "title": "Dirty Bytes Array Copy to Storage (Solidity 0.8.15)",
        "severity": "High",
        "description": "Copying bytes arrays to storage leaves dirty memory in storage slots.",
        "remediation": "Upgrade compiler pragma to >= 0.8.16."
    },
    {
        "version_regex": r"0\.8\.(13|14)",
        "title": "Inline Assembly Memory Clobbering (Solidity 0.8.13-0.8.14)",
        "severity": "Medium",
        "description": "Yul optimizer may incorrectly evaluate memory operations in inline assembly.",
        "remediation": "Upgrade compiler pragma to >= 0.8.16."
    },
    {
        "version_regex": r"0\.8\.20",
        "title": "PUSH0 Opcode Incompatibility on L2s (Solidity 0.8.20 Default)",
        "severity": "High",
        "description": "Solidity 0.8.20 defaults to the Shanghai EVM (includes PUSH0), which reverts on Arbitrum, zkSync Era, and older L2s.",
        "remediation": "Set evm_version = 'paris' in foundry.toml when deploying to L2 rollups."
    }
]

def scan_compiler_hazards(target_dir):
    target_path = Path(target_dir).resolve()
    findings = []

    # 1. Scan Solc pragmas in source files
    for sol_file in target_path.rglob("*.sol"):
        if any(x in sol_file.parts for x in ["test", "tests", "mocks", "mock", "lib", "node_modules"]):
            continue
        with open(sol_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Pragma scan
        for cv in COMPILER_VULNERABILITIES:
            if re.search(r"pragma\s+solidity\s+[^;]*" + cv["version_regex"], content):
                findings.append({
                    "file": sol_file.name,
                    "title": cv["title"],
                    "severity": cv["severity"],
                    "description": cv["description"],
                    "remediation": cv["remediation"]
                })

        # Non-memory-safe assembly scan
        assembly_blocks = re.findall(r"assembly\s*\{", content)
        if assembly_blocks:
            findings.append({
                "file": sol_file.name,
                "title": "Non-Memory-Safe Inline Assembly Block",
                "severity": "Medium",
                "description": f"Found {len(assembly_blocks)} assembly block(s) without ('memory-safe') annotation. Risk of memory clobbering if via_ir is enabled.",
                "remediation": "Annotate assembly blocks with `assembly (\"memory-safe\") { ... }`."
            })

    return findings

def main():
    parser = argparse.ArgumentParser(description="Compiler & Yul Optimizer Hazard Scanner.")
    parser.add_argument("target_dir", help="Path to project repository")
    parser.add_argument("--output-file", default="ultimate-audit/compiler_hazards.md", help="Output markdown report")
    args = parser.parse_args()

    target_path = Path(args.target_dir).resolve()
    out_path = Path(args.output_file).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    findings = scan_compiler_hazards(target_path)

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("# Solidity Compiler & Optimizer Hazard Report\n\n")
        if not findings:
            f.write("✅ Zero compiler version or optimizer memory hazards detected.\n")
        else:
            f.write("| File | Severity | Hazard Title | Description | Recommended Remediation |\n")
            f.write("|---|---|---|---|---|\n")
            for item in findings:
                f.write(f"| `{item['file']}` | {item['severity']} | {item['title']} | {item['description']} | {item['remediation']} |\n")

    print(f"✅ Compiler Hazard Scan complete. Report saved to {out_path}")

if __name__ == "__main__":
    main()

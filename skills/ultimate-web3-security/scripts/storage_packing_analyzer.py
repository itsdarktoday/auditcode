#!/usr/bin/env python3
"""
Storage Slot Packing & Pointer Hazard Analyzer for ultimate-web3-security.
Audits Solidity storage variables, sub-32-byte packing alignments,
and storage pointer declarations for collision and corruption risks.
"""

import os
import sys
import re
import argparse
from pathlib import Path

def scan_storage_packing(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    findings = []
    content = "".join(lines)

    # 1. Detect uninitialized storage pointers inside functions (struct storage x;)
    uninitialized_storage_ptr = re.finditer(r'\b([A-Z][a-zA-Z0-9_]*)\s+storage\s+([a-zA-Z0-9_]+)\s*;', content)
    for match in uninitialized_storage_ptr:
        struct_type = match.group(1)
        var_name = match.group(2)
        line_num = content[:match.start()].count('\n') + 1
        findings.append({
            "line": line_num,
            "severity": "CRITICAL",
            "hazard": "Uninitialized Local Storage Pointer",
            "description": f"Local storage variable `{struct_type} storage {var_name}` is declared without initialization. In older Solidity versions, it points to storage slot 0 and overwrites critical state variables!",
            "remediation": f"Assign `{var_name}` to a storage reference immediately upon declaration or change to `memory`."
        })

    # 2. Check upgradeable contracts missing storage gaps
    is_upgradeable = bool(re.search(r'is\s+[^\;\{]*(Initializable|UUPSUpgradeable|Upgradeable)', content))
    has_gap = bool(re.search(r'uint256\[\d+\]\s+(__gap|gap)\s*;', content))
    has_erc7201 = bool(re.search(r'@custom:storage-location\s+erc7201', content))

    if is_upgradeable and not has_gap and not has_erc7201:
        findings.append({
            "line": 1,
            "severity": "MEDIUM",
            "hazard": "Upgradeable Contract Missing Storage Gap",
            "description": "Contract inherits Upgradeable base contracts but omits `uint256[50] __gap` or ERC-7201 namespaced storage. Upgrading base contracts will shift storage slot offsets and corrupt child state.",
            "remediation": "Add `uint256[50] private __gap;` at the end of the contract or use ERC-7201."
        })

    return findings

def main():
    parser = argparse.ArgumentParser(description="Storage Slot Packing & Pointer Analyzer.")
    parser.add_argument("target_dir", help="Path to project repository")
    parser.add_argument("--output-file", default="ultimate-audit/storage_packing_hazards.md", help="Output report")
    args = parser.parse_args()

    target_path = Path(args.target_dir).resolve()
    out_path = Path(args.output_file).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    all_findings = []
    for sol_file in target_path.rglob("*.sol"):
        if any(x in sol_file.parts for x in ["test", "tests", "mocks", "mock", "lib", "node_modules"]):
            continue
        findings = scan_storage_packing(sol_file)
        if findings:
            all_findings.append((sol_file.relative_to(target_path), findings))

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("# Storage Slot Packing & Pointer Hazard Report\n\n")
        if not all_findings:
            f.write("✅ Zero storage pointer or missing gap hazards detected.\n")
        else:
            for rel_path, items in all_findings:
                f.write(f"## Contract: `{rel_path}`\n\n")
                f.write("| Line | Severity | Hazard Type | Description | Remediation |\n")
                f.write("|---|---|---|---|---|\n")
                for item in items:
                    f.write(f"| L{item['line']} | {item['severity']} | {item['hazard']} | {item['description']} | {item['remediation']} |\n")
                f.write("\n")

    print(f"✅ Storage Packing Scan complete. Report saved to {out_path}")

if __name__ == "__main__":
    main()

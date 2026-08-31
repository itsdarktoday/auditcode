#!/usr/bin/env python3
"""
Multi-L2 EVM Dialect & Execution Hazard Scanner for ultimate-web3-security.
Audits target Solidity code for chain-specific execution quirks across
Arbitrum, Optimism/Base, zkSync Era, and Polygon zkEVM.
"""

import os
import sys
import re
import argparse
from pathlib import Path

L2_HAZARDS = [
    {
        "id": "L2-ARB-01",
        "chain": "Arbitrum",
        "severity": "High",
        "pattern": r"block\.number",
        "rule": "block.number returns L1 block number on Arbitrum. Short timeframes will desync.",
        "remediation": "Use block.timestamp or ArbSys(100).arbBlockNumber() for L2 sequencing."
    },
    {
        "id": "L2-ZKSYNC-01",
        "chain": "zkSync Era",
        "severity": "High",
        "pattern": r"extcodesize\s*\(|tx\.origin\s*==\s*msg\.sender",
        "rule": "EOA vs Contract checks (extcodesize == 0) break native Account Abstraction on zkSync.",
        "remediation": "Remove extcodesize EOA validation; use ERC-1271 isValidSignature."
    },
    {
        "id": "L2-OP-01",
        "chain": "Optimism / Base",
        "severity": "Medium",
        "pattern": r"address\(this\)\.balance\s*[\);]",
        "rule": "Exact balance sweeps can revert on OP Stack if L1 Data Gas fees are deducted from contract.",
        "remediation": "Reserve gas buffer or allow partial parameter balance sweeps."
    },
    {
        "id": "L2-PREVRANDAO-01",
        "chain": "All L2s",
        "severity": "Medium",
        "pattern": r"block\.prevrandao|block\.difficulty",
        "rule": "PREVRANDAO / DIFFICULTY is sequencer-controlled or constant on L2 rollups.",
        "remediation": "Do not use prevrandao/difficulty for randomness on L2; use Chainlink VRF."
    },
    {
        "id": "L2-COINBASE-01",
        "chain": "All L2s",
        "severity": "Low",
        "pattern": r"block\.coinbase",
        "rule": "block.coinbase returns the Sequencer Fee Vault on L2, not a block builder.",
        "remediation": "Ensure fee routing addresses are configurable rather than hardcoded to coinbase."
    }
]

def scan_file(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    findings = []
    for line_num, line in enumerate(lines, 1):
        # Skip comments
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        for hazard in L2_HAZARDS:
            if re.search(hazard["pattern"], line):
                findings.append({
                    "id": hazard["id"],
                    "chain": hazard["chain"],
                    "severity": hazard["severity"],
                    "line_num": line_num,
                    "line_content": stripped,
                    "rule": hazard["rule"],
                    "remediation": hazard["remediation"]
                })
    return findings

def main():
    parser = argparse.ArgumentParser(description="Multi-L2 EVM Dialect Hazard Scanner.")
    parser.add_argument("target_dir", help="Path to project repository")
    parser.add_argument("--output-file", default="ultimate-audit/l2_hazards.md", help="Output markdown report")
    args = parser.parse_args()

    target_path = Path(args.target_dir).resolve()
    out_path = Path(args.output_file).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    all_hazards = []
    for sol_file in target_path.rglob("*.sol"):
        if any(x in sol_file.parts for x in ["test", "tests", "mocks", "mock", "lib", "node_modules"]):
            continue
        file_findings = scan_file(sol_file)
        if file_findings:
            all_hazards.append((sol_file.relative_to(target_path), file_findings))

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("# Multi-L2 EVM Dialect Hazard Report\n\n")
        f.write("Scans for chain-specific execution differences across Arbitrum, Optimism, Base, and zkSync Era.\n\n")

        if not all_hazards:
            f.write("✅ Zero L2 execution hazards detected.\n")
        else:
            for rel_path, findings in all_hazards:
                f.write(f"## File: `{rel_path}`\n\n")
                f.write("| Hazard ID | Target Chain | Severity | Line | Code Snippet | Hazard Description |\n")
                f.write("|---|---|---|---|---|---|\n")
                for item in findings:
                    f.write(f"| {item['id']} | {item['chain']} | {item['severity']} | L{item['line_num']} | `{item['line_content'][:40]}` | {item['rule']} |\n")
                f.write("\n")

    print(f"✅ L2 Hazard Scan complete. Report written to {out_path}")

if __name__ == "__main__":
    main()

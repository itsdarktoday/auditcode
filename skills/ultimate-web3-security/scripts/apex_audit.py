#!/usr/bin/env python3
"""
Apex Audit Engine for ultimate-web3-security.
The master autonomous execution runner. Runs all AST, differential, L2, math,
gas, multicall, and compiler scanners in a unified high-speed pipeline.
Emits a structured executive dossier for immediate agent ingestion.
"""

import os
import sys
import json
import subprocess
import argparse
from pathlib import Path

def run_script(script_path, args):
    if not os.path.exists(script_path):
        return ""
    cmd = [sys.executable, str(script_path)] + args
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.stdout.strip()

def main():
    parser = argparse.ArgumentParser(description="Master Apex Web3 Security Engine.")
    parser.add_argument("target_dir", help="Path to project repository to audit")
    parser.add_argument("--output-dir", default="", help="Directory for audit outputs")
    args = parser.parse_args()

    target = Path(args.target_dir).resolve()
    script_dir = Path(__file__).parent.resolve()
    skill_root = script_dir.parent.resolve()

    if args.output_dir:
        out_dir = Path(args.output_dir).resolve()
    else:
        out_dir = target / "ultimate-audit"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("================================================================================")
    print(" ⚡ ULTIMATE WEB3 SECURITY :: APEX AUTONOMOUS AUDIT ENGINE")
    print("================================================================================")
    print(f"[*] Target Repository: {target}")
    print(f"[*] Audit Workspace:  {out_dir}")

    # 1. Enumerate Scope & SLOC
    sol_files = [f for f in target.rglob("*.sol") if not any(x in f.parts for x in ["test", "tests", "mocks", "mock", "lib", "node_modules", "out", "cache"])]
    total_sloc = 0
    for f in sol_files:
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
                total_sloc += len([line for line in fp if line.strip() and not line.strip().startswith("//")])
        except Exception:
            pass

    print(f"[*] Scope: {len(sol_files)} in-scope contracts | {total_sloc:,} SLOC")
    print("--------------------------------------------------------------------------------")
    print("[*] Running Autonomous Scanning Pipeline...")

    # 2. Run AST & Storage Slot Topology
    print("  -> [1/7] Extracting AST Storage Slot Topology...")
    run_script(script_dir / "extract_ast_topology.py", [str(target), "--output-file", str(out_dir / "topology.md")])

    # 3. Run Differential Specification Miner
    print("  -> [2/7] Mining Canonical Differential Specs (ERC-4626 / Compound / Staking)...")
    diff_report = out_dir / "differential_spec_report.md"
    run_script(script_dir / "differential_spec_miner.py", [str(target), "--output-file", str(diff_report)])

    # 4. Run L2 & Rollup Hazard Scanner
    print("  -> [3/7] Scanning Multi-L2 EVM Dialect Hazards (Arbitrum, zkSync, OP Stack)...")
    l2_report = out_dir / "l2_hazards.md"
    run_script(script_dir / "l2_hazard_scanner.py", [str(target), "--output-file", str(l2_report)])

    # 5. Run Payable Multicall & msg.value Reuse Detector
    print("  -> [4/7] Detecting Payable Multicall Loop & msg.value Re-use...")
    multicall_report = out_dir / "multicall_hazards.md"
    run_script(script_dir / "multicall_msg_value_detector.py", [str(target), "--output-file", str(multicall_report)])

    # 6. Run Precision Truncation & Division-Before-Multiplication Scanner
    print("  -> [5/7] Analyzing Division-Before-Multiplication & Precision Loss...")
    precision_report = out_dir / "precision_truncation.md"
    run_script(script_dir / "precision_truncation_scanner.py", [str(target), "--output-file", str(precision_report)])

    # 7. Run EIP-150 63/64 Gas Griefing Scanner
    print("  -> [6/7] Checking EIP-150 Gas Forwarding & Silent Subcall Reverts...")
    gas_report = out_dir / "gas_griefing_hazards.md"
    run_script(script_dir / "eip150_gas_scanner.py", [str(target), "--output-file", str(gas_report)])

    # 8. Run Compiler & Yul Optimizer Hazard Scanner
    print("  -> [7/9] Verifying Solc Pragmas & Yul Memory-Safety Blocks...")
    compiler_report = out_dir / "compiler_hazards.md"
    run_script(script_dir / "compiler_hazard_scanner.py", [str(target), "--output-file", str(compiler_report)])

    # 9. Run NatSpec Intent Contradiction Miner
    print("  -> [8/9] Mining NatSpec Intent-vs-Code Contradictions...")
    natspec_report = out_dir / "natspec_contradictions.md"
    run_script(script_dir / "natspec_intent_miner.py", [str(target), "--output-file", str(natspec_report)])

    # 10. Run Storage Slot Packing & Pointer Analyzer
    print("  -> [9/11] Auditing Storage Slot Packing & Uninitialized Pointers...")
    storage_report = out_dir / "storage_packing_hazards.md"
    run_script(script_dir / "storage_packing_analyzer.py", [str(target), "--output-file", str(storage_report)])

    # 11. Run Access Control Matrix & Fund Flow Visualizer
    print("  -> [10/11] Mapping Access Control Matrix & Mermaid Flow Graph...")
    access_report = out_dir / "access_matrix.md"
    run_script(script_dir / "generate_access_matrix.py", [str(target), "--output-file", str(access_report)])

    # 12. Synthesize Foundry Invariant Fuzz Test Suite
    print("  -> [11/11] Synthesizing Autonomous Foundry Invariant Test Suite...")
    invariants_file = out_dir / "test" / "AuditInvariants.t.sol"
    run_script(script_dir / "generate_foundry_invariants.py", [str(target), "--output-file", str(invariants_file)])

    # Aggregate All Raw Leads into master leads.md
    leads_file = out_dir / "leads.md"
    modules = [
        ("Canonical Spec Deviations", diff_report),
        ("L2 Execution Hazards", l2_report),
        ("Payable Multicall & msg.value Reuse", multicall_report),
        ("Precision Truncation Hazards", precision_report),
        ("EIP-150 Gas Griefing Hazards", gas_report),
        ("Compiler & Yul Hazards", compiler_report),
        ("NatSpec Intent Contradictions", natspec_report),
        ("Storage Packing & Pointer Hazards", storage_report)
    ]

    with open(leads_file, 'w', encoding='utf-8') as lf:
        lf.write("# Master Audit Lead Manifest\n\n")
        lf.write(f"Generated automatically by Apex Audit Engine across {len(sol_files)} contracts.\n\n")

        for rname, rpath in modules:
            if rpath.exists():
                content = rpath.read_text(encoding='utf-8')
                lf.write(f"\n---\n## Module: {rname}\n\n")
                lf.write(content)
                lf.write("\n")

    print("--------------------------------------------------------------------------------")
    print(f"✅ Scanning Pipeline Complete! All modules executed successfully.")
    print(f"   📂 Master Lead Manifest: {leads_file}")
    print("================================================================================\n")

if __name__ == "__main__":
    main()

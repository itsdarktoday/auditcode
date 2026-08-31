#!/usr/bin/env python3
"""
AST & Storage Layout Topology Extractor for ultimate-web3-security.
Parses solc / forge inspect output to extract inheritance graphs and storage slot allocations.
"""

import os
import sys
import json
import subprocess
import argparse
from pathlib import Path

def run_cmd(cmd, cwd=None):
    res = subprocess.run(cmd, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.returncode, res.stdout, res.stderr

def extract_storage_layout(contract_name, cwd):
    code, out, _ = run_cmd(f"forge inspect {contract_name} storageLayout", cwd=cwd)
    if code == 0 and out.strip():
        try:
            return json.loads(out)
        except Exception:
            pass
    return None

def main():
    parser = argparse.ArgumentParser(description="Extract AST topology and storage layout.")
    parser.add_argument("target_dir", help="Path to project repository")
    parser.add_argument("--output-file", default="ultimate-audit/topology.md", help="Output markdown file")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    out_file = Path(args.output_file).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    # Get list of contracts
    code, out, _ = run_cmd("forge build --names", cwd=target_dir)
    contract_names = [line.strip() for line in out.splitlines() if line.strip() and not line.startswith("Compiling")]

    with open(out_file, 'w', encoding='utf-8') as f:
        f.write("# Protocol Architecture & Storage Slot Topology\n\n")
        f.write(f"Detected {len(contract_names)} contracts in compilation graph.\n\n")

        for name in contract_names:
            layout = extract_storage_layout(name, target_dir)
            if layout and "storage" in layout and layout["storage"]:
                f.write(f"## Contract: `{name}` Storage Layout\n\n")
                f.write("| Slot | Offset | Variable | Type |\n")
                f.write("|---|---|---|---|\n")
                for var in layout["storage"]:
                    f.write(f"| {var.get('slot')} | {var.get('offset')} | `{var.get('label')}` | `{var.get('type')}` |\n")
                f.write("\n")

    print(f"✅ Protocol topology and storage layouts saved to {out_file}")

if __name__ == "__main__":
    main()

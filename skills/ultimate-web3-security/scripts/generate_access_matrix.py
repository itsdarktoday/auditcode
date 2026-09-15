#!/usr/bin/env python3
"""
Access Control Matrix & Protocol Fund-Flow Visualizer for ultimate-web3-security.
Parses functions, visibility, modifiers, and fund transfers across target contracts.
Generates an Access Control Matrix and a Mermaid architecture diagram for scope.md.
"""

import os
import sys
import re
import argparse
from pathlib import Path

def parse_contract(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Find contract names
    contract_matches = re.finditer(r'(contract|abstract contract)\s+([a-zA-Z0-9_]+)', content)
    contracts = [m.group(2) for m in contract_matches]
    contract_name = contracts[0] if contracts else file_path.stem

    # Find functions: function name(params) visibility modifiers
    func_pattern = r'function\s+([a-zA-Z0-9_]+)\s*\([^\)]*\)\s*([^{;]*)(?:\{|;)'
    matches = re.finditer(func_pattern, content)

    functions = []
    for m in matches:
        fname = m.group(1)
        mods_str = m.group(2).strip()

        # Determine visibility
        if "external" in mods_str:
            vis = "external"
        elif "public" in mods_str:
            vis = "public"
        elif "internal" in mods_str:
            vis = "internal"
        elif "private" in mods_str:
            vis = "private"
        else:
            vis = "public"

        # Only track external/public entry points
        if vis not in ["external", "public"]:
            continue

        is_payable = "payable" in mods_str
        view_pure = "view" in mods_str or "pure" in mods_str

        # Extract role modifiers
        modifiers = []
        for word in re.findall(r'\b[a-zA-Z0-9_]+(?:\([^\)]*\))?', mods_str):
            if word not in ["external", "public", "internal", "private", "payable", "view", "pure", "override", "virtual", "returns"]:
                if not word.startswith("returns"):
                    modifiers.append(word)

        role = ", ".join(modifiers) if modifiers else "Public / Unrestricted"

        functions.append({
            "contract": contract_name,
            "function": fname,
            "visibility": vis,
            "payable": is_payable,
            "state_mutating": not view_pure,
            "role": role
        })

    return contract_name, functions

def main():
    parser = argparse.ArgumentParser(description="Access Control Matrix & Fund Flow Generator.")
    parser.add_argument("target_dir", help="Path to project repository")
    parser.add_argument("--output-file", default="ultimate-audit/access_matrix.md", help="Output markdown report")
    args = parser.parse_args()

    target_path = Path(args.target_dir).resolve()
    out_path = Path(args.output_file).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    all_functions = []
    contract_names = []

    for sol_file in target_path.rglob("*.sol"):
        if not sol_file.is_file():
            continue
        if any(x in sol_file.parts for x in ["test", "tests", "mocks", "mock", "lib", "node_modules", "out", "cache", "artifacts", "build"]):
            continue
        cname, funcs = parse_contract(sol_file)
        if funcs:
            contract_names.append(cname)
            all_functions.extend(funcs)

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("# Protocol Access Control Matrix & Fund Flow Topology\n\n")
        f.write(f"Scanned {len(contract_names)} contracts and {len(all_functions)} public/external entry points.\n\n")

        # 1. Access Control Matrix
        f.write("## 1. Access Control & Privilege Matrix\n\n")
        f.write("| Contract | Function | Role / Access Guard | State Mutating? | Payable (ETH)? |\n")
        f.write("|---|---|---|---|---|\n")
        for fn in all_functions:
            mut_badge = "🔴 Yes" if fn["state_mutating"] else "🟢 View/Pure"
            pay_badge = "💰 Yes" if fn["payable"] else "No"
            role_badge = f"`{fn['role']}`" if fn["role"] != "Public / Unrestricted" else "🌐 Public"
            f.write(f"| `{fn['contract']}` | `{fn['function']}()` | {role_badge} | {mut_badge} | {pay_badge} |\n")

        f.write("\n## 2. Architecture & Interaction Graph (Mermaid)\n\n")
        f.write("```mermaid\nflowchart TD\n")
        f.write("    User([🌐 Unprivileged User])\n")
        f.write("    Admin([🔑 Protocol Admin / Owner])\n\n")

        for cname in contract_names[:10]:
            f.write(f"    subgraph {cname}_Box [{cname}]\n")
            c_funcs = [fn for fn in all_functions if fn["contract"] == cname and fn["state_mutating"]]
            for fn in c_funcs[:4]:
                f.write(f"        {cname}_{fn['function']}[\"{fn['function']}()\"]\n")
            f.write("    end\n")

        f.write("\n    User -->|calls public functions| UserEntrypoints{Public Calls}\n")
        f.write("    Admin -->|calls restricted setters| AdminEntrypoints{Restricted Calls}\n")
        f.write("```\n\n")

    print(f"✅ Access Control Matrix & Topology generated at {out_path}")

if __name__ == "__main__":
    main()

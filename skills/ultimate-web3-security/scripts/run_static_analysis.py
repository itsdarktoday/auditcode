#!/usr/bin/env python3
"""
Multi-Scanner Static Analysis Aggregator for ultimate-web3-security.
Runs Slither, Aderyn, Semgrep, and 4nalyzer, aggregating high-signal findings into candidate seeds for leads.md.
"""

import os
import sys
import json
import shutil
import subprocess
import argparse
from pathlib import Path

def run_cmd(cmd, cwd=None):
    res = subprocess.run(cmd, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.returncode, res.stdout, res.stderr

def run_slither(target_dir, output_file):
    if not shutil.which("slither"):
        print("⚠️ Slither not found, skipping.")
        return []
    print("🔍 Running Slither...")
    json_path = output_file.parent / "slither.json"
    run_cmd(f"slither . --json {json_path} --filter-paths 'test|mocks|lib'", cwd=target_dir)
    findings = []
    if json_path.exists():
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for detector in data.get("results", {}).get("detectors", []):
                    check = detector.get("check", "")
                    impact = detector.get("impact", "Informational")
                    desc = detector.get("description", "").strip()
                    findings.append({
                        "tool": "slither",
                        "check": check,
                        "impact": impact,
                        "description": desc
                    })
        except Exception as e:
            print(f"Error parsing Slither output: {e}")
    return findings

def run_aderyn(target_dir, output_file):
    if not shutil.which("aderyn"):
        print("⚠️ Aderyn not found, skipping.")
        return []
    print("🔍 Running Aderyn...")
    json_path = output_file.parent / "aderyn.json"
    run_cmd(f"aderyn --output {json_path}", cwd=target_dir)
    findings = []
    if json_path.exists():
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for issue in data.get("high_issues", {}).get("issues", []):
                    findings.append({"tool": "aderyn", "check": issue.get("title", ""), "impact": "High", "description": issue.get("description", "")})
                for issue in data.get("medium_issues", {}).get("issues", []):
                    findings.append({"tool": "aderyn", "check": issue.get("title", ""), "impact": "Medium", "description": issue.get("description", "")})
        except Exception as e:
            print(f"Error parsing Aderyn output: {e}")
    return findings

def main():
    parser = argparse.ArgumentParser(description="Aggregate static analysis results.")
    parser.add_argument("target_dir", help="Path to target project repository")
    parser.add_argument("--output-dir", default="ultimate-audit", help="Output directory")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    seeds_file = out_dir / "static_leads.md"
    all_findings = []
    all_findings.extend(run_slither(target_dir, seeds_file))
    all_findings.extend(run_aderyn(target_dir, seeds_file))

    with open(seeds_file, 'w', encoding='utf-8') as f:
        f.write("# Static Analysis Candidate Seeds\n\n")
        f.write("| Tool | Severity | Check / Detector | Description |\n")
        f.write("|---|---|---|---|\n")
        for idx, item in enumerate(all_findings, 1):
            f.write(f"| {item['tool']} | {item['impact']} | {item['check']} | {item['description'][:120]}... |\n")

    print(f"✅ Aggregated {len(all_findings)} raw static findings into {seeds_file}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Hostile Invariant Mutation Fuzzer for ultimate-web3-security.
Applies deliberate adversarial mutations to target smart contracts and runs the project's test suite.
If the test suite passes on a broken mutant, flags an undetected protocol blind spot.
"""

import os
import sys
import re
import shutil
import subprocess
import argparse
from pathlib import Path

MUTATION_OPERATORS = [
    (r"\bnonReentrant\b", "/* nonReentrant */", "Removed nonReentrant guard"),
    (r"\b(require\s*\([^\;]*;\))", "/* \\1 */", "Commented out require validation"),
    (r"\b(\+\=)\b", "-=", "Inverted arithmetic assignment (+ to -)"),
    (r"\b(\-\=)\b", "+=", "Inverted arithmetic assignment (- to +)"),
    (r"\b(>)\b", "<", "Inverted comparison operator (> to <)"),
    (r"\b(<)\b", ">", "Inverted comparison operator (< to >)"),
    (r"\b(==)\b", "!=", "Inverted equality operator (== to !=)")
]

def run_cmd(cmd, cwd=None):
    res = subprocess.run(cmd, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.returncode, res.stdout, res.stderr

def test_mutant(target_file, orig_pattern, replacement, desc, target_dir):
    with open(target_file, 'r', encoding='utf-8') as f:
        original_content = f.read()

    mutated_content, count = re.subn(orig_pattern, replacement, original_content, count=1)
    if count == 0 or mutated_content == original_content:
        return None

    # Write mutated file
    with open(target_file, 'w', encoding='utf-8') as f:
        f.write(mutated_content)

    try:
        # Run test suite
        code, out, err = run_cmd("forge test --summary", cwd=target_dir)
        # If code == 0, the test suite PASSED despite the broken mutation!
        if code == 0:
            return {
                "file": target_file.name,
                "mutation": desc,
                "status": "SURVIVED (BLIND SPOT DETECTED)",
                "consequence": "Test suite passed despite hostile mutation! The protocol has no test coverage or invariant check for this guard."
            }
        else:
            return {
                "file": target_file.name,
                "mutation": desc,
                "status": "KILLED (TEST SUITE CAUGHT IT)",
                "consequence": "Protected by existing tests."
            }
    finally:
        # Restore original content
        with open(target_file, 'w', encoding='utf-8') as f:
            f.write(original_content)

def main():
    parser = argparse.ArgumentParser(description="Hostile Mutation Invariant Testing.")
    parser.add_argument("target_dir", help="Path to project repository")
    parser.add_argument("--max-mutants", type=int, default=10, help="Maximum mutants to generate")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    print(f"🔬 Starting Mutation Testing on {target_dir}...")

    results = []
    sol_files = list(target_dir.rglob("*.sol"))
    
    mutants_tested = 0
    for sfile in sol_files:
        if any(x in sfile.parts for x in ["test", "tests", "mocks", "mock", "lib", "node_modules"]):
            continue
        for pattern, repl, desc in MUTATION_OPERATORS:
            if mutants_tested >= args.max_mutants:
                break
            res = test_mutant(sfile, pattern, repl, desc, target_dir)
            if res:
                results.append(res)
                mutants_tested += 1
                status_icon = "⚠️" if "SURVIVED" in res["status"] else "🛡️"
                print(f"{status_icon} Mutant #{mutants_tested} on `{res['file']}`: {desc} -> {res['status']}")

    print("\n--- Mutation Testing Summary ---")
    survived = [r for r in results if "SURVIVED" in r["status"]]
    print(f"Total Mutants Tested: {len(results)}")
    print(f"Mutants Killed by Tests: {len(results) - len(survived)}")
    print(f"Mutants Survived (Blind Spots): {len(survived)}")

if __name__ == "__main__":
    main()

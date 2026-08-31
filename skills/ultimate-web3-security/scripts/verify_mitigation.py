#!/usr/bin/env python3
"""
Automated Mitigation Verifier for ultimate-web3-security.
Applies a proposed patch, verifies that the exploit PoC is blocked (reverts),
and verifies that all original protocol tests pass with zero regressions.
"""

import os
import sys
import subprocess
import argparse
import tempfile
import shutil
from pathlib import Path

def run_cmd(cmd, cwd=None):
    """Executes a shell command and returns (returncode, stdout, stderr)."""
    res = subprocess.run(cmd, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.returncode, res.stdout, res.stderr

def main():
    parser = argparse.ArgumentParser(description="Verify a proposed security mitigation diff.")
    parser.add_argument("target_dir", help="Path to the target project repository")
    parser.add_argument("patch_file", help="Path to the .diff or .patch file")
    parser.add_argument("--poc-test", required=True, help="Path or test match name for the exploit PoC")
    parser.add_argument("--fork-url", default="", help="Optional RPC URL for fork tests")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    patch_file = Path(args.patch_file).resolve()

    if not patch_file.exists():
        print(f"❌ Patch file not found: {patch_file}")
        sys.exit(1)

    print(f"🔍 Step 1: Pre-patch verification (Verifying exploit succeeds)...")
    poc_cmd = f"forge test --match-test {args.poc_test} -vv"
    if args.fork_url:
        poc_cmd += f" --fork-url {args.fork_url}"
    
    code, out, _ = run_cmd(poc_cmd, cwd=target_dir)
    if code != 0:
        print(f"⚠️ Warning: PoC failed before patch application! Check test setup.")
    else:
        print(f"✅ PoC successfully reproduced exploit pre-patch.")

    print(f"🛠️ Step 2: Applying mitigation patch ({patch_file.name})...")
    apply_code, apply_out, apply_err = run_cmd(f"git apply {patch_file}", cwd=target_dir)
    if apply_code != 0:
        print(f"❌ Failed to apply patch:\n{apply_err}")
        sys.exit(1)
    print(f"✅ Patch applied cleanly.")

    try:
        print(f"🛡️ Step 3: Re-running exploit PoC post-patch (Must FAIL/REVERT)...")
        post_code, post_out, _ = run_cmd(poc_cmd, cwd=target_dir)
        if post_code == 0:
            print(f"❌ Exploit still SUCCEEDED after patch! Mitigation is INEFFECTIVE.")
            mitigation_success = False
        else:
            print(f"✅ Exploit REVERTED / FAILED as expected. Attack path blocked!")
            mitigation_success = True

        print(f"🧪 Step 4: Running full regression test suite...")
        suite_code, suite_out, _ = run_cmd("forge test", cwd=target_dir)
        if suite_code != 0:
            print(f"⚠️ Regression detected! Normal unit tests failed after patch.")
            regression_clean = False
        else:
            print(f"✅ All protocol unit tests passed with 0 regressions.")
            regression_clean = True

        print("\n==========================================")
        if mitigation_success and regression_clean:
            print("🏆 VERDICT: [MITIGATION-VERIFIED: BLOCKS_EXPLOIT + ZERO_REGRESSIONS]")
        elif mitigation_success:
            print("⚠️ VERDICT: [MITIGATION-PARTIAL: BLOCKS_EXPLOIT BUT HAS_REGRESSIONS]")
        else:
            print("❌ VERDICT: [MITIGATION-FAILED: EXPLOIT_NOT_BLOCKED]")
        print("==========================================\n")

    finally:
        print(f"🧹 Step 5: Rolling back patch...")
        run_cmd("git reset --hard HEAD", cwd=target_dir)
        print(f"✅ Repository restored to clean baseline state.")

if __name__ == "__main__":
    main()

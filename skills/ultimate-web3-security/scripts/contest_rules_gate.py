#!/usr/bin/env python3
"""
Sherlock & Code4rena Competitive Contest Judging Engine for ultimate-web3-security.
Applies official competitive judging rules (Sherlock / C4 criteria) to candidate findings.
Eliminates contested or invalid issues (trusted admin griefing, 1-wei dust, user slippage mistake).
"""

import os
import sys
import re
import argparse
from pathlib import Path

CONTEST_RULES = [
    {
        "id": "RULE-ADMIN-TRUST",
        "name": "Trusted Admin Assumption",
        "regex": r"(admin\s+can\s+rug|owner\s+can\s+set|malicious\s+owner|centralization\s+risk)",
        "exception_regex": r"(front-run|unbounded|no\s+upper\s+bound|permanent\s+lock|retroactive)",
        "action": "DOWNGRADE_OR_INVALID",
        "reason": "Admins and contract owners are assumed trusted in Sherlock/C4 unless an unprivileged amplifier (front-running, un-bounded parameter freeze, retroactive theft) is proven."
    },
    {
        "id": "RULE-1WEI-DUST",
        "name": "1-Wei Precision Dust",
        "regex": r"(1\s*wei\s+loss|rounding\s+error\s+of\s+1\s*wei|few\s*wei)",
        "exception_regex": r"(donation|inflation\s+attack|drain|compounding|magnified)",
        "action": "DOWNGRADE_OR_INVALID",
        "reason": "1-wei rounding differences are considered Informational / Non-issue unless part of an inflation donation attack or self-amplifying drain loop."
    },
    {
        "id": "RULE-USER-SLIPPAGE",
        "name": "User Slippage / Self-Griefing",
        "regex": r"(user\s+forgets\s+slippage|user\s+sets\s+0\s+min|bad\s+deadline|user\s+input\s+mistake)",
        "exception_regex": r"(hardcoded\s+0|protocol\s+enforces|missing\s+slippage\s+parameter)",
        "action": "DOWNGRADE_OR_INVALID",
        "reason": "If a user simply provides bad parameters (slippage = 0) where the protocol allows custom parameters, it is considered user error."
    },
    {
        "id": "RULE-ZERO-ADDRESS",
        "name": "Missing Zero Address Validation",
        "regex": r"(address\(0\)\s+check|missing\s+zero\s+address|zero-address\s+validation)",
        "exception_regex": r"(burn|permanent\s+lock|immutable)",
        "action": "CAP_AT_LOW",
        "reason": "Missing zero address validation is strictly Low / Informational according to Sherlock/C4 rules."
    }
]

def judge_finding(title, description):
    combined = f"{title}\n{description}".lower()
    verdicts = []

    for rule in CONTEST_RULES:
        if re.search(rule["regex"], combined):
            # Check if exception applies
            if re.search(rule["exception_regex"], combined):
                verdicts.append({
                    "rule": rule["name"],
                    "status": "PASS (EXCEPTION_VALIDATED)",
                    "note": "Finding has a valid amplifier or exploit mechanism."
                })
            else:
                verdicts.append({
                    "rule": rule["name"],
                    "status": rule["action"],
                    "note": rule["reason"]
                })

    return verdicts

def main():
    parser = argparse.ArgumentParser(description="Competitive Contest Rules Judge.")
    parser.add_argument("report_or_finding", help="Path to markdown finding or report")
    args = parser.parse_args()

    target_file = Path(args.report_or_finding).resolve()
    if not target_file.exists():
        print(f"File not found: {target_file}")
        sys.exit(1)

    content = target_file.read_text(encoding='utf-8')
    # Simple split by finding headers
    sections = re.split(r'(?=#+\s+\[[A-Z]-[0-9]+\])', content)

    print("================================================================================")
    print(" ⚖️ SHERLOCK / CODE4RENA CONTEST RULES JUDGING EVALUATOR")
    print("================================================================================")

    for idx, sec in enumerate(sections[1:], 1):
        lines = sec.strip().splitlines()
        title = lines[0] if lines else f"Finding #{idx}"
        desc = "\n".join(lines[1:])
        results = judge_finding(title, desc)

        print(f"\nEvaluating: {title}")
        if not results:
            print("  ✅ PASS: Conforms to competitive contest criteria with zero rule violations.")
        else:
            for r in results:
                status_icon = "⚠️" if "DOWNGRADE" in r["status"] else "ℹ️"
                print(f"  {status_icon} [{r['status']}] {r['rule']}: {r['note']}")

    print("\n================================================================================")

if __name__ == "__main__":
    main()

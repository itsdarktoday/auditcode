---
name: 05_poc_verification
description: PoC Exploit Development & Verification Phase Checklist
tags: ["poc_verification", "exploitation"]
---

# Proof-of-Concept (PoC) Verification Checklist

1. **Quality Review (Critic Agent)**:
   - Run `critic` over all candidate findings in state.
   - Apply 4-gate verification (Reachability, Control Flow, Financial Impact, Minimal Fix).
   - Filter false positives and calibrate severity (Critical / High / Medium / Low / Gas / Info).

2. **Foundry PoC Test Execution (`poc_dev` Agent)**:
   - For all Critical and High findings, draft a self-contained Foundry test (`test/PoC.t.sol`).
   - Execute via `foundry_test(match_test: "test_Exploit")`.
   - Ensure the test asserts stolen funds or broken invariants (`assertGt`, `assertEq`).
   - On successful run, update vuln status to `poc_verified` and attach execution trace.

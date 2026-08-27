---
name: amm_dex
description: Comprehensive playbook for auditing Automated Market Makers (AMMs) & DEXes
tags: ["playbook", "defi", "amm", "dex"]
---

# Automated Market Maker (AMM) Audit Playbook

1. **Invariant Curve Math ($x \cdot y = k$, Stableswap)**:
   - Verify constant product or stableswap invariant is maintained strictly ($k_{after} \ge k_{before}$).
   - Audit fee deductions: fees must increase $k$ and not be deducted before curve calculation in a way that allows balance extraction.

2. **Slippage, Deadlines & Sandwich Defenses**:
   - Check that `amountOutMin` and `deadline` are enforced and not hardcoded to 0 or `block.timestamp`.
   - Audit pool token deposit/burn ratios for initial liquidity provisioning (dead shares burn).

3. **Flash Swaps & Reentrancy**:
   - Ensure flash swap callbacks verify invariant balance check before finishing execution.
   - Verify transient storage reentrancy protection.

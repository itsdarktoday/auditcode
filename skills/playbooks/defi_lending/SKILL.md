---
name: defi_lending
description: Comprehensive playbook for auditing DeFi Lending & Borrowing Protocols
tags: ["playbook", "defi", "lending"]
---

# DeFi Lending & Borrowing Protocol Audit Playbook

1. **Collateral Valuation & Health Factors**:
   - Check collateral factor / Loan-to-Value (LTV) limits.
   - Verify oracle feeds (Chainlink heartbeat, staleness, min/max bounds, TWAP windows).
   - Ensure interest rate index compounds monotonically before balance changes.

2. **Liquidation Mechanics**:
   - Check liquidation incentive bonus vs minimum liquidation threshold.
   - Ensure self-liquidations cannot generate profit from unbacked bad debt.
   - Verify bad debt absorption / insurance fund accounting.

3. **Borrow Caps & Asset Isolation**:
   - Verify borrow caps exist on volatile/illiquid collateral assets to prevent infinite minting attacks.
   - Check flash loan fees and reentrancy protections during collateral swaps.

# Post-Mortem: Platypus Finance (.5M Exploit)

- **Date:** February 16, 2023
- **Protocol Archetype:** Stableswap / CDP Collateral
- **Root Cause Category:** Emergency Function Invariant Bypass
- **Target Invariant Broken:**  (Solvency & Asset Backing)

## 1. Vulnerability Mechanics
Platypus Finance included an  function in  to allow users to withdraw staked LP collateral if the pool was paused.
However, ** did NOT check if the user had outstanding borrowed debt against that collateral in the Platypus CDP system ()**.

## 2. Attack Walkthrough
1. Attacker flash-borrows 4M USDC.
2. Attacker deposits USDC to receive LP tokens and stakes them in MasterPlatypus.
3. Attacker borrows 1M USP (Platypus stablecoin) against the staked LP collateral.
4. Attacker calls . The contract checks that  or emergency flag, and returns 100% of the collateral USDC to the attacker **without checking borrow solvency**.
5. Attacker repays the flash loan and swaps the borrowed 1M USP for remaining pool assets, pocketing .5M pure profit.

## 3. Key Takeaways & Defense Matrix
- **Rule:** Emergency withdrawal and bypass functions MUST still enforce debt clearance and solvency checks.

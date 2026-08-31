# Post-Mortem: Euler Finance (97M Exploit)

- **Date:** March 13, 2023
- **Protocol Archetype:** Lending / CDP
- **Root Cause Category:** Accounting Desync & Missing Health Factor Invariant Check
- **Target Invariant Broken:**  (Solvency) &  (Health Factor Invariant)

## 1. Vulnerability Mechanics
In Euler's , the  function allowed a user to donate their  (collateral balance) to the Euler reserve vault.
Crucially, ** did NOT execute a health factor liquidity check ()** on the caller.



## 2. Attack Walkthrough
1. Attacker flash-borrows 0M DAI.
2. Attacker deposits 0M DAI to mint 0M eDAI collateral and borrows 9.5M DAI (leveraged minting to 00M total debt / collateral).
3. Attacker calls . This burns 100M eDAI from the attacker's account, putting the attacker deep into unbacked bad debt.
4. Because the health factor was not checked during , the transaction does not revert.
5. In the same transaction, the attacker calls  on their own account. The liquidation logic calculates a massive liquidation discount, transferring all remaining underlying collateral to the liquidator (attacker-controlled account) while leaving unbacked bad debt in Euler.

## 3. Key Takeaways & Defense Matrix
- **Rule:** EVERY function that reduces collateral balance or increases liabilities MUST unconditionally invoke the health check before execution finishes.
- **PoC Invariant:** .

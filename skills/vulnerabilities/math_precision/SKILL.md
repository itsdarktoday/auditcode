---
name: math_precision
description: Guide to Precision Loss, Division before Multiplication, and Rounding
tags: ["vuln", "math"]
---

# Math Precision, Rounding & Arithmetic Security

### 1. Division Before Multiplication
- **Anti-Pattern**:
  ```solidity
  uint256 reward = userBalance / totalBalance * rewardPool; // userBalance / totalBalance truncates to 0!
  ```
- **Remediation**:
  ```solidity
  uint256 reward = (userBalance * rewardPool) / totalBalance;
  ```

### 2. Decimal Mismatch & Precision Loss
- Scaling between 6-decimal tokens (USDC, USDT), 8-decimal tokens (WBTC), and 18-decimal tokens (DAI, ETH).
- Always scale up to 18 decimals before division, and scale down only at the final settlement step.

### 3. Unchecked Arithmetic Hazards
- In Solidity 0.8+, `unchecked { ... }` bypasses compiler overflow/underflow checks.
- Audit every `unchecked` block for possible underflow in balance subtractions or counter loops.

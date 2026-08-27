---
name: erc4626_vault_audit
description: Comprehensive playbook for auditing Yield Vaults & ERC-4626 implementations
tags: ["playbook", "erc4626", "vault"]
---

# ERC-4626 Yield Vault Audit Playbook

1. **Share Pricing & First Depositor Protection**:
   - Check for virtual shares/assets offset (`_decimalsOffset()`).
   - Check initial dead shares burnt to `address(0xdead)` upon deployment.

2. **Deposit & Withdrawal Flows**:
   - Check slippage parameters on deposit and redeem.
   - Check fee deductions (management fees, performance fees, withdrawal fees) and rounding direction.

3. **Strategy Harvesting & Loss Handling**:
   - Check strategy report losses vs gains.
   - Ensure harvest cannot be front-run by large deposits followed by immediate withdrawal.

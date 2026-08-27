---
name: erc4626_vaults
description: Guide to ERC-4626 Tokenized Vault Vulnerabilities and Inflation Attacks
tags: ["vuln", "erc4626", "vault"]
---

# ERC-4626 Vault Inflation & Share Dilution Attacks

### 1. First Depositor Inflation Attack
- **Mechanism**:
  1. Attacker is the first depositor in a new vault.
  2. Attacker deposits `1 wei` of underlying asset and receives `1 share`.
  3. Attacker directly transfers (donates) `1,000,000e18` underlying tokens to the vault contract address without minting shares.
  4. Now `totalAssets = 1,000,000e18 + 1` while `totalSupply = 1`.
  5. A victim user attempts to deposit `1,999,999e18` tokens.
  6. Calculated shares: `assets * totalSupply / totalAssets` = `1,999,999e18 * 1 / (1,000,000e18 + 1) = 1 share` (due to integer truncation).
  7. Attacker redeems their 1 share and steals half the victim's deposited assets!
- **Remediation**:
  - Implement virtual shares and virtual assets offset (e.g. OpenZeppelin's `_decimalsOffset()` = 3).
  - Burn initial dead shares (e.g. `1000 shares` sent to `address(0xdead)` on deployment).

### 2. Rounding Direction Inversion
- **Standard Requirement**:
  - `convertToShares` / `previewDeposit` (assets -> shares): Round DOWN (favor vault).
  - `previewMint` (shares -> assets required): Round UP (favor vault).
  - `convertToAssets` / `previewRedeem` (shares -> assets): Round DOWN (favor vault).
  - `previewWithdraw` (assets -> shares burned): Round UP (favor vault).

---
name: upgradeability
description: Security guide for upgradeable smart contracts (Transparent, UUPS, Diamond, Beacon), storage layout collisions, uninitialized constructors, and gap management.
---

# Smart Contract Upgradeability Security Guide

## Proxy Architectures
- **UUPS (Universal Upgradeable Proxy Standard - ERC-1822 / ERC-1967)**: Upgrade logic lives inside the implementation contract.
- **Transparent Upgradeable Proxy**: Upgrade logic lives in the ProxyAdmin contract.
- **Diamond Pattern (ERC-2535)**: Multi-facet proxy with modular function routing.
- **Beacon Proxy**: Multiple proxies point to a single Beacon contract holding the implementation address.

---

## Critical Vulnerability Patterns

### 1. Uninitialized Implementation Contract
- **Root Cause**: The implementation contract's constructor does not lock initialization (`_disableInitializers()`).
- **Attack Vector**: Attacker calls `initialize()` directly on the implementation contract, becomes owner, and calls `selfdestruct` or malicious upgrades (Parity-style bug).
- **Remediation**:
  ```solidity
  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor() {
      _disableInitializers();
  }
  ```

### 2. Storage Layout Collisions & Variable Shifts
- **Root Cause**: In upgradeable contracts, state variables must never be reordered, inserted before existing variables, or changed in type.
- **Attack Vector**: Adding a new variable before existing ones shifts the storage slots of all subsequent state variables, causing memory corruption and fund theft.
- **Remediation**:
  - Always append new state variables at the end of the contract inheritance tree.
  - Use ERC-7201 Namespaced Storage Layouts in Solidity 0.8.20+.

### 3. Missing Storage Gaps (`uint256[50] private __gap`)
- **Root Cause**: Base upgradeable contracts without `__gap` reserve no storage slots for future inherited variables.
- **Impact**: Extending parent contracts in future upgrades overwrites child contract storage variables.
- **Remediation**: Add `uint256[50] private __gap;` at the bottom of all abstract/base contracts.

### 4. Missing Access Control on `_authorizeUpgrade` (UUPS)
- **Root Cause**: In UUPS proxies, `_authorizeUpgrade(address newImplementation)` overrides the upgrade permission.
- **Attack Vector**: If `onlyOwner` modifier is omitted, any user can upgrade the proxy to a malicious implementation.
- **Remediation**:
  ```solidity
  function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
  ```

### 5. Function Selector Clashing
- **Root Cause**: Proxy contract and Implementation contract share a function with identical 4-byte selector.
- **Remediation**: Transparent proxy pattern separates admin calls from user calls via `if (msg.sender == admin)`.

---
name: access_control
description: Guide to Access Control, Initializers, and Governance Exploits
tags: ["vuln", "access_control"]
---

# Access Control, Initializers & Governance Security

### 1. Uninitialized Implementation Contracts
- **Vulnerability**: An implementation contract used behind a UUPS/Transparent proxy has an `initialize()` function that was never called on the logic contract itself.
- **Exploit**: Attacker calls `initialize()` on the implementation address, becomes owner, and calls `upgradeToAndCall()` with `selfdestruct` or malicious delegatecall, bricking all user proxies!
- **Remediation**: Add `_disableInitializers()` in the logic contract constructor:
  ```solidity
  constructor() {
      _disableInitializers();
  }
  ```

### 2. Signature Replay & Malleability
- Check `ecrecover` return value `signer != address(0)`.
- Use OpenZeppelin's `ECDSA.recover` to enforce upper `s` bound (`s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0`).
- Include `block.chainid`, contract `address(this)`, and incremental `nonce` in signature digest.

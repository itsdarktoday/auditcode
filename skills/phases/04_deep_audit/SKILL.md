---
name: 04_deep_audit
description: Deep Multi-Agent Security Audit Phase Checklist
tags: ["deep_audit", "vuln_assess"]
---

# Deep Multi-Agent Security Audit Checklist

Dispatch the specialist subagents in parallel across 10 specialized lenses:

1. **`math_precision`**: Precision loss, division before multiplication, rounding direction favoring attacker, ERC4626 first depositor inflation attacks, mismatched decimal scaling.
2. **`access_control`**: Missing modifiers, implementation initializers uninitialized, `tx.origin`, signature malleability (`ecrecover` zero return, secp256k1 `s` value), replay attacks, permit front-running.
3. **`economic_security`**: Spot price oracle reliance, flash loan attacks, short TWAP window manipulation, Chainlink min/max answer bounds, missing L2 sequencer uptime feed, sandwiching.
4. **`reentrancy`**: Read-only reentrancy on view functions, cross-contract/cross-function reentrancy, ERC777/1155 hooks, CEI violations.
5. **`invariant_agent`**: Evaluate defined invariants against complex multi-step state transitions.
6. **`periphery_agent`**: Non-standard ERC20 tokens (USDT missing return value, fee-on-transfer, rebasing tokens, blacklists).
7. **`boundary_agent`**: Zero deposit/withdraw, max uint256 bounds, off-by-one errors, first depositor edge cases, pause state transitions.
8. **`solana_analyst`**: (If Solana) Missing signers, PDA bump seed validation, duplicate mutable accounts, account closing reloads.

# EIP-150 63/64 Gas Rule & Partial Subcall Failure Griefing

Under Ethereum's EIP-150 rule, a calling contract forwards at most **63/64** of its remaining gas to an external subcall, retaining 1/64 for itself.

---

## 1. The Vulnerability Mechanism
When a contract wraps an external subcall in a `try/catch` or low-level `target.call(...)` and continues execution even if the subcall returns `false`:
1. An attacker can calculate the exact gas to pass so that:
   - The subcall receives just enough gas to start, but runs **out of gas** and reverts.
   - The caller retains 1/64 of remaining gas (e.g. 50,000 gas), which is **sufficient for the caller to finish its own execution!**
2. The caller interprets the failed subcall as "recipient rejected payment" or "user callback failed", marks the internal state as settled/transferred, and keeps the user's funds or closes their position without delivering the asset!

---

## 2. Common Manifestations
- **Griefed Relayers / Keepers:** Relayer forwards gas to execute a meta-tx; subcall fails due to insufficient gas; relayer claims fee while user operation is marked failed.
- **Push Payments inside try/catch:** Contract attempts to push rewards; failing subcall silently dropped; user permanently loses reward claim without receiving tokens.
- **Cross-Chain Bridge Message Execution:** Destination relayer executes message with sub-optimal gas, causing destination execution revert while message hash is consumed.

---

## 3. Defense & Remediation
1. **Enforce Minimum Gas Before Subcall:**
   ```solidity
   require(gasleft() >= MIN_EXECUTION_GAS, "Insufficient gas forwarded");
   (bool success, ) = target.call{gas: MIN_EXECUTION_GAS}(data);
   require(success, "Call failed");
   ```
2. **Pull Over Push:** Never execute batch pushes inside try/catch loops. Use pull-based withdrawal patterns.

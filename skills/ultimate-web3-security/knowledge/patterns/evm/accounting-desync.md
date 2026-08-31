# accounting-desync (evm)

root cause: value leaves (or enters) the contract but the variable tracking it is not updated — or is updated in only one of two branches.
protocol type: any protocol holding user funds (vault, lending, staking, bridge, DEX)
affected architecture: `totalX` / `Σ userX` ledgers, claim pointers, fee accumulators, locked/minted pairs on bridges.
attack preconditions: a second code path that moves the value without going through the shared accounting function; or a branch where the update is skipped.
invariant violated: `totalX == Σ userX`, "every credited unit is debited exactly once", "claims ≤ balances".
exploit pattern: variants — (a) withdraw path transfers tokens but skips `totalX -= amount`; (b) deposit path credits `amount` while `amount - fee` arrived (see fee-on-transfer pattern); (c) claim function resets the debt before/after the transfer inconsistently, allowing double-claim; (d) two entry points move the same value and only one updates the ledger.
detection strategy: money-map walk (Phase 2): for every `transfer`/`mint`/`burn`/`claim`, list the tracked totals that must change and confirm the update is in the SAME branch. Grep each `+=`/`-=` pair; check every early-return and revert path for skipped updates.
false-positive indicators: reconciliation function recomputes totals periodically; only caller funds affected (self-harm); the skipped update is intentional (burn of dust); value is cosmetic (view-only totals).
example PoC: /tmp/test-vault/ultimate-audit/poc/withdraw-desync/Exploit.t.sol (forge test --match-test test_withdrawDesync → PASS; attacker profit 33%, victim claim permanently locked)

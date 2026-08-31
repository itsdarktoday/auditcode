# RESULTS — latest eval run (2026-08-13)

Run protocol: full pipeline-lite per fixture (recon → money map/invariants → lenses → hypothesis → judge gates → verdict). Evidence levels: PoC (forge test passes) / trace (complete unbroken attacker→harm path).

## Vulnerable fixtures

| Fixture | Ground truth | Reported | Verdict | Severity | Confidence | Evidence | Root-cause match |
|---|---|---|---|---|---|---|---|
| V01_ReentrancyVault | reentrancy (CEI) | reentrancy (CEI) | VALID | HIGH | high (100) | **PoC** (drains 10 eth from 1) | ✅ exact |
| V02_ClaimDesync | accounting desync | accounting desync | VALID | HIGH | high (100) | **PoC** (B underpaid 50, remainder locked) | ✅ exact |
| V03_DonationShares | share inflation/rounding | donation → share round-to-0 | VALID | HIGH | high (100) | **PoC** (victim 0 shares for 1000e18) | ✅ exact |
| V04_StaleOracle | oracle staleness | missing staleness/heartbeat | VALID | HIGH | high (95) | trace (stale price → overborrow → bad debt) | ✅ exact |
| V05_InitFrontRun | initialization | unguarded initialize → ownership takeover | VALID | HIGH | high (100) | trace (callable anytime, any caller) | ✅ exact |
| V06_MissingGuard | access control | missing guard on economic param | VALID | HIGH | high (100) | trace (setFee(10000) permissionless) | ✅ exact |
| V07_SigReplay | signature replay | chainId omitted + nonce unsigned | VALID | HIGH | high (95) | trace (replay on fork/sibling chain; in-protocol replay) | ✅ exact |
| V08_FeeOnTransfer | fee-on-transfer accounting | credits requested ≠ received | VALID | HIGH | high (100) | **PoC** (1 credit insolvency per deposit) | ✅ exact |

## Clean fixtures

| Fixture | Reported | Verdict |
|---|---|---|
| C01_CleanVault | nothing | 0 FP — delta accounting, CEI, nonReentrant, dead-share first deposit all correctly recognized as safe |
| C02_CleanStaking | nothing | 0 FP — reward-debt settlement correct; stake() CEI ordering noted but correctly dropped (no callback token in scope) |
| C03_CleanEscrow | nothing | 0 FP — two-step owner, pull payments, CEI recognized |

## Scores

- TP = 8, FN = 0, FP = 0
- **Precision = 8/8 = 100%**
- **Recall = 8/8 = 100%**

## Methodology learnings recorded this run (regression gate outputs)

1. **Reentrancy shape falsification**: a decrement-style CEI bug in a pure-ETH single-mapping vault (`send; balance -= amount`) is NOT exploitable in Solidity ≥0.8 — the recursive unwind underflows on the second decrement and reverts the entire tx. Only assignment-style zeroing (`amount = balances[user]; send(amount); balances[user] = 0`) yields a working drain. → written into `knowledge/patterns/evm/reentrancy.md` FP indicators.
2. PoC discipline caught two test-authoring bugs before they polluted results (0.8-underflow attacker; underfunded attacker). Both were PoC bugs, not fixture bugs — confirmed by re-running against the fixtures as written.

## Honest limitations

- Author = evaluator (bias risk; mitigated by independent PoC execution and by using canonical bug classes).
- Small corpus (8 vuln + 3 clean, single-contract fixtures) — measures class detection on known shapes, NOT novel-bug discovery on real protocols.
- V04/V05/V06/V07 carry trace-level (not PoC-level) evidence.

# Multi-Agent Swarm Orchestrator

The Swarm Orchestrator parallelizes the audit across specialized subagents running concurrently. It maximizes discovery breadth while maintaining strict depth through specialized prompt bundling and blind verification.

---

## 1. Swarm Architecture

The swarm deploys up to 18 specialized parallel agents divided into three echelons:

```
                      ┌─────────────────────────────────┐
                      │    Master Audit Orchestrator     │
                      └────────────────┬────────────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         ▼                             ▼                             ▼
┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│ ECHELON 1: LENSES│         │ ECHELON 2: GAPS  │         │ECHELON 3: SKEPTIC│
│ (14 Specialists) │         │ (3 Seam Hunters) │         │ (Adversary/Judge)│
└────────┬─────────┘         └────────┬─────────┘         └────────┬─────────┘
         │                            │                            │
         ▼                            ▼                            ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                    Deduplication & 5-Gate Judge Matrix                     │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Agent Roster

### Echelon 1: Specialized Lens Agents (Parallel Audit)
1. **`lens-math-precision`**: Fixed-point rounding, catastrophic cancellation, zero-share mints, decimal shifts ( \leftrightarrow 18 \leftrightarrow 27$).
2. **`lens-reentrancy-transient`**: CEI violations, read-only view reentrancy, ERC-777/1155 hooks, EIP-1153 `TSTORE`/`TLOAD` dirty states.
3. **`lens-access-control`**: Missing modifiers, initialization front-running, UUPS `_authorizeUpgrade`, capability `store` leaks.
4. **`lens-economic-mev`**: Flash loan price distortion, sandwichable TWAP windows, collateral manipulation, atomic arbitrage.
5. **`lens-oracle-pricing`**: Stale Chainlink feeds, L2 sequencer downtime grace periods, multi-asset decimal normalization.
6. **`lens-lending-cdp`**: Health factor manipulation, toxic collateral DoS, soft-liquidation cascades, bad debt socialization.
7. **`lens-amm-hooks`**: Uniswap v4 hook return delta spoofing, beforeSwap/afterSwap reentrancy, tick boundary rounding drift.
8. **`lens-vault-inflation`**: ERC-4626 first-depositor share inflation, direct token balance donations, unharvested yield sandwiching.
9. **`lens-governance-voting`**: Flash-loan voting weight, snapshot block manipulation, proposal cancellation race conditions.
10. **`lens-signatures-permits`**: EIP-712 cross-chain replay, signature malleability (, v$), permit front-running DoS.
11. **`lens-upgradeability-proxies`**: Storage layout collisions, uninitialized logic contracts, missing storage gaps.
12. **`lens-dos-griefing`**: Unbounded dynamic array iteration, push-over-pull payment reverts, 63/64th gas exhaustion.
13. **`lens-crosschain-bridges`**: Message payload replay, destination gas trapping, lock/mint parity drift.
14. **`lens-assembly-lowlevel`**: Free memory pointer (`0x40`) corruption, dirty upper bits in assembly casting, returndatacopy buffer overflows.

### Echelon 2: Gap-Hunter Agents (Multi-Lens Seams)
15. **`gap-hunter-numerical`**: Intersections between math rounding and economic incentives.
16. **`gap-hunter-trust`**: Intersections between access control boundaries and external callbacks.
17. **`gap-hunter-flow`**: Intersections between state machines, asynchronous settlement queues, and multi-contract interactions.

### Echelon 3: Autonomous Skeptic Adversary
18. **`skeptic-adversary`**: Formulates committed invariant defenses (`[CI-1]` to `[CI-6]`) and hunts for exact code lines to disprove candidates.

---

## 3. Bundle-Packing Protocol (`build_swarm_bundles.py`)

Before spawning agents, the orchestrator compiles:
1. `source.md`: All in-scope target source files formatted in markdown fenced code blocks.
2. `agent-N-bundle.md`: `source.md` + Standard Operating Procedure (SOP) + Agent Specialty + Global Shared Rules.

Agents read their bundle directly in Turn 1, eliminating repetitive codebase file-searching operations.

---

## 4. Parallel Dispatch via `invoke_subagent`

The orchestrator launches the swarm concurrently:

```python
invoke_subagent(
    Subagents=[
        {"TypeName": "research", "Role": "Math Precision Auditor", "Prompt": "..."},
        {"TypeName": "research", "Role": "Reentrancy Transient Auditor", "Prompt": "..."},
        {"TypeName": "research", "Role": "Economic MEV Auditor", "Prompt": "..."},
        # ... up to 18 parallel agents
    ]
)
```

---

## 5. Deduplication & Consolidation Rules

1. Parse all candidate findings and leads from the agent outputs.
2. Deduplicate strictly by `(Contract, Function, RootCauseMechanism)`.
3. Preserve distinct fix recommendations as **Option A** and **Option B**.
4. Verify the **Completeness Hard Gate**:
   1212\text{Completeness: } N \text{ unique leads generated} \equiv N \text{ covered in final judgment.}1212

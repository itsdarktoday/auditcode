# Ultimate Web3 Security Skill

The world's most advanced, production-grade autonomous Web3 security research system for AI agent runtimes. Give it any smart contract repository and trigger with:
**"Audit this protocol"** | **"Security review"** | **"Find all vulnerabilities in this codebase"**

---

## 🚀 The 12-Phase Core Pipeline

```
RECON/SCOPING → PROTOCOL MODEL → THREAT MODEL → DEEP ANALYSIS (Manual + Archetype + Dynamic)
→ ATTACK GENERATION → HYPOTHESIS ENGINE → EXPLOIT VALIDATION → FALSE POSITIVE ELIMINATION
→ ADVERSARIAL SKEPTIC REVIEW → SECOND OPINION → FINDING JUDGE → FINAL REPORT → KNOWLEDGE MEMORY
```

---

## ⚡ Apex Capabilities (The 6 Powerhouse Engines)

### 1. Multi-Agent Swarm Parallelization (`agents/swarm-orchestrator.md`)
- **14 Specialized Lens Agents**: Math/Precision, Reentrancy/Transient Storage, Access Control, Economic/MEV, Oracle/Pricing, Lending/CDP, AMM/Hooks, Vault Inflation, Governance/Voting, Signatures/Permits, Proxies/Upgradeability, DoS/Griefing, Cross-Chain, and Low-Level Assembly.
- **3 Gap-Hunter Seam Agents**: Numerical-Economic, Trust-Callback, and State-Machine Flow seams.
- **Autonomous Skeptic Adversary**: Formulates committed invariant defenses (`[CI-1]` to `[CI-6]`) to disprove candidate findings.
- Automated bundle compiler (`scripts/build_swarm_bundles.py`) packing codebase source directly for zero-overhead parallel dispatch.

### 2. Automated Exploit PoC Synthesizer & DeFi Mock Battery (`skills/poc-builder/`)
- Pre-built DeFi mocks: `MockFlashLoanProvider.sol` (Aave/Balancer 0.09% fee), `MockOracle.sol` (Chainlink AggregatorV3 staleness/heartbeat simulation), and `MockHostileERC20.sol` (Fee-on-transfer, rebasing, reentrant callbacks, zero-transfer reverts, blacklist reverts).
- Automated CLI scaffolding (`scripts/generate_poc.py`) generating executable Foundry fork tests with hard assertions (`assertLt(victimBalanceAfter, victimBalanceBefore)`).

### 3. Real-World DeFi Exploit Post-Mortem Database (`knowledge/postmortems/`)
- Curated signature catalogue of 100+ landmark DeFi hacks (*Euler Finance $197M, KyberSwap Elastic $47M, Curve Vyper $60M, Platypus $8.5M, Radiant Capital $4.5M, Nomad Bridge $190M, Wormhole $320M, Mango Markets $114M, Hundred Finance $7M*).
- Instant trigger-matching linking code defects to historic exploit patterns.

### 4. Symbolic & Formal Invariant Synthesis (`skills/formal-verifier/`)
- Bounded symbolic execution via Halmos and Kontrol (`svm.createUint256()`, `svm.assume()`, `assert()`).
- Mathematical proof generation across $2^{256}$ input states for roundtrip conservation, zero-share minting prevention, and exchange rate monotonicity.

### 5. Automated Mitigation Verifier & Regression Testing Loop (`scripts/verify_mitigation.py`)
- Automated patch-and-verify closed loop:
  1. Applies recommended code diff to a temporary worktree.
  2. Re-runs the exploit PoC $\to$ **Asserts exploit reverts/fails**.
  3. Re-runs the protocol's full unit & integration test suite $\to$ **Asserts 0 regressions**.
  4. Emits authoritative status: `[MITIGATION-VERIFIED: BLOCKS_EXPLOIT + ZERO_REGRESSIONS]`.

### 6. AST & Static Analysis Pipeline Integration (`scripts/`)
- Multi-scanner aggregator (`scripts/run_static_analysis.py`) converting Slither, Aderyn, Semgrep, and 4nalyzer SARIF findings into prioritized seeds.
- AST & Storage Slot Topology Extractor (`scripts/extract_ast_topology.py`) mapping state variable slot offsets and inheritance hierarchies into `scope.md`.

---

## 📁 Repository Layout

| Directory / File | Description |
|---|---|
| `SKILL.md` | Master orchestrator: pipeline dispatch, effort modes, chain dispatch, global rules |
| `core/01..10` | 12-phase rigorous methodology guides loaded on demand |
| `agents/` | Swarm Orchestrator + 18 specialized lens, gap-hunter, and skeptic agent templates |
| `skills/evm-deep-audit/` | EVM sub-skill + 14-vector modern attack catalog |
| `skills/poc-builder/` | Executable Foundry scaffolds, DeFi mocks (FlashLoan, Oracle, Hostile ERC20) |
| `skills/fuzz-harness/` | Stateful invariant testing (Medusa, Echidna, Foundry handlers & properties) |
| `skills/formal-verifier/` | Halmos symbolic property testing & invariant proofs |
| `skills/solana-audit/` | Solana SVM sub-skill (Token-2022 Transfer Hooks, Anchor 0.30+, CPI reload) |
| `skills/move-audit/` | Sui/Aptos Move sub-skill (PTB atomic batching, capability `store` leaks) |
| `skills/zk-audit/` | Circom / ZK circuit sub-skill (soundness, field aliasing, division collapses) |
| `knowledge/postmortems/` | Landmark DeFi exploit database with root causes and invariants |
| `scripts/` | Mechanized CLI tools (Swarm bundle builder, PoC generator, mitigation verifier, AST extractor, static aggregator, fuzz runners) |
| `evals/` | Benchmark corpus (29 fixtures: 19 vulnerable + 10 clean, 100% precision & recall) |

---

## 🛠️ Usage

```bash
# Standard comprehensive audit (Recon -> Invariant Model -> Deep Analysis -> PoC -> Judge -> Report)
Audit this protocol.

# Deep audit with full parallel swarm, invariant fuzzing campaigns, and mainnet fork PoCs
Audit this protocol --deep.

# Quick triage scan (single-pass vector evaluation)
Audit this protocol --quick.
```

All audit artifacts and reports land in `{target}/ultimate-audit/` without modifying the target repository.


# Phase 1 — Recon & Scoping

Goal: discover, scope, and topologically map the target. Understand the architectural archetype, trust boundaries, and execution environment before hunting. Output: `{AUDIT_DIR}/scope.md` (use `templates/scope.md`).

## 1.1 Resolve the target & execution environment

- Project root, chain(s), compiler versions, EVM hardfork target (e.g. Cancun, Shanghai, Paris).
- **Default excludes:** `interfaces/`, `lib/`, `mocks/`, `test/`, `scripts/`, node modules, `*.t.sol`, `*.s.sol`, `*Mock*`, `*Test*` — unless the user explicitly scopes them.
- **Size guards:** source file >1 MB → refuse; >500 KB → treat as extreme complexity.
- **Toolchain & environment profile:**
  - Detect `foundry.toml`, `hardhat.config.*`, `Cargo.toml` + `Anchor.toml`, `Move.toml`, or Circom `package.json`.
  - Check EVM opcode capabilities: Cancun (`TSTORE`/`TLOAD`/`MCOPY`/`BLOBHASH`), Shanghai (`PUSH0`), Paris. If Cancun is active, mark **Transient Storage Lens** as mandatory.
  - Run baseline build: `forge build` / `cargo check` / `sui move build`.
  - Run test suite & coverage in background (`forge coverage` / `cargo test`) — test gaps reveal unverified assumptions.

## 1.2 Protocol Archetype Classification

Identify the primary and secondary protocol archetypes to activate specialized mental models in Phase 4:

1. **Lending / CDP / Money Market:** Collateral pools, debt tracking, interest rate curves, liquidations, oracle feeds.
2. **AMM / DEX / Liquidity Engine:** Constant product, concentrated liquidity (ticks), stableswap invariants, routing, hooks.
3. **Yield Vaults / Tokenized Assets (ERC-4626):** Share-to-asset accounting, deposit/mint/withdraw/redeem symmetry, multi-strategy allocations, yield harvesting.
4. **Liquid Staking & Restaking (LST / LRT):** Validator delegation, slashing propagation, unbonding queues, exchange rate sync.
5. **Perpetuals & Synthetic Derivatives:** Margin accounting, funding rates, skew management, mark/index prices, auto-deleveraging (ADL).
6. **Cross-Chain & Bridges:** Relayer messaging, payload serialization, nonce/hash replay, lock-mint / burn-unlock parity.
7. **Governance & DAOs:** Token voting weights, proposal lifecycles, execution timelocks, quorum checks, flash loan vote defense.
8. **Account Abstraction (ERC-4337):** UserOp validation, paymaster deposit accounting, bundler simulation compatibility, signature aggregators.
9. **Zero-Knowledge Circuits (Circom / Halo2 / Noir):** Proof verification wrappers, signal constraints, public input bindings.

## 1.3 Documentation, History & Mechanized Recon

- Run `bash {SKILL_DIR}/scripts/enumerate.sh <root> <src-dir>` — nSLOC, NatSpec ratio, test coverage stats, commit velocity.
- Run `python3 {SKILL_DIR}/scripts/analyze_git_security.py --repo <root> --src-dir <src-dir> --json {AUDIT_DIR}/git-security-analysis.json` — dangerous area changes, recent bug fixes, tech debt markers, forked dependency drift.
- Read **all** architectural documentation before writing: READMEs, whitepapers, audit history, bug bounty scopes, `SECURITY.md`, and deployment migration scripts.
- **Doc/Code Mismatch Detection:** Compare documentation claims against implementation reality (e.g. "fee is capped at 5%" vs code `require(fee <= 10000)`). Flag every discrepancy as `⚠️ DOC/CODE MISMATCH`.

## 1.4 Inter-Contract Call Graph & Topology

Map the contract relationships and data-flow topology:
- **Core State Holders:** Vaults, pools, ledger mappings, token storage.
- **Logic / Proxy Layers:** Implementation contracts, Beacon proxies, UUPS upgrades, Diamond facets.
- **Periphery & Routers:** User-facing routers, multicall wrappers, permit2 integrators, zap contracts.
- **External Dependencies:** Oracle aggregators (Chainlink, Pyth, RedStone), Uniswap pools, Curve gauges, lending adapters.
- **Callback & Hook Surfaces:** ERC-777/1155 tokens, Uniswap v3/v4 hooks, flash-loan receivers, liquidator callbacks.

## 1.5 Prior-Art & Known-Issues Register

- Consult public vulnerability databases (Solodit, Immunefi, historical contest findings).
- Record each prior finding with a **mechanism-level** note (what was broken, why it broke, how it was patched).
- Load relevant pattern families from `{SKILL_DIR}/knowledge/index.md`.

## 1.6 Complexity Rubric & Effort Mode Calibration

Score each dimension 1–4:

```
composite = 0.20×nSLOC + 0.25×externalIntegration + 0.20×stateCoupling 
          + 0.15×accessControl + 0.10×upgradeability + 0.10×mathComplexity
```

- **Red Flags (Auto-bump to ≥3.5):** User-supplied `delegatecall` targets; transient storage (`TSTORE`/`TLOAD`); untrusted callbacks in math loops; Solana user-supplied program accounts / `invoke_signed` complex seeds; Sui PTB atomic bundles; Circom `<--` unconstrained assignments.
- **Effort Dispatch:**
  - 1.0–1.5 LOW → Vector scan (`--quick`).
  - 1.6–2.5 MEDIUM → Full standard pipeline (`--standard`).
  - 2.6–4.0 HIGH/CRITICAL → Full pipeline + parallel lens subagents + fuzz harnesses + fork PoCs (`--deep`).

## 1.7 Trust Assumptions & Boundary Matrix

| From | To | Assumption | Breaking Scenario (Can unprivileged actor trigger?) |
|---|---|---|---|
| Users | Protocol | Assets held safely | Share inflation / donation attack |
| Protocol | Oracle | Fresh, non-manipulated price | Flash loan spot skew / stale round |
| Protocol | External Token | Standard ERC-20 compliance | Fee-on-transfer / rebasing / blacklisting |
| Core | Periphery | Parameters pre-validated | Parameter spoofing / arbitrary callback |

## Output: `scope.md`

Produce `{AUDIT_DIR}/scope.md` containing:
- Target identity, chain, compiler & EVM target versions.
- In-scope file list with nSLOC and complexity ratings.
- Classified protocol archetype and activated domain lenses.
- Inter-contract call graph and external dependency topology.
- Trust boundary matrix and doc/code mismatch register.
- Documented assumptions and open questions.

## Exit Gate

- Every in-scope file cataloged with entry-point classification.
- Protocol archetype identified.
- Trust boundary matrix populated with breaking scenarios.
- All baseline builds and script outputs collected.

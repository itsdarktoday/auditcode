# Tool Card — Foundry Fork Testing

**Run**: `forge test --fork-url $ETH_RPC_URL --fork-block-number N` with `vm.createSelectFork(...)` in the test (see `{SKILL_DIR}/skills/poc-builder/SKILL.md`).

**Questions it answers**: Does the exploit work against REAL deployed state — real pools, real oracle config, real token balances, real proxy admins?

**Evidence it produces**: the strongest PoC evidence available: end-to-end execution against mainnet state at a pinned block, with before/after balance proofs.

**Blind spots**: needs RPC access (public endpoints work; archive nodes needed for old blocks); block pinning means the PoC is a historical snapshot — state may differ today (note the block); fork tests do not simulate mempool/MEV context (sandwich feasibility needs separate reasoning); `deal`/`prank` abuse can fake anything — use them only where production-equivalent.

**Usage in the pipeline**: Phase 6 for finding class (b) — deployment-dependent findings. Also for **fork-differential analysis**: deploy the fork-origin protocol's code on the same fork and diff behavior against the audited fork (what changed = attack surface).

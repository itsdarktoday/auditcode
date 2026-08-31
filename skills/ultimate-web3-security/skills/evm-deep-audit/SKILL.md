---
name: evm-deep-audit
description: EVM/Solidity deep-analysis sub-skill for the ultimate-web3-security pipeline. Not intended to be invoked standalone; loaded by the master skill when the target is EVM (Solidity/Vyper).
---

# EVM Deep Audit

Loaded when the target is EVM. Extends the core pipeline with EVM-specific reasoning.

## Accounting-first posture

Most real EVM money bugs are **accounting desync**: value leaves the contract but the variable tracking it is never decremented (or decremented in only one of two branches). Before anything else, build the money map (core Phase 2) and treat every tracked total as an invariant: `totalX == Σ userX`.

## EVM-specific protocol modeling

- Token behaviors are **assumptions, not guarantees**: fee-on-transfer, rebasing, blacklisting, zero-amount reverts, dual-address (TUSD-style), decimals ≠ 18, missing return values. Note which tokens are arbitrary (user-supplied) vs protocol-owned.
- ETH vs WETH handling: `msg.value` enforcement on ETH branches is a classic gap (Socratic drill: why is the branch here, where is `msg.value == amount` enforced?).
- Pause-state asymmetries: which functions respect `whenNotPaused`, which don't, and what that desync enables.

## Lens dispatch (from core/04) — EVM triggers

Load `references/attack-catalog.md` entries when the trigger fires:

- **L1 Accounting drift** — always on.
- **L2 Access control** — trigger: modifiers, roles, init/`reinitializer`, ownership transfer.
- **L3 Rounding/precision** — trigger: shares math, exchange rates, rewards, fees, `mulDiv`.
- **L4 Oracle** — trigger: `latestRoundData`, TWAP, spot price reads, fallback oracles.
- **L5 Liquidation** — trigger: lending/vault/perp code paths.
- **L6 Signatures** — trigger: `ecrecover`, EIP-712, permits, meta-tx.
- **L7 Reentrancy/external calls** — trigger: any external call, tokens with hooks (ERC-777/1155), callbacks.
- **L8 Upgradeability** — trigger: proxy patterns, `delegatecall`, storage layout.
- **L9 Governance** — trigger: vote, propose, execute, timelock.
- **L10 DoS** — always on for user-facing loops and withdrawals.
- **L11 Cross-chain** — trigger: bridge/messaging contracts.
- **L12 Composability** — trigger: calls into external protocols (Uniswap hooks, staking integrations, routers).

## Do-not-flag list (safe patterns)

`unchecked` in 0.8+ (verify the reasoning) · explicit narrowing casts in 0.8+ (revert on overflow) · MINIMUM_LIQUIDITY burn on first deposit · SafeERC20 · `nonReentrant` present on the actual path (only flag cross-contract/read-only variants) · two-step admin transfer · consistent protocol-favoring rounding unless compounding or zero-rounding.

## Severity calibration (EVM-specific)

- Missing access control on a function setting a **protocol-wide economic parameter** → HIGH.
- Missing access control on **per-user state** setters → MEDIUM/LOW.
- Admin action with no timelock → LOW/INFO (centralization), unless an unprivileged amplifier is named.
- Missing `nonReentrant` with no callback-enabled token in scope → speculative, drop (FP risk); with a callback-enabled token, judge the actual path.
- Griefing/DoS affecting ALL users of a critical function → HIGH; per-user → MEDIUM.

## Static tooling

See `{SKILL_DIR}/tools/` cards. Slither first (`slither . --exclude-dependencies`), then Semgrep with the custom patterns under `tools/`, then CodeQL taint if available. Feed alerts into `leads.md` tagged with origin.

## Dynamic tooling

Invariant extraction + Medusa/Echidna via `{SKILL_DIR}/skills/fuzz-harness/SKILL.md`; Halmos for bounded symbolic checks of rounding/exchange-rate math; fork-differential for forked protocols.

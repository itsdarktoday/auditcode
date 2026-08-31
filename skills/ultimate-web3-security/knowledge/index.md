# Pattern Index

Trigger keywords → pattern file. Consulted in Phase 1.3 (prior-art) and Phase 4 (lens dispatch). Grows during Phase 12.

## EVM — reentrancy & external calls

- `read-only reentrancy`, `view after external call`, `oracle snapshot`, `Balancer-style` → `patterns/evm/reentrancy-read-only.md`
- `cross-function reentrancy`, `nonReentrant missing`, `callback`, `ERC-777`, `transitive reentrancy` → `patterns/evm/reentrancy.md`

## EVM — accounting

- `totalX == Σ userX`, `accounting desync`, `missing decrement`, `one-sided write`, `claim twice` → `patterns/evm/accounting-desync.md`
- `share inflation`, `first depositor`, `donation attack`, `totalAssets`, `rounding` → `patterns/evm/rounding-share-inflation.md`
- `fee-on-transfer`, `balanceOf vs amount`, `transferFrom accounting`, `rebasing`, `blacklisting`, `no return value` → `patterns/evm/tokens-erc-deviations.md`

## EVM — oracle & pricing

- `spot price`, `TWAP`, `latestRoundData`, `staleness`, `flash loan manipulation` → `patterns/evm/oracle-manipulation.md`

## EVM — access control & upgradeability

- `missing modifier`, `role confusion`, `ownership transfer`, `tx.origin`, `init abuse` → `patterns/evm/access-control.md`
- `storage collision`, `proxy slot`, `upgrade`, `beacon`, `UUPS` → `patterns/evm/storage-collision.md` + `patterns/evm/upgradeability.md`
- `uninitialized`, `front-run initialize`, `implementation init` → `patterns/evm/init-front-run.md`

## EVM — signatures & governance

- `replay`, `EIP-712`, `chainId`, `permit` → `patterns/evm/signature-replay.md`
- `voting manipulation`, `quorum`, `timelock`, `delegation`, `emergency` → `patterns/evm/governance.md`

## EVM — liquidation, DoS, MEV, composability, cross-chain

- `liquidation DoS`, `unliquidatable`, `bad debt` → `patterns/evm/liquidation-dos.md`
- `permanent lock`, `gas exhaustion`, `unbounded loop`, `griefing`, `63/64`, `EIP-150` → `patterns/evm/dos-griefing.md` + `patterns/evm/eip150-gas-griefing.md`
- `sandwich`, `front-running`, `slippage`, `MEV` → `patterns/evm/mev-frontrunning.md`
- `external protocol integration`, `hooks`, `cross-protocol assumption` → `patterns/evm/composability.md`
- `bridge`, `relayer`, `message replay`, `chainid` → `patterns/evm/cross-chain.md`

## EVM — L2 & Compiler Hazards

- `Arbitrum`, `Optimism`, `Base`, `zkSync Era`, `L2`, `extcodesize`, `block.number on L2` → `patterns/evm/l2-execution-hazards.md`
- `via_ir`, `optimizer`, `Yul`, `memory-safe`, `0.8.15`, `0.8.20 PUSH0` → `patterns/evm/compiler-optimizer-bugs.md`

## DeFi Exploit Post-Mortem Corpus

- `Euler`, `KyberSwap`, `Curve`, `Platypus`, `Radiant`, `Nomad`, `Wormhole`, `Mango`, `Hundred` → `postmortems/index.md`

## Solana

- `reload after CPI`, `stale account`, `CPI` → `patterns/solana/cpi-reload.md`
- `duplicate mutable account`, `from == to`, `account confusion` → `patterns/solana/duplicate-mutable-account.md`
- `PDA seeds`, `bump`, `signer`, `owner`, `reinit`, `remaining_accounts` → `patterns/solana/account-validation.md`
- `reward debt`, `share price`, `lamports`, `overflow` → `patterns/solana/economic-accounting.md`

## Move

- `capability store`, `Cap transfer`, `signer` → `patterns/move/capability-store.md`
- `capability burn/reissue`, `freeze`, `transfer policy`, `witness` → `patterns/move/capabilities.md`
- `UID/ID`, `dynamic fields`, `clock/epoch`, `abort-before-checkpoint` → `patterns/move/object-model.md`
- `PTB`, `check-vs-settlement`, `stale package` → `patterns/move/defi-timing.md`

## ZK

- `under-constrained`, `alias`, `division`, `Mux selector`, `public input` → `patterns/zk/soundness.md`
- `over-constraint`, `privacy leak`, `trusted setup` → `patterns/zk/completeness-privacy.md`

## Solana — fund locking & lifecycle

- `funder locked`, `deposit stuck`, `finalize revert`, `compute before move`, `no refund instruction`, `supply exhausted`, `terminal supply`, `epoch brick` → `patterns/pcn-funder-lock.md`

## 2026-08-14 — EBSI core services (EVM registries)
- Pattern: swap-and-pop index bookkeeping — when a dynamic array is swap-removed, every mapping that stores element→index MUST be remapped for the moved element, or the stale index later causes OOB panic (RecordLib.insertRecordOwner → permanent per-record DoS). Check both list+index pairs on every delete path (owners, revokedOwnerIds, children, allInvited, didsByController).
- Pattern: permissionless first-writer-wins DID insertion without key-to-identifier binding → squatting; gatekeeper must be off-chain AND documented, or bind identifier to key.
- Pattern: commit-reveal binding to msg.sender + EIP-712 field pinning + block maturity is the correct front-running defense; maturity must be ≥1 blocks after commit, measured from commit block.

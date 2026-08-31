# Token-2022 Extension Pitfalls (Solana)

Load-on-trigger: whenever a program touches a Token-2022 mint, token account, vault, escrow, staking flow, AMM, or bridge. Each entry: **Trigger → Exploit shape → Prove → Safe-policy**.

## Transfer fees (fee_basis_points / max_fee)

**Trigger**: `transfer`/`transfer_checked` on a mint with a transfer-fee extension; balance assertions using requested amounts.

**Exploit shape**: amount credited ≠ amount received (fee deducted) → accounting desync (mirror of EVM fee-on-transfer); the fee recipient can raise `fee_basis_points` mid-flow to drain settlement paths if its authority is untrusted.

**Prove**: show the settlement math uses pre-fee amounts and the mint has (or can get) fees.

**Safe-policy**: use post-transfer balances for settlement; or reject/whitelist fee mints; check `transfer_fee_config` authority is trusted and rate bounded.

## PermanentDelegate

**Trigger**: mint with permanent-delegate extension.

**Exploit shape**: delegate can move tokens WITHOUT holder consent — any "balance is a commitment" logic (collateral, escrow, auction deposits) is voidable; user funds walk away.

**Prove**: show the mint has a delegate and the protocol treats balances as committed.

**Safe-policy**: reject mints with permanent delegate at init (unless protocol explicitly trusts the delegate address).

## FreezeAuthority / MintCloseAuthority / CloseAuthority

**Trigger**: mints retaining freeze/mint/close authorities.

**Exploit shape**: freeze kills withdrawal flows (DoS of ALL holders of that token); `close` + reinitialize on the mint → token identity swap → redirect/drain attacks (attacker's "USDC" accepted where real USDC was expected).

**Prove**: show the authority is untrusted and the protocol's flows depend on freeze-ability or mint identity.

**Safe-policy**: require authorities revoked/renounced for protocol-critical tokens; never trust mint identity alone — check mint address against a canonical registry.

## Confidential transfers / realloc / metadata tricks

**Trigger**: newer extensions (confidential transfer, realloc) or mutable metadata.

**Exploit shape**: hidden balances break `amount == expected` logic; realloc changes account size assumptions; metadata swap → phishing-grade confusion.

**Prove**: show the protocol reads balances/identity that the extension can change.

**Safe-policy**: whitelist the exact extension set accepted; validate `AccountType` (Token vs Mint vs Multisig) with discriminators.

## Dual-WSOL / native handling

**Trigger**: programs handling both SOL and WSOL (`syncNative`, `close_account`).

**Exploit shape**: wrap/unwrap paths not atomic with settlement → attacker splits the flow (funds stuck in WSOL account they control, or `syncNative` griefing); `close_account` lamport accounting crediting the wrong account.

**Prove**: trace the wrap/unwrap + settle sequence; show a split.

**Safe-policy**: single atomic instruction wraps→settles→unwraps; validate close destination.

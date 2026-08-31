# cpi-reload (solana)

root cause: after a CPI that mutates an account, the program continues using the stale in-memory copy of that account.
protocol type: any Solana program performing CPIs (token transfers, other programs)
affected architecture: instruction handlers that CPI into token-2022/token/other programs and then check or use the account's lamports/token balance/state.
attack preconditions: a CPI path where the invoked program changes account data (transfer, transfer fees, delegation, close); attacker can order account arguments to exploit the stale view.
invariant violated: "in-memory account state equals on-chain account state at every post-CPI use".
exploit pattern: program transfers X via CPI then checks `token_account.amount` (stale pre-transfer value) to authorize a withdrawal or reward → double-spend / over-credit; token-2022 transfer fees make the delta non-obvious.
detection strategy: mark every CPI call; after each, list every subsequent read of any CPI-touched account; require `reload()`/re-derivation before use. Grep for `transfer` followed by balance reads in the same handler.
false-positive indicators: `reload()` after every CPI; post-CPI checks only read accounts the CPI cannot touch; balances re-fetched via a fresh CPI/read.
example PoC: none yet.

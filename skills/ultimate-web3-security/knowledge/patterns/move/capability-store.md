# capability-store (move)

root cause: a capability struct carries the `store` ability, so it can be wrapped/transferred, breaking "only the intended holder has it".
protocol type: Sui/Aptos Move protocols (coins, vaults, markets)
affected architecture: capability structs (MintCap, BurnCap, FreezeCap, UpgradeCap, AdminCap) with abilities `store`/`copy`/`drop`; creation paths that don't burn or restrict the cap.
attack preconditions: an attacker path that obtains the cap (marketplace, wrapping exploit, shared-object confusion) or a re-issuance path (upgrade re-mints).
invariant violated: "each capability has exactly one holder, fixed at creation; no path mints a second".
exploit pattern: cap with `store` is wrapped into another object and traded → attacker buys authority (mint, freeze) → inflate supply, freeze user funds; or an upgrade path re-creates the cap without burning the old one.
detection strategy: for every capability struct: audit abilities (no `store`/`copy` unless intentional), audit every construction site (burn the original? one-time guard?), audit whether the cap is required at entry (signer vs cap mismatch).
false-positive indicators: cap structs without `store`; one-time creation guard consumed on first use; caps held only by protocol-controlled addresses verified on-chain.
example PoC: none yet.

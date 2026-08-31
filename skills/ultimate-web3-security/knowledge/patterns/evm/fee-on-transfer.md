# fee-on-transfer (evm)

root cause: protocol assumes `transferFrom(amount)` delivers `amount`; fee-on-transfer tokens deliver less.
protocol type: any protocol accepting arbitrary ERC-20s (vaults, DEX, lending, staking, bridges)
affected architecture: deposit/credit paths that credit `amount` based on the requested value; liquidation paths computing exact debt paydown; permit + transfer flows.
attack preconditions: an arbitrary (user-supplied or whitelisted) token that charges transfer fees, rebases, or returns non-standard values.
invariant violated: "credited balance == actual received balance" (`Σ user claims <= actual balance`).
exploit pattern: (a) deposit credits 100 but only 97 arrives → attacker withdraws 100 repeatedly, draining others (inflation); (b) liquidation repays `amount` but contract receives less → debt not cleared → bad debt; (c) permit approves X but transfer pulls X−fee → accounting mismatch; (d) fee-on-transfer breaks exchange-rate math (totalAssets from raw balance).
detection strategy: for every `transferFrom`/`transfer` on non-constant tokens: is the credited value derived from requested or from actual (before/after `balanceOf` delta)? Grep deposits, claims, liquidations, bridges.
false-positive indicators: only a fixed whitelist of standard tokens accepted; balance-delta accounting (`after - before`) used; token registry rejects fee tokens; the value difference is the caller's own loss only.
example PoC: none yet.

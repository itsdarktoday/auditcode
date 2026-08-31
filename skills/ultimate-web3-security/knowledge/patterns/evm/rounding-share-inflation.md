# rounding-share-inflation (evm)

root cause: share/exchange-rate math rounds in a direction that is exploitable when looped or when donations skew `totalAssets`.
protocol type: vault / ERC-4626 / staking with shares
affected architecture: `shares = amount * totalSupply / totalAssets`-style math, first-deposit handling, reward accrual from raw balances.
attack preconditions: attacker can deposit/withdraw repeatedly (loop-able rounding) or donate assets directly to the contract (inflation).
invariant violated: "share value never decreases", "deposit/withdraw round-trip is lossless within rounding", "first depositor cannot capture donated value".
exploit pattern: (a) first depositor mints 1 wei share then donates to inflate totalAssets → next depositor's shares round to 0 (steals their deposit); (b) repeated deposit/withdraw harvests rounding dust at victim scale (loop-able → not Low); (c) protocol-favoring rounding compounds into material value.
detection strategy: trace the share formula with concrete numbers (Phase 2.7 numeric grounding); check MINIMUM_LIQUIDITY-equivalent protection on first deposit; check whether rounding is loop-able (per-tx cost < per-tx gain); Halmos on the exchange-rate function.
false-positive indicators: virtual/offset accounting (Uniswap v3 style); MINIMUM_LIQUIDITY present; one-time dust < gas cost; rounding favors the protocol consistently AND victims are the protocol's own fees only; explicit docs accepting precision loss.
example PoC: none yet.

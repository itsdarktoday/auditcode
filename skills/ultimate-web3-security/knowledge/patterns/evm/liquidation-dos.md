# liquidation-dos (evm)

root cause: positions become unliquidatable (or liquidations unprofitable) through token behavior or gas/rounding effects; bad debt accrues to the protocol.
protocol type: lending, perp, margin protocols
affected architecture: keeper/auction liquidation flows, health-factor checks, collateral seizure, partial liquidation math.
attack preconditions: a token with blocking behavior (fee-on-transfer, blacklist, reverting transfer) as collateral; or rounding that makes liquidation unprofitable; or griefable auction parameters.
invariant violated: "every underwater position can be liquidated; protocol stays solvent".
exploit pattern: (a) attacker self-positions with a blacklisting/fee token so the liquidation `transferFrom` reverts forever → position unliquidatable → protocol eats bad debt; (b) rounding makes liquidator profit < gas → no one liquidates → bad debt; (c) auction griefing (one bid blocks settlement); (d) unfair liquidation price steals from users (opposite direction).
detection strategy: trace the liquidation path with each accepted collateral type; check exact-amount assumptions; check keeper incentives at boundary prices; check health-factor math uses the same oracle as the attack can move.
false-positive indicators: liquidation uses balance-delta accounting; collateral whitelist excludes blocking tokens; keeper incentives have caps and floor; TWAP-protected liquidation prices.
example PoC: none yet.

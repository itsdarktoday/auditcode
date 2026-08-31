# oracle-manipulation (evm)

root cause: a user-affecting value (price, rate) is derived from manipulable, stale, or misconfigured oracle data.
protocol type: lending, perp, DEX, liquidations, any pricing consumer
affected architecture: spot-reserve reads, short TWAPs, Chainlink feeds without staleness/heartbeat checks, fallback oracle switches, decimals conversions.
attack preconditions: the feeding pool is shallow enough to move (flash-loanable); or the feed can be stale/zero; or the fallback is attacker-influenceable.
invariant violated: "prices reflect the true market within tolerance at the moment of use".
exploit pattern: (a) flash-loan moves a spot pool, then a same-tx borrow/liquidate/exit uses the poisoned price; (b) stale Chainlink answer (no `updatedAt` check or zero price) lets trades happen at dead prices; (c) decimals mismatch (8 vs 18) scales prices 1e10; (d) TWAP window too short to resist sandwiching; (e) oracle-fallback switch is manipulable.
detection strategy: for each price read: which pool/feed, at what liquidity, checked at what freshness, with which decimals? Compute manipulation cost for X% move and compare to extractable value.
false-positive indicators: 30-min+ TWAP on deep pools; staleness checked with correct heartbeat and price>0; manipulation cost > profit (show math); admin-controlled oracle with governance and timelock.
example PoC: none yet.

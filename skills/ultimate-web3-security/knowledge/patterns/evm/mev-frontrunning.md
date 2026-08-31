# mev-frontrunning (evm)

root cause: value can be extracted from transaction ordering — user transactions carry no effective slippage/deadline/ordering guarantees, so adversarial reordering captures the difference.

protocol type: DEX/AMM (V2/V3/V4), lending/liquidation, auctions, staking reward flows, ERC20 approvals/permits.

affected architecture: swap paths with min-output params, pool share/rate functions, liquidation bonuses, auction bid timers, permit/approve+action sequences.

attack preconditions: mempool visibility on a public chain; hardcoded or absent slippage/deadline; price-sensitive state (spot reserves, share prices) changeable within one block; attacker capital, usually flash-loanable.

invariant violated: the user receives ≥ their quoted output within their stated deadline; prices/rates reflect committed pre-tx state; one order per auction/approval.

exploit pattern:
- sandwich: buy before the victim's swap, sell after (price impact); concentrated-liquidity variant pushes price out of the victim's active tick range for maximum slippage.
- deposit-sandwich: inflate share price before a victim's deposit, back-run to withdraw the profit (donation/first-depositor inflation).
- liquidation-backrun: move price to the liquidation threshold, then back-run liquidate to capture the bonus.
- frontrun-init/approve: front-run initialize() with attacker params; front-run approve(newValue) to consume the old allowance; front-run permit nonce consumption (wrap in try/catch); front-run reward claims to shift payout rates.
- jit-liquidity: add concentrated liquidity around a pending swap, earn the fees, remove in the same block — dilutes passive LPs (check minimum lock period).
- first-swap/lp-migration: pool initialized at the wrong ratio → first swapper extracts the difference; non-atomic LP migration between pools is a manipulation window.
- lvr/multiblock: rebalancing strategies always trade at the stale price (loss-versus-rebalancing); multi-block TWAP manipulation is cheaper with short observation windows.
- slippage-deadline: amountOutMin=0 hardcoded or dropped by the router; deadline == block.timestamp (zero protection); slippage computed before fee deduction; withdrawal path lacking min-output protection.

detection strategy: grep amountOutMin/minAmountOut/sqrtPriceLimitX96 for hardcoded zeros or non-passthrough; verify deadlines are user-supplied and compared strictly to block.timestamp; flag spot-price reads (getReserves/balanceOf) in valuation where a TWAP/staleness-checked feed belongs; audit permit flows for front-run handling; check auction bid paths for self-bid/timer-reset and refund mechanics. Tools: manual order-dependency traces, Slither weak-prng for timestamp randomness, param-passthrough audits on routers.

false-positive indicators: user-supplied min-out and deadline enforced at the pool itself; TWAP/Chainlink with staleness checks for valuation; virtual-offset share math; minimum LP lock period; atomic deploy+init or commit-reveal; permit wrapped in try/catch.

example PoC: none yet.

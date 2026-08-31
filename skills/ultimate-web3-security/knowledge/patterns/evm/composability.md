# composability (evm)

root cause: integration code trusts external protocol behavior that is permissionless, version-specific, or silently different — others act on the contract's behalf, hooks execute attacker code, or shutdown paths behave unexpectedly.

protocol type: adapters/aggregators/vaults over Uniswap, Aave, Curve, Convex, Lido, Chainlink; flash-loan consumers; hook-enabled pools (UniV4).

affected architecture: external call sites (swap/claim/withdraw), callback handlers, token-approval grants, price/rate reads from external contracts.

attack preconditions: an external function callable by anyone against the contract's position (getReward(address,bool), claimComp, claimRewards); unvalidated callback msg.sender; reliance on return values instead of balance deltas; external pools that can be killed/paused.

invariant violated: the contract's external positions and approvals change only as its own logic intends; observed balances/values equal actual external protocol state.

exploit pattern:
- permissionless-claim: external reward/withdraw functions that anyone can trigger for the contract → front-run reward claims or force unfavorable exits; measure the ACTUAL balance delta, never a precomputed earned().
- callback-spoof: flash-loan/UniV4-hook callback missing msg.sender validation → attacker calls the callback directly to mint/finalize without repayment; hooks re-enter (see reentrancy pattern).
- silent-failure: external call returns without effect (CVX.mint when not operator, non-reverting ERC20, killed Curve pool) → the contract continues with wrong assumed amounts.
- version-drift: semantics differ per version/upgrade — Curve get_dy vs exchange, native-vs-WETH ocean ids, Aave aToken rate timing, Compound cToken→Comet, UniV3 negative-tick rounding; external upgrades/deprecations silently break assumptions.
- shutdown-migration: external pool/market/vault paused or killed → user paths revert (bricked funds) with no governance path to migrate the dependency.
- return-vs-delta: trusting swap() return amounts instead of measuring balanceOf delta → front-run/refund mismatches corrupt accounting.
- donation-flashloan: accounting from balanceOf(address(this)) lets flash-loan deposits and donations corrupt share prices/exchange rates (see flashloan module).
- approval-overbroad: infinite approvals to external routers → any router bug drains the contract; skim/sweep/claimRewards destinations mis-mapped (funds land elsewhere).

detection strategy: build the integration inventory (protocol, version, functions called, data dependency); for each external call determine: permissionless-callable?, silent-fail paths, balance-delta vs return-value; grep callback functions for msg.sender validation; confirm dependency migration/kill-switch setters exist; classify external price reads as spot vs TWAP. Tools: manual matrix plus grep of .call/.staticcall sites; Slither arbitrary-send-erc20 for approvals.

false-positive indicators: trusted version-pinned adapters with balance-delta accounting; callbacks validate msg.sender == known pool; kill-switch/migration setters present; TWAP/staleness-checked oracles; minimal targeted approvals.

example PoC: none yet.

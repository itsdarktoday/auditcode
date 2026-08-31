# tokens-erc-deviations (evm)

root cause: code assumes standard ERC20 behavior (amount sent == amount received, balance static, bool returned, transfer always succeeds) while real tokens deviate — fees, rebases, blocklists, missing returns, zero-reverts, dual addresses, odd decimals.

protocol type: any handling user-supplied or arbitrary tokens: DEXes, vaults, lending, staking, bridges, launchpads, fee-distribution sweeps.

affected architecture: deposit/withdraw accounting, share/rate math scaled by decimals, fee-collection and rescue/skim paths, token whitelists.

attack preconditions: a non-standard token listed or routed through (USDC/USDT blocklists, stETH rebases, fee-on-transfer memecoins, BNB zero-reverts); or an attacker chooses the token passed to a generic handler.

invariant violated: internal accounting equals actual measured token delta (recorded balance == balanceOf-measured receipt); any token accepted is deposited/exited safely or rejected.

exploit pattern:
- fee-on-transfer: credit requested amount while transfer delivered amount−fee → protocol bleeds; fix by balance-delta before/after measurement.
- rebasing: cached balanceOf/totalSupply goes stale between rebases → wrong share/rate math; use shares (wstETH) or re-read fresh.
- blocklisting: blocklisted fee recipient/treasury makes every routed transfer revert → permanent DoS; pull-pattern fee accrual + try/catch restore.
- no-return: USDT-style transfer without bool reverts under IERC20/SafeERC20-free code; never assume return values, always SafeERC20.
- zero-amount-revert: BNB/LEND revert on 0-amount transfers → skip zero amounts in loops/distributions.
- dual-address: TUSD-style proxy pairs (double entry points) let users deposit via one address and withdraw via another; validate token identity, don't trust balanceOf alone.
- decimals: hardcoded 18 breaks USDC(6)/WBTC(8); 10**(18−decimals) underflows for >18; cToken 8 vs underlying 18 mis-scaling; same token different decimals across chains (USDC 6 vs 18).
- approval-race/permit: approve(newValue) front-run consumes old allowance; permit tx front-run burns nonce (wrap in try/catch); permit signed for a different token still yields a valid ecrecover.
- self-transfer: from==to with cached balances double-credits or overwrites state; guard or use direct storage ops.
- callback-tokens: ERC777/1363/721/1155 hooks execute user code mid-transfer (see reentrancy pattern).

detection strategy: grep token.transfer/transferFrom/approve for SafeERC20 and return checks; grep 1e18/10**18/decimals() for hardcoded scaling; enumerate every function crediting amounts after transferFrom (FOT); compare balanceOf(address(this)) usage vs internal counters (donation/rebase); check token-address validation on generic handlers; spot tokensToSend/onReceived hooks on any transfer path.

false-positive indicators: token whitelist pinned to known-standard assets; balances always measured by delta; non-rebasing wrapper (wstETH); zero amounts guarded; SafeERC20 everywhere plus pull-payments; single canonical entry point with identity check.

example PoC: none yet.

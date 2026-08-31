# dos-griefing (evm)

root cause: protocol work or funds depend on unbounded inputs or adversarial participants — attackers grow collections, revert callbacks, or force state that makes core paths permanently fail at trivial cost.

protocol type: any with loops over user data, push-payments, queues, auctions, staking cooldowns, keeper-callable claims.

affected architecture: batch/distribution loops, refund paths, user-growable arrays, balanceOf-based accounting, timers reset by deposits.

attack preconditions: attacker-controlled array length, entry count, or callback behavior (reverting receiver, gas-wasting fallback, blocklisted address); grief cost << victim loss.

invariant violated: core operations complete for all legitimate users regardless of other participants' actions; all protocol work is bounded.

exploit pattern:
- permanent-lock: push-refund to a reverting contract bricks auction bids (use pull-pattern); blocklisted or EOA-reverting payee bricks distribution loops; exits blocked while entries open; paused token/entity prevents withdrawing pre-existing positions; users can't unwind positions after an entity is removed.
- gas-exhaustion: unbounded loop over a user-pushable array; O(n²) nested scans or string concatenation; array.length re-read from storage each iteration; one ERC20 transfer per iteration caps ~447 users at a 30M gas limit.
- state-bloat: no minimum deposit/amount → 1-wei deposits flood arrays (10k dust withdrawal requests poison the queue); storage entries cost the attacker pennies but persist forever; onBehalf staking lets an attacker bloat a victim's history.
- callback-revert: one revert in a batch bricks all recipients (no try/catch); return-bomb sends 10MB returndata → OOG on copy; gas-wasting receive().
- 63/64-griefing: relayer supplies just enough gas — outer call succeeds, inner call OOGs, nonce consumed anyway; guard with gasleft() checks and success requires.
- force-fed-eth: selfdestruct donation breaks address(this).balance == expected checks and balance-derived accounting (survives EIP-6780); use internal counters.
- zero-value-op: deposit(0) resets cooldown/lastDepositBlock and blocks same-block withdrawals; zero transfers on reverting tokens brick loops.
- timestamp-griefing: block.timestamp deadlines (proposer shift ~12s) brick last-moment auction bids; a 1-wei deposit resets a victim's lock timer.

detection strategy: for every loop record its bound and data source (user-controlled? capped?); grep .push( without a max check; check every external call inside batch paths for try/catch or pull-pattern; grep balanceOf(address(this))/address(this).balance for donation sensitivity; check minimum-amount guards on deposit/queue entry points. Tools: Slither costly-loop/unbounded-loop detectors, manual grief-ratio estimate (victim loss / attacker cost).

false-positive indicators: capped arrays (MAX_*), per-user pagination/keep-per-user processing, pull-payments, minimum deposits, internal accounting instead of balanceOf, try/catch on optional payments, zero-amount guards.

example PoC: none yet.

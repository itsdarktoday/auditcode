# defi-timing (move)

root cause: state is checked and settled at different times than the protocol assumes: per-call limits re-evaluated mid-PTB, checkpointed accounting written out of order or never synced, old package versions settling on new state, and user intents bound at signing but resolved at execution.

protocol type: Sui/Aptos DeFi (DEX, lending, staking, oracles, bridges)

affected architecture: PTB-composable entry functions with per-call numeric limits (close factors, rate limits, flash loans), accumulator/reward-debt checkpoint accounting, multi-version shared objects, signed transaction/intent binding.

attack preconditions: a per-call limit is checked against current state in a function a PTB can call repeatedly in one transaction; reward checkpoint fields default to 0/stale; a shared object lacks a version assert while old packages stay callable; signed parameters (price, deadline, chain, amount) are not re-validated at settlement.

invariant violated: "settlement uses the same state snapshot the check was made against: per-transaction limits hold across PTB calls, reward deltas use synced checkpoints, only current-version code touches shared state, and signed intents bind their parameters."

exploit pattern: (concrete variants, one line each)
- call `liquidate()` N times in one PTB: close factor recomputed on remaining debt each call → 50%+25%+12.5%+… ≈ full liquidation (SUI-28)
- per-call rate limit/cooldown/withdrawal cap re-read mid-PTB → N× the limit inside one transaction (SUI-28)
- flash-loan stake→claim→unstake in one PTB with accumulator updated per call → inflated rewards (common-move 10.2)
- per-account `last_index`/`reward_debt` initialized to 0 instead of the current pool index → entire historical accumulator credited (DEFI-88, Scallop)
- stale package (V2) without a version assert callable directly on the live shared object → the fixed bug stays exploitable (SUI-23)
- admin function changing reward rate or total staked without `update_reward_index()` first → silent reward theft/dilution (DEFI-15)
- price read at check time, settled later at a different price with no staleness/ref-price binding → oracle drift profit (DEFI-17/19/95)
- signed message/quote lacking chain ID, deadline, nonce, or amount binding → replay or stale-quote execution (DEFI-75)
- checkpoint written after aborting arithmetic → time delta grows on every retry, function permanently stuck (common-move 12.1)
- lock/denylist decision made at one epoch and funds settled in the next → burned source-side, blocked destination-side (SUI-21)

detection strategy: (code shapes/triggers/tools)
- for every entry with a numeric limit, test PTB-repeatability: simulate 5 sequential calls in one PTB against fresh state; flag limits derived from state the function itself mutates (SUI-28 ritual)
- grep constructors of `last_index|reward_debt|last_update|last_accrual` fields for `0`/`default()` initializers — across every historical package version, not just the active one
- build the SHARED-object list (grep `share_object`) and require a `version` field + assert at the top of every `&T`/`&mut T` function plus a wired migration (SUI-23 ritual)
- grep admin entry points that mutate rate/total-staked without calling the accumulator updater first
- in signed flows: grep for chain ID, nonce/deadline, and amount inclusion in the signed payload (defi/defi-signatures.md)

false-positive indicators: limits tracked cumulatively per transaction (hot-potato accumulators, per-obligation flags); constructors syncing checkpoints to the current pool index on all versions; version-gated shared objects with wired migration; admin paths updating the accumulator first; signed quotes include deadline and are re-checked at settlement.

example PoC: none yet.

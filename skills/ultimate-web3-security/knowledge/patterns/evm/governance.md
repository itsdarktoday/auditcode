# governance (evm)

root cause: voting power, quorum, or execution authority derived from manipulable/live state or bypassable lifecycle checks — attackers acquire cheap votes, or proposals execute without the intended authorization, delay, or payload match.

protocol type: DAOs, ve-token/slope-voting systems, staking-governance hybrids, multisig+timelock stacks.

affected architecture: proposal state machines, checkpoint/snapshot vote accounting, timelock queues, delegate registries, aggregate vote-weight variables (bias/slope/totalWeight).

attack preconditions: votable/executable path reachable in one tx without a snapshot; quorum computed live; timelock admin or setDelay callable outside the governor; entities removable while their positions still count.

invariant violated: one token = one vote at the proposal snapshot; votes only counted within the proposal lifecycle; execution requires quorum + delay + the exactly queued payload.

exploit pattern:
- flashloan-voting: castVote reads live balanceOf/getVotes → borrow-vote-repay in one tx; flash-loaned tokens delegated to self and voted.
- double-voting: transfer-and-revote without checkpoint write in _beforeTokenTransfer; self-delegation counted as holder AND delegatee (2x).
- quorum-manipulation: quorum from live totalSupply (mint/burn racing); totalSupply==0 → 0 quorum; burned/stranded tokens inflate the denominator → unreachable quorum.
- timelock-bypass: timelock admin is an EOA; setDelay(0) allowed or not itself delayed; executor accepts targets/values/calldata mismatching the queue; keccak(target,value,data) collision overwrites a queued proposal; direct admin calls skip the timelock.
- proposal-lifecycle: create+vote+execute in the same block; execute before voting period ends; votes accepted on queued/executed proposals; cancel front-run by an opposing proposer; re-execution of executed proposals.
- delegation-griefing: delegatee accumulates checkpoints → re-delegation gas-exhaustion; dust positions inflate checkpoint count (voting-dust inflation).
- emergency-powers: pause blocks exits while entries remain open; no unpause; renounce-while-paused; whenNotPaused on liquidate() accumulates bad debt; removal of an entity prevents users from unwinding positions created earlier.
- aggregate-desync: removal updates totalBias but not slope/changesSum; two-step removal where users skip step 2 leaves inflated aggregates; division-by-zero when all participants removed.
- checkpoint-window: MAX_NUM_WEEKS < maxLockPeriod/WEEK → long locks return zero weight or stale extrapolation.
- exit-manipulation: ragequit/exit reads live treasury balanceOf → sandwiched by a treasury-draining proposal; exit callable by anyone for any member.

detection strategy: build the role-capability matrix (propose/vote/queue/execute/cancel/pause); verify getPastVotes(,snapshot) not getVotes; grep state(id) checks on every proposal-taking function; confirm timelock admin == governor and delay > 0; enumerate every aggregate on add/remove paths and mirror the update. Triggers: totalSupply inside quorum math, block.timestamp == endBlock races, keccak-only proposal ids, balanceOf(treasury) in exit math.

false-positive indicators: checkpoints snapshotted at proposal creation; quorum as % of fixed snapshot supply; timelock admin is the governor and delay non-zero; aggregates mirrored on removal with MAX_WEEKS >= maxLock/WEEK; exits use internal accounting.

example PoC: none yet.

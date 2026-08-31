# reentrancy (evm)

root cause: control returns to attacker-controlled code during an external call while protocol state is only partially updated; any state read or written in that window is stale or unprotected.

protocol type: any moving tokens/ETH: vaults, DEXes, lending, staking, NFT markets, bridges, flash-loan consumers.

affected architecture: functions with external calls (raw call, ETH send, token transfer, hooks, flash callbacks) positioned before/among state writes; multi-function contracts sharing state; view functions exposing mid-update state.

attack preconditions: attacker-controllable callee (msg.sender on withdraw, callback-enabled tokens, flash-loan callback, user-supplied target) plus a second entry point or external protocol that can act on the stale state.

invariant violated: settled state — no observable inconsistency between internal accounting and external effects during any external call; each unit of value leaves exactly once.

exploit pattern:
- single-function: external call (.call/send/transfer) before the state write (balance decrement) in the same function; re-enter and double-withdraw. NOTE (0.8 falsification, verified by PoC): decrement-style bugs on a single mapping in pure-ETH vaults are NOT exploitable — the recursive unwind underflows on the second decrement and reverts the whole tx; the exploitable shape uses a CACHED amount + assignment-style zeroing (`amount = balances[user]; send(amount); balances[user] = 0`) or cross-function/second-mapping state.
- cross-function: function A guarded (nonReentrant/CEI), function B sharing the same state unguarded; re-enter B during A's call.
- read-only: view function computes price/rate/balance from state mid-update during a callback; another protocol reads the poisoned value.
- cross-contract/transitive: state split across contracts, or a downstream protocol reads victim's mid-call state; includes re-entering a DIFFERENT protocol sharing the same pool.
- token-callback: ERC777 tokensReceived/tokensToSend, ERC1363 onTransferReceived, ERC721/1155 onReceived hooks give recipient execution during safeTransfer/safeMint.
- init-reentrancy: external call mid-initialize() re-enters to exploit partially set state.
- flash-callback: flash-loan/flash-swap/liquidation callback re-enters the flash entry function or related state; repayment/collateral invariant checked in the wrong order.

detection strategy: for every external call list (a) state writes after it, (b) other public functions reading/writing those variables, (c) views reading them. Triggers: .call{value} or safeTransferFrom before balance update; receive/fallback on payable state functions; tokensReceived/onERC721Received implementations; flash entry lacking nonReentrant. Tools: Slither reentrancy detectors (miss read-only/cross-contract), modifier sibling-diff (compare modifiers across functions sharing state), guard-coverage matrix. Do not trust transfer()/send() 2300-gas or CEI alone.

false-positive indicators: all state settled before every external call and no other function/contract observes mid-call state; guard on ALL entry points in the state group; view returns caller-private data only; callback msg.sender validated against a trusted pool; pull-payment only.

example PoC: evals/corpus/test/EvalPoCs.t.sol::test_V01_reentrancy (assignment-style zeroing drain; also documents the 0.8 decrement-style falsification).

# read-only-reentrancy (evm)

root cause: a `view` function reads protocol state while an external call mid-update has left it inconsistent; attacker reads the poisoned value to steal.
protocol type: DEX / vault / lending (anywhere a price, rate, or balance is derived from live state)
affected architecture: update flows that (1) mutate state, (2) make an external call, (3) mutate state again — while a view function computes a user-facing value from state between (2) and (3).
attack preconditions: a callback-capable token/contract on the deposit/withdraw path (ERC-777, ERC-1155, malicious token), or a hook the user controls.
invariant violated: derived values (price, exchange rate, balances) equal the settled state ("price reflects committed reserves").
exploit pattern: attacker calls the state-changing function → external call fires attacker's callback before the final state update → inside the callback, attacker calls the view (or another contract reads it) and acts on the intermediate value (arbitrage, cheaper exit, bigger borrow).
detection strategy: mark every external call that sits BETWEEN two state updates; check which views/functions read the touched state; ask whether any user-facing value can be computed mid-update. Static: Slither reentrancy detectors miss this class — manual trace + targeted Semgrep ("state write, external call, state write in one function").
false-positive indicators: `nonReentrant` does NOT protect views — irrelevant signal; the view only reads caller-private state; the intermediate value is not usable by anyone (privileged reader only); state is updated atomically before the external call (CEI satisfied).
example PoC: none yet.

# access-control (evm)

root cause: privileged state mutation reachable by unauthorized callers — missing, wrong, or inverted checks, unguarded initialization, or caller identity established from spoofable inputs (tx.origin, attacker-supplied from, unvalidated callbacks).

protocol type: any with roles/ownership: proxies, tokens, bridges, routers/multicall, staking, governance, helper/periphery contracts.

affected architecture: setters, minters, upgraders, withdrawals; initialize()/reinitializer flows; periphery contracts (bridge token setters, adapters) that mirror main-contract privileges.

attack preconditions: a state-writing external function without a modifier or with a bypassable check; an initialization window that can be raced; a lower role able to reach higher-role actions.

invariant violated: every state transition is authorized — only the configured role performs each mutation, and that authorization survives deployment, upgrades, and ownership transfers.

exploit pattern:
- missing-modifier: state mutator (mint, setFee, rescueTokens, setRouter) with no onlyOwner/onlyRole or bare/unconditional require; modifier present on siblings but dropped on one function.
- init-abuse: initialize() callable twice or front-runnable (deploy+init gap); implementation initialized directly (missing _disableInitializers); reinitializer without version bump; _setupRole after deploy without check.
- role-confusion: wrong role on a check; lower role escalates (role admin == role holder); self-grant; inconsistent enforcement across entry points (transfer guarded, unstake/fee-claim not).
- ownership-transfer: single-step transfer to wrong/zero address; stale pendingOwner accepted; renounce leaves no admin; renounce-while-paused locks; hardcoded admin or deployer privilege retention; cross-chain privilege persistence.
- tx.origin: auth via tx.origin breaks with any intermediary; EXTCODESIZE==0 EOA checks invalidated by EIP-7702 delegated EOAs; whitelist privilege borrowing via 7702 delegation; dual-signature validation ambiguity.
- arbitrary-target: delegatecall/call to a user-influenced or setter-mutable address grants full storage write; implementation slot writable by non-timelocked admin.
- restriction-gap: blocklist/pause covers transfer() but not unstake()/claims (blocked users exit another way); transfer hook blocks the admin burn meant for restricted addresses; msg.sender-only check bypassed via transferFrom.
- on-behalf-without-auth: permissionless router/multicall takes attacker-supplied from/owner and drains anyone who approved it; callback entry points (onERC721Received, flash callbacks) missing msg.sender validation.
- two-step-race: two-step flows (propose/claim, deposit/withdraw pairing) where the second step lacks the first step's auth, or aggregate state updates land in the wrong step.

detection strategy: enumerate every external/public non-view function → map modifier/require → flag missing or wrong; modifier sibling-diff (functions missing a modifier their state siblings have); grep tx.origin, ecrecover, delegatecall targets, setRouter/setMinter/setBridge, initialize; check initializer guard + _disableInitializers + reinitializer version. Enumerate centralization surface: worst-case damage per role (mint unbounded? fee to 100%? pause exits?). Tools: Slither unprotected-upgrade/uninitialized-state/arbitrary-send, Semgrep for bare require(msg.sender ==).

false-positive indicators: function permissionless by design with no privileged side effects; auth enforced in a shared internal helper on all paths; trusted callback validates msg.sender and token; two-step owner transfer with both steps guarded; role admin disjoint from role holders.

example PoC: none yet.

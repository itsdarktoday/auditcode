# upgradeability (evm)

root cause: upgrade machinery trusts initialization, storage layout, and code assumptions that break across proxy/implementation/beacon/facet boundaries — the init is taken over, storage collides, or the upgrade path self-bricks.

protocol type: proxies (transparent/UUPS/beacon), diamonds, clones/factories (ERC-1167, CREATE2), EIP-7702 delegations.

affected architecture: initialize()/reinitializer flows, storage-layout chains with __gap, upgrade/admin functions, facet cuts, clone deploy+init sequences.

attack preconditions: uninitialized implementation reachable; front-runnable deploy→init gap; predictable CREATE2 salt; setter-mutable implementation slot; storage offsets reused across versions/facets.

invariant violated: storage layout stable across all versions with each slot written only by its declared owner; initialization runs exactly once by the intended caller; upgrade authority fixed; the proxy always resolves to executable code.

exploit pattern:
- storage-collision: proxy variable overlaps an implementation slot (esp. slot 0 vs _implementation); __gap missing/shrunk shifts child storage; diamond facets share non-namespaced slots; EIP-7702 redelegation between contracts using the same slots; immutables read through delegatecall return 0.
- beacon-issue: beacon/implementation pair out of sync — facet cut misses modified selectors or registration, non-standard diamond breaks introspection, function added to implementation but absent from proxy ABI (interface mismatch, missing forwarding).
- uups-auth: _authorizeUpgrade missing/unprotected → anyone upgrades to a selfdestructing implementation; new implementation lacking upgradeTo bricks the proxy permanently; upgrades not behind timelock/multisig.
- init-patterns: initialize() without initializer guard; missing _disableInitializers() in implementation constructor; unprotected versioned reinitializer on upgrade; missing parent __init call; uninitialized critical dependency → DoS; nested initializer modifiers block execution.
- migration-risks: constructor-set config invisible through the proxy; EIP-712 domain lacking verifyingContract → old-implementation signatures remain valid; implementation destroyed/unset → delegatecall silently succeeds (no extcodesize check); proxy-vs-implementation selector clash.
- create2-clone: predictable/user-controlled salt → address pre-funding or front-run deployment of a malicious clone; non-atomic clone deploy+init gap; initcode-hash mismatch for address prediction; stale factory config propagating to children.

detection strategy: read implementation constructors for _disableInitializers; diff storage layouts across versions (forge storage-layout / slither-check-upgradeability); enumerate proxy public functions for selector clashes; grep upgradeTo/_authorizeUpgrade for modifiers; check initialize() for external calls (init reentrancy) and reinitializer versioning; trace CREATE2 salt derivation (msg.sender+nonce vs user input).

false-positive indicators: ERC-1967/EIP-7201 namespaced slots with __gap in every inheritance level; deploy+init atomic or initializer gated by onlyOwner; salt includes msg.sender and a unique nonce; verifyingContract in the EIP-712 domain; UUPSUpgradeable inherited by every new implementation.

example PoC: none yet.

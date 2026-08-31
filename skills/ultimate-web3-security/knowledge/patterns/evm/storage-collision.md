# storage-collision (evm)

root cause: two contracts (implementation + proxy, or two implementation versions) declare storage at the same slot with different meaning.
protocol type: upgradeable protocols
affected architecture: Transparent/UUPS/Beacon proxies, inheritable base contracts, libraries with storage, contracts with storage gaps.
attack preconditions: an upgrade that reorders/renames/adds state variables; missing storage gaps in base contracts; inheritance chains where a base and child both declare storage.
invariant violated: "each storage slot has exactly one meaning across all versions".
exploit pattern: upgrade swaps implementation → old slot now read/written as a different type (owner address read as balance, admin overwritten by an unrelated write) → privilege escalation or fund theft. Variants: proxy storage clobbered by implementation variables at slots 0..n (pre-ERC-7201); missing gap breaks later upgrades; `delegatecall` to user-supplied address.
detection strategy: slot-map the inheritance chain (Slither `--print variable-order` / `slither-read-storage`); diff slot layouts between deployed implementation and new one; check namespaced storage (ERC-7201) and storage gaps.
false-positive indicators: ERC-7201 namespaced storage used consistently; storage gaps present in all base contracts; layout verified identical via upgrade check tooling; immutable (non-upgradeable) deployment.
example PoC: none yet.

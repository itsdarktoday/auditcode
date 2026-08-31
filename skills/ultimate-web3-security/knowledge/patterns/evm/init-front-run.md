# init-front-run (evm)

root cause: initialization is callable by anyone, or callable twice, or missing on the deployed logic contract.
protocol type: upgradeable protocols, clones/factories
affected architecture: `initialize` functions, proxy deployments where the logic contract itself is uninitialized, factories deploying children.
attack preconditions: uninitialized state observable on-chain (proxy or implementation) and an initializer without proper guards.
invariant violated: "initialization runs exactly once, by the intended party, before any user action".
exploit pattern: (a) attacker front-runs the deployer's `initialize` tx and becomes owner/admin; (b) attacker calls `initialize` on the logic contract directly (uninitialized implementation) — corrupts/claims admin; (c) double initialization resets critical params; (d) clone children initialized with attacker args.
detection strategy: for every initializer: `initializer`/`reinitializer` modifier present? constructor calls `_disableInitializers()`? deployed logic contract uninitialized (check via RPC/etherscan read)? factory passes attacker-controlled args?
false-positive indicators: `_disableInitializers()` in constructor AND initializer modifier; initialization in the same tx as deployment (CREATE2 factory + atomic deploy); verified deployer tx order (init before any user tx).
example PoC: none yet.

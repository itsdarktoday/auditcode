# signature-replay (evm)

root cause: a signed message is accepted in a context the signer didn't authorize (other chain, other contract, other time, other order).
protocol type: any protocol with permits, meta-tx, off-chain orders, governance votes, bridge messages
affected architecture: EIP-712 domains, `ecrecover` flows, nonce/deadline handling, order hash construction.
attack preconditions: a domain element missing or wrong (chainId, verifyingContract, typehash), or a nonce space too small/reusable, or order fields ambiguous (colliding encodings).
invariant violated: "a signature authorizes exactly one action in exactly one context".
exploit pattern: (a) missing chainId → signature replays on a sibling chain (fork, L2); (b) wrong typehash/domain → cross-protocol reuse (drain via another contract's verify); (c) permit + fee-on-transfer: signer approves X, attacker executes where X−fee arrives → signer loses X but gets less; (d) order hash ambiguity (two different orders, same hash) → wrong order filled; (e) missing deadline → stale-signature replay after conditions change.
detection strategy: for each signed message: enumerate domain fields and verify chainId + verifyingContract + version + typehash against the struct; check nonce consumption and deadline enforcement; test hash collisions for packed encodings.
false-positive indicators: full domain (chainId, verifyingContract, typehash) + nonce + deadline all enforced; signature consumed in-storage (one-shot); domain separator computed via EIP-712 standard library.
example PoC: none yet.

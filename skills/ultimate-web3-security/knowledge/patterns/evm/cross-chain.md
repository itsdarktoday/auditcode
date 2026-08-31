# cross-chain (evm)

root cause: source-chain trust, message uniqueness, and destination conditions assumed rather than enforced — messages replay, sources spoof, or destination execution fails without a recovery path.

protocol type: bridges (lock-mint, burn-unlock, liquidity-network), LayerZero/CCIP/Wormhole/Axelar/Hyperlane integrations, custom relayer/validator systems.

affected architecture: send/execute pairs, trustedRemote/endpoint configs, nonce/processed-message ledgers, mint authority on wrapped tokens, validator multisigs, refund paths.

attack preconditions: message lacking (chainId, nonce) uniqueness; destination accepting unverified senders; finality shallower than the source chain's reorg depth; relayer able to under-gas; mint functions unprotected.

invariant violated: each source-chain event executes at most once on the intended chain with the sender verified; destination minted == source locked; failed delivery returns value to the user.

exploit pattern:
- replay-same-chain: missing processedMessages[hash] or a global nonce → same message re-executed; ECDSA malleability (raw ecrecover) bypasses hash-based dedup.
- replay-cross-chain: signature/UserOperation domain lacking chainId (or wildcard chainId==0 in EIP-7702 authorizations) → replay on another chain; chain-specific vs global nonce mismatch.
- ordering-finality: insufficient confirmations (1 block on fast chains) → source reorg reverts the lock while destination mint stands; source/destination state diverge under partial failures.
- trusted-source-spoof: trustedRemote unset or wrong for a chain → attacker deploys a fake source; missing sender verification on destination; callback/execute accepts anyone as relayer.
- chainid-mismatch: wrong chain ids in endpoint configs or refund addresses; abi.encodePacked hash collisions across senders+amounts when nonce is global (PACKED-01).
- token-mapping: minted > locked (infinite mint); wrapped-token setRouter/setMinter without auth; cross-chain decimals unnormalized (USDC 6 vs 18); canonical-vs-synthetic mapping confusion.
- gas-liquidity: minDstGas unset → message arrives but OOGs; destination assumes WETH/token balance present (empty pool bricks the swap); refund routed to the adapter instead of the user; 63/64 under-gassed relay burns the nonce anyway.
- rate-limit-griefing: global (not per-user) rate limits fillable by self-transfers; missing circuit breaker lets a single exploit drain the whole bridge.

detection strategy: enumerate every message struct → check (sourceChain, nonce, sender) tuple and processed ledger; verify sender against trustedRemote/endpoint for all chains; check confirmation count per source chain; grep setRouter/setMinter/setBridge for modifiers; trace full refund paths; check adapterParams/options minDstGas. Tools: manual tuple-completeness check, grep keccak256(abi.encodePacked) in message hashes, Slither for unprotected mint.

false-positive indicators: per-chain nonces + processedMessages with malleability-safe ECDSA; finality ≥ reorg threshold of the source chain; trustedRemotes set for all chains by governance; mint authority == bridge only with supply caps; refunds reach the source user; per-user rate limits.

example PoC: none yet.

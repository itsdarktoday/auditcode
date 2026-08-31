# Post-Mortem: Nomad Bridge (90M Exploit)

- **Date:** August 1, 2022
- **Protocol Archetype:** Cross-Chain Bridge
- **Root Cause Category:** Uninitialized Zero-Value Root Bypass
- **Target Invariant Broken:**  (Bridge Message Authentication & Authorization)

## 1. Vulnerability Mechanics
Nomad's  contract processed cross-chain messages based on Merkle tree root confirmations.
During a routine upgrade, the Nomad team initialized the  mapping for the default value  with a non-zero timestamp.
Because , any message whose calculated root was  was automatically treated as **valid and confirmed by governance**.

## 2. Attack Walkthrough
1. Attacker constructed a bridge withdrawal message claiming 100 WBTC with invalid/dummy proof data that resolved to root .
2. The contract checked , passed validation, and minted WBTC to the attacker.
3. Hundreds of copycat searchers replayed the same transaction with their own recipient address, draining 90M in hours.

## 3. Key Takeaways & Defense Matrix
- **Rule:** Never allow default/uninitialized values (, ) to represent valid confirmed states.

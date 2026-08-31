# Post-Mortem: KyberSwap Elastic (7M Exploit)

- **Date:** November 22, 2023
- **Protocol Archetype:** AMM / Concentrated Liquidity
- **Root Cause Category:** Precision Rounding & Tick Boundary Double-Counting
- **Target Invariant Broken:**  (Conservation of Value in Swaps) &  (Monotonic AMM Reserves)

## 1. Vulnerability Mechanics
KyberSwap Elastic attempted to optimize Uniswap v3 concentrated liquidity calculations by re-computing liquidity and active fees during tick crossings.
During a specific swap sequence that crosses a tick boundary without exhausting the entire tick's liquidity, the contract calculated:
1. Re-computed the current tick's liquidity delta.
2. Added the delta twice while updating pool reserves.
3. Due to an inverted rounding direction in , the pool calculated that infinite liquidity was available at a distorted price.

## 2. Attack Walkthrough
1. Attacker flash-borrows funds and creates an artificial concentrated liquidity position in an empty price tick range.
2. Attacker swaps back and forth across the exact boundary tick.
3. The double-counted liquidity and rounding error caused KyberSwap's internal accounting to record that the pool owed the attacker millions of tokens for virtually zero input.
4. Attacker drained all collateral reserves across Ethereum, Arbitrum, Optimism, Polygon, and Avalanche.

## 3. Key Takeaways & Defense Matrix
- **Rule:** Never re-compute aggregate liquidity deltas mid-swap when crossing ticks; enforce strictly monotonic invariant $.
- **Fuzz Property:** Stateful invariant testing flipping ticks 1,000 times must yield non-increasing pool surplus.

---
name: oracle_manipulation
description: Guide to Price Oracle Manipulation and Flash Loan Attacks
tags: ["vuln", "oracle", "defi"]
---

# Price Oracle Manipulation & Flash Loan Attacks

### 1. Spot Price Reliance
- **Vulnerability**: Relying on instant AMM reserves (`pair.getReserves()` in Uniswap V2, `slot0().sqrtPriceX96` in Uniswap V3).
- **Exploit**:
  1. Flash loan 50,000,000 USDC.
  2. Swap massive volume on AMM to drastically skew spot exchange rate.
  3. Call victim protocol function (mint, borrow, liquidate) at manipulated price.
  4. Swap back on AMM to restore liquidity and repay flash loan with multi-million profit.
- **Remediation**: Use multi-block Time-Weighted Average Price (TWAP) or decentralized off-chain oracles (Chainlink) with sanity bounds.

### 2. Chainlink Oracle Pitfalls
- **Staleness**: Always check `updatedAt > 0 && block.timestamp - updatedAt <= HEARTBEAT_PERIOD`.
- **Round ID**: Check `answeredInRound >= roundId`.
- **Min/Max Answers**: Check returned price `price > minAnswer && price < maxAnswer` to avoid using hardcoded floor during asset collapses (e.g., LUNA).
- **L2 Sequencer Feed**: On Arbitrum, Optimism, Base, check the Chainlink Sequencer Uptime Feed before accepting oracle data.

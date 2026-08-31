# Post-Mortem: Radiant Capital (.5M Exploit)

- **Date:** January 3, 2024
- **Protocol Archetype:** Lending / Compound v2 Fork
- **Root Cause Category:** Empty Market Precision Loss & Share Inflation
- **Target Invariant Broken:**  (Rounding Direction & Precision Conservation)

## 1. Vulnerability Mechanics
Radiant deployed a brand new native USDC market on Arbitrum.
In Compound v2 forks, when a market is newly initialized, .
The exchange rate formula is:
1318	ext{ExchangeRate} = rac{	ext{TotalCash} + 	ext{TotalBorrows} - 	ext{TotalReserves}}{	ext{TotalSupply}}1318
When  is 0, the initial rate defaults to .
The attacker exploited a 1-wei deposit rounding bug compounded by the difference between 6-decimal USDC and 18-decimal internal math.

## 2. Attack Walkthrough
1. Attacker deposits 1 wei into the new USDC market, minting 1 share ().
2. Attacker executes a flash loan and directly transfers M USDC to the contract (donation), inflating the exchange rate to  	imes 10^{24}$.
3. Due to integer truncation, subsequent borrows against inflated collateral drained remaining market liquidity.

## 3. Key Takeaways & Defense Matrix
- **Rule:** Never allow first depositors to control exchange rate ratios; enforce  burn to address(0) or virtual decimals offset.

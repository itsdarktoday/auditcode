# Real-World DeFi Exploit Post-Mortem Database

Searchable index mapping code triggers and vulnerability classes to landmark historical Web3 exploits.

| Exploit Name | Loss | Vector / Archetype | Root Cause & Invariant Violation | Reference File |
|---|---|---|---|---|
| **Euler Finance** | 97M | Lending / Donation | `donateToReserves` failed to verify health factor, burning eTokens without reducing borrow debt (`INV-01`) | `euler-finance.md` |
| **KyberSwap Elastic** | 7M | AMM / Concentrated Liquidity | Double counting liquidity when swapping across ticks + rounding direction error (`INV-03`) | `kyberswap-elastic.md` |
| **Curve Finance** | 0M | DEX / Reentrancy | Vyper compiler reentrancy lock failure allowing read-only reentrancy during LP valuation (`INV-02`) | `curve-vyper-reentrancy.md` |
| **Platypus Finance** | .5M | Stableswap / MasterChef | Emergency withdrawal condition short-circuited solvency checks (`INV-01`) | `platypus-finance.md` |
| **Radiant Capital** | .5M | Lending / Share Inflation | Empty market precision loss in `cToken` exchange rate rounding (`INV-03`) | `radiant-capital.md` |
| **Nomad Bridge** | 90M | Cross-Chain / Bridge | Default uninitialized root `0x00` accepted all message proofs as confirmed (`INV-08`) | `nomad-bridge.md` |
| **Wormhole Bridge** | 20M | Bridge / Signature | Deprecated `verify_signatures` instruction bypassed guardian set check (`INV-08`) | `wormhole-bridge.md` |
| **Mango Markets** | 14M | Perps / Oracle Manipulation | Skewing illiquid spot oracle to artificially inflate unrealized PnL and borrow against it (`INV-05`) | `mango-markets.md` |
| **Hundred Finance** | M | Lending / ERC-777 | ERC-777 `tokensToSend` hook reentrancy before borrow balance update in Compound v2 fork (`INV-02`) | `hundred-finance.md` |

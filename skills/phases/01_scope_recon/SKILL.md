---
name: 01_scope_recon
description: Smart Contract Scope & Architecture Discovery Phase Checklist
tags: ["scope_recon", "recon"]
---

# Scope & Architecture Reconnaissance Checklist

1. **Framework & Environment Detection**:
   - Detect project framework: Foundry (`foundry.toml`), Hardhat (`hardhat.config.js/ts`), Anchor (`Anchor.toml`), Truffle, or Ape.
   - Run compilation check: `forge build` or `npx hardhat compile`.
   - Record compiler version and optimizer runs in `state_update update_scope`.

2. **In-Scope Contracts Discovery**:
   - Locate all primary contracts in `src/`, `contracts/`, or `programs/`.
   - Exclude mock, test, and third-party library files (`test/`, `mock/`, `lib/`, `node_modules/`).
   - Run `contract_inspect` on every in-scope contract to parse AST, calculate SLOC, and extract public functions.

3. **Topology & Inheritance Mapping**:
   - Identify base contracts, abstract contracts, and interfaces.
   - Determine proxy patterns (UUPS, Transparent, Diamond, Beacon, Minimal Proxy).

4. **External Integrations**:
   - Identify third-party dependencies: Uniswap V2/V3, Aave, Chainlink, LayerZero, Wormhole, Pyth.
   - Note integrated token standards: ERC20, ERC721, ERC1155, ERC4626.

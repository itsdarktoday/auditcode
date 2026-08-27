---
name: signatures
description: Vulnerability analysis guide for cryptographic signatures, EIP-712, ECDSA malleability, replay attacks, and permit vulnerabilities in smart contracts.
---

# Cryptographic Signatures & Permit Security Guide

## Common Vulnerabilities

### 1. Signature Replay Across Chains / Contracts
- **Issue**: Signature does not bind `block.chainid` or the contract address (`address(this)`).
- **Impact**: Signature valid on Ethereum can be replayed on Arbitrum, Polygon, or another instance of the protocol.
- **Fix**: Use EIP-712 typed data hashing with `DOMAIN_SEPARATOR` containing `chainId` and `verifyingContract`. Recompute separator if `block.chainid` changes (hard forks).

### 2. Missing Nonce or Replay on Same Contract
- **Issue**: Signature can be submitted multiple times because nonces are not tracked or invalidated.
- **Impact**: Fund drain via duplicate signature submission.
- **Fix**: Increment a user nonce (`mapping(address => uint256) public nonces`) upon every signature consumption.

### 3. ECDSA Signature Malleability
- **Issue**: Standard `ecrecover` accepts malleable `s` values (`s > secp256k1n / 2`) and arbitrary `v` (27/28).
- **Impact**: An attacker can invert `s` to create a valid alternate signature for the same payload and bypass signature-hash based duplicate checks.
- **Fix**: Use OpenZeppelin's `ECDSA.recover` which enforces `s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D57611027BB4925A184417A762E9741`.

### 4. Zero Address Recovery (`ecrecover` returning `address(0)`)
- **Issue**: `ecrecover` returns `address(0)` on malformed signatures. If an uninitialized signer variable is `address(0)`, the check `require(signer == authorizedSigner)` passes.
- **Fix**: Enforce `require(signer != address(0), "Invalid signature")`.

### 5. ERC-2612 / Permit Front-Running & Griefing
- **Issue**: `permit()` can be front-run by anyone extracting `(v, r, s)` from the mempool.
- **Impact**: When the original caller executes a multicall or combined `permit` + `deposit`, the second call reverts because the permit nonce was already consumed.
- **Fix**: In wrapper functions, use a `try/catch` around `permit()` or check allowance before calling `permit()`.

### 6. Compact Signatures (EIP-2098) & Smart Contract Wallets (ERC-1271)
- **Issue**: Contract wallets (Gnosis Safe, Argent) do not have ECDSA private keys and fail standard `ecrecover`.
- **Fix**: Support ERC-1271 `isValidSignature(bytes32 hash, bytes signature)` using OpenZeppelin's `SignatureChecker`.

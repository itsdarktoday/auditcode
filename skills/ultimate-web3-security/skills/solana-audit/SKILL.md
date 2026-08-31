---
name: solana-audit
description: Solana/Rust (Anchor + Native) deep-analysis sub-skill for the ultimate-web3-security pipeline. Loaded when auditing Solana programs.
---

# Solana Deep Audit (Anchor & Native Rust)

Loaded when auditing Solana programs. Extends the core pipeline with SVM-specific account validation, CPI lifecycle, and Token-2022 extension models.

## 1. SVM Threat Model & Account Architecture

- **Stateless Code & External Account State:** Solana programs own NO internal storage; all state lives in externally passed `AccountInfo` structs. Every instruction parameter is an untrusted account until proven otherwise.
- **Arbitrary Account Substitution:** An attacker can pass ANY arbitrary account (attacker-owned token account, malicious program, fake sysvar) into any instruction argument.
- **Account Aliasing (Duplicate Mutable Accounts):** The SAME mutable account passed into two different parameters (e.g. `source == destination`) can cause double-credits or overwritten checks.

## 2. The Nine Critical Solana Vulnerability Vectors

### 1. Account Ownership & Type Discrimination
- Every program-owned account MUST verify `account.owner == program_id` (Anchor: `Account<'info, T>` enforces this; raw `AccountInfo` does NOT).
- Verify 8-byte Anchor discriminator or enum discriminator on all custom data structs to prevent account type confusion.

### 2. Signer & Authority Validation
- Every privileged action (withdrawal, parameter setter, position close) MUST check `account.is_signer == true` (`Signer<'info>` in Anchor).

### 3. PDA Derivation & Bump Seed Canonicalization
- Every PDA must validate all seeds against expected inputs.
- **Canonical Bump Check:** Always use `find_program_address` or validate that the stored bump matches the canonical bump to prevent PDA hijacking via non-canonical bumps.

### 4. Duplicate Mutable Account Aliasing
- When an instruction takes two mutable accounts of the same type (e.g. `transfer(from, to, amount)`), explicitly enforce `require_keys_neq!(ctx.accounts.from.key(), ctx.accounts.to.key())`.

### 5. `remaining_accounts` Untrusted Iteration
- Dynamic account lists passed via `remaining_accounts` have unchecked length and unverified owners. Explicitly validate owner, discriminator, and signer status on every item during iteration.

### 6. Stale Account Data Post-CPI (`reload()` Missing)
- Calling a CPI that modifies an account (e.g. SPL Token transfer or lending pool deposit) mutates the on-chain account data, but leaves the local memory struct unchanged.
- **THE Classic Solana Bug:** Forgetting to call `account.reload()?` before performing subsequent balance or invariant checks.

### 7. Closing Accounts & Lamport Drain / Reinitialization
- When closing an account: (1) zero out all account data (`**account.to_account_info().try_borrow_mut_data()? = &mut []`), (2) set discriminator to a dedicated `CLOSED_ACCOUNT_DISCRIMINATOR`, (3) transfer all lamports to the destination.
- Ensure an account closed in transaction $N$ cannot be revived/re-initialized in transaction $N+1$ with stale state.

### 8. Token-2022 & Transfer Extensions (Modern SVM)
- **Transfer Hooks:** Token-2022 transfer hooks invoke an external program on EVERY transfer $\rightarrow$ Potential reentrancy / CPI recursion into the calling program.
- **Transfer Fees:** `transfer_checked` amount differs from received amount due to withholding fees. All balance assertions MUST calculate `actual_received = amount - fee`.
- **Permanent Delegate & Freeze Authorities:** Malicious or privileged mints can freeze balances or seize tokens without holder signature.

### 9. Zero-Copy & Memory Safety
- `AccountLoader<'info, T>` with `#[account(zero_copy)]`: Ensure memory alignment and that uninitialized padding bytes do not leak confidential data or allow unaligned pointer panics.

## 3. Tooling & Verification

- `cargo check` / `cargo clippy` for compilation sanity.
- Anchor IDL diff against deployed program bytecode (`solana program dump`).
- Trident Invariant Fuzzing (`trident fuzz run`).


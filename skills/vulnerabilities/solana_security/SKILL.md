---
name: solana_security
description: Guide to Solana Program & Anchor Security Auditing
tags: ["vuln", "solana", "anchor"]
---

# Solana & Anchor Program Security

### 1. Missing Signer & Owner Validation
- Ensure accounts authorizing transfers are defined as `Signer<'info>` instead of `AccountInfo<'info>`.
- Verify account ownership against the expected program ID (`account.owner == &expected_program_id`).

### 2. PDA Bump Seed Derivation
- Always store and validate canonical bump seed (`bump = account.bump` in Anchor context).
- Avoid user-controlled arbitrary seeds without length delimiters to prevent PDA collision attacks.

### 3. Duplicate Mutable Accounts
- Check that source and destination accounts are distinct (`require_keys_neq!(ctx.accounts.from.key(), ctx.accounts.to.key())`).

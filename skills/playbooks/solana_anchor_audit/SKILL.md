---
name: solana_anchor_audit
description: Comprehensive playbook for auditing Solana Anchor Programs
tags: ["playbook", "solana", "anchor"]
---

# Solana Anchor Program Audit Playbook

1. **Account Constraints & Contexts**:
   - Verify `#[account(...)]` macros on all accounts in instruction contexts.
   - Check `has_one = ...` constraints for ownership relations.

2. **Cross-Program Invocation (CPI)**:
   - Check signer seeds for CPI calls using `invoke_signed`.
   - Verify target program ID matches expected system or token program.

3. **Token Account Handling**:
   - Verify mint matches expected SPL token mint.
   - Ensure SPL token transfers use associated token accounts (ATA).

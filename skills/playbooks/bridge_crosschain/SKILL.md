---
name: bridge_crosschain
description: Comprehensive playbook for auditing Cross-Chain Bridges & Messaging Protocols
tags: ["playbook", "bridge", "crosschain"]
---

# Cross-Chain Bridge Audit Playbook

1. **Message Verification & Proofs**:
   - Verify Merkle proof / light client header validation.
   - Check threshold signature scheme (TSS) and validator set rotation rules.

2. **Replay & Double-Spend Defenses**:
   - Ensure message nonces and source chain IDs are hashed into unique message identifiers.
   - Verify that processed messages are marked before external execution (CEI).

3. **Fee & Token Custody**:
   - Check native token wrapping and unwrapping balances.
   - Ensure paused state on bridge prevents relaying on destination chain.

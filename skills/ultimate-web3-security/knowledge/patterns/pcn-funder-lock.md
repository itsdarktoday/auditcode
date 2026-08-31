# Pattern: compute-before-move finalize reverts permanently lock user SOL

- Protocol: pcn-program (Solana/Anchor) — epoch-based reward emissions
- Date: 2026-08-14

## Pattern
A funding instruction commits user funds into a program-owned account (`open_epoch` transfers `support_budget_lamports` into the Epoch PDA). The only outflow instruction (`finalize_epoch`) runs a fallible computation (`compute_reward_pool`, requires strict `lifetime < max_supply` and `reward_pool > 0`) BEFORE any lamport move. Any revert rolls back the refund path. The program has no close/cancel/refund instruction, so the account is a trap.

## Why it's critical
The trigger state (`lifetime == max_supply`) is the DETERMINISTIC endpoint of normal operation: each successful finalize strictly grows lifetime (pool is capped by remaining supply, so the last epoch lands exactly on max_supply). No privileged misbehavior needed → permissionless funders lose 100% of deposits and the protocol permanently bricks. Admin-legal configs (>= vs strict < on supply; unbounded target that zeroes the support cap) are reachability amplifiers.

## Detection heuristics
1. For every instruction that moves funds in: enumerate ALL paths out; if exactly one exit and it is fallible, the funding instruction is a lock.
2. Check order: fallible computation → then lamport moves. Any revert = user funds stuck.
3. Compare guard strictness across instructions: `update_config` uses `>=` where the hot path requires strict `<`.
4. Track supply/emission accumulation invariants: finite supply + strictly growing counter = terminal state is reachable.
5. Solana-specific: lamports in a program-owned account can only be moved by the program; token paths don't move lamports.

## PoC approach
LiteSVM: loop normal open+finalize until the terminal counter state, deposit fresh funder, attempt finalize (expect revert), probe every other instruction (expect gated failures), advance clock arbitrarily, assert epoch status/lamports/funder balance unchanged.

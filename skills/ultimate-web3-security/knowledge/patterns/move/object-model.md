# object-model (move)

root cause: the object-centric storage model (Sui) and global-storage model (Aptos) are misused: ownership classes (owned/shared/immutable/wrapped), UID/ID identity, dynamic fields, and clock/epoch semantics are treated as interchangeable when they are not.

protocol type: Sui Move protocols with objects/shared state; Aptos global-storage protocols

affected architecture: shared objects mutated by entry functions, dynamic fields attached to deleted/retained objects, `ID` vs `address` identities, Clock/epoch-based time and randomness, hot-potato/wrapped objects, periodic accounting checkpoints.

attack preconditions: a shared object is mutated without a permission check; dynamic fields are addable by any caller; code uses `epoch_timestamp_ms`/`epoch`/`digest` as current time or entropy; `object::delete` runs while dynamic fields are attached; `address`→`ID` conversions without existence validation; aborting arithmetic sits before a checkpoint write.

invariant violated: "object ownership, identity, and time semantics match developer intent: no mutation of shared objects without a capability, no orphaned or injectable state, no stale time values, and every accounting checkpoint advances."

exploit pattern: (concrete variants, one line each)
- shared object accepts `&mut T` without a caller permission/capability check → anyone manipulates protocol state (SUI-01)
- shared object mutated in PTB step A and read in step B before invariants are restored → mid-PTB inconsistent-state exploit (SUI-02)
- anyone can `dynamic_field::add` to a shared object → attacker injects fake balances/slots the logic trusts (SUI-06)
- `object::delete(uid)` with dynamic fields still attached → child values/balances orphaned and locked forever (SUI-25)
- `epoch_timestamp_ms()` used as current time → up-to-24h-stale values in expiry/price/lock logic (SUI-07)
- `epoch()`/`digest()`/object ID bytes used as randomness → deterministic, validator-influenceable seeds (SUI-43)
- `ID` vs `address` confusion (`id_from_address` without account existence check) → valid messages permanently unclaimable (SUI-33, DEFI-10)
- periodic accumulator update writes its checkpoint after aborting arithmetic → delta grows each retry, function permanently uncallable (common-move 12.1)
- `table::add` without `contains` check → duplicate-key abort DoS on a second deposit/interaction (SUI-14)
- hot potato dropped mid-transaction or created-then-aborted → funds lost / inconsistent receipts (SUI-09, SUI-17)

detection strategy: (code shapes/triggers/tools)
- grep `transfer::share_object|public_share_object` → build the SHARED list; for each type check every `&T`/`&mut T` entry for a capability gate (SUI-01 ritual)
- grep `dynamic_field::add|remove` → permissioning of adds; cleanup of all dynamic fields before any `object::delete`
- grep `epoch_timestamp_ms|tx_context::epoch|tx_context::digest` → flag as time/randomness misuse; require `sui::clock::Clock` for current time
- grep `id_from_address|object::id` conversions → require existence/type validation against a registry
- for each `last_update|last_checkpoint|cumulative_index` write: check it executes before any aborting arithmetic (common-move 12.1)
- build/test: `sui move test`, `aptos move test`; coverage on modules owning shared objects

false-positive indicators: shared objects gated by admin/user caps; `clock::timestamp_ms(clock)` used instead of epoch time; dynamic fields all permissioned and removed before delete; ID conversions validated against a registry; checkpoint written before risky math.

example PoC: none yet.

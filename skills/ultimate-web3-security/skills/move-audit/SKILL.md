---
name: move-audit
description: Sui & Aptos Move deep-analysis sub-skill for the ultimate-web3-security pipeline. Loaded when auditing Move packages.
---

# Move Deep Audit (Sui & Aptos)

Loaded when auditing Move packages. Models Move's object-centric storage model, capability authorization, and Programmable Transaction Blocks (PTB).

## 1. Move Threat Model & Object Storage Architecture

- **Object Ownership vs Shared Objects:** State is either owned by an address or shared among all users (`transfer::share_object`). Shared objects are susceptible to race conditions and atomic sandwiching.
- **Programmable Transaction Blocks (PTB):** Up to 1,024 commands batched in ONE atomic transaction. Intermediate outputs of command $N$ feed command $N+1$. Functions cannot assume they execute in isolation.
- **Linear Type System & Capabilities:** Authorization is granted by passing an un-copyable capability struct (`&AdminCap`), not address matching.

## 2. Seven Critical Move Vulnerability Vectors

### 1. Capability Leakage & `store` Ability Trap
- **The #1 Move Bug:** Assigning the `store` ability to an administrative capability struct (e.g. `struct AdminCap has key, store`).
- A struct with `store` can be wrapped into another public object or transferred via `transfer::public_transfer`, leaking admin control. Privileged capabilities MUST have ONLY `key` (no `store`, no `copy`, no `drop`).

### 2. PTB Multi-Call Invariant Bypass
- Functions designed assuming single invocation per transaction can be called repeatedly within a single PTB (e.g. `deposit()` $\rightarrow$ `flash_borrow()` $\rightarrow$ `claim_reward()` $\rightarrow$ `withdraw()`).
- Invariants must hold atomically across every intermediate PTB step.

### 3. Dynamic Field Type Confusion & Exhaustion
- Dynamic fields (`dynamic_field::add`, `dynamic_object_field`) keyed by attacker-controlled inputs can overwrite existing keys or collide with internal types.
- Inserting thousands of dynamic fields can hit Sui's `max_move_object_size` or execution gas budget, permanently bricking object access.

### 4. Stale Package Version Post-Upgrade
- On Sui, when package $V1$ upgrades to $V2$, the $V1$ package bytecode **remains permanently callable on-chain**.
- If objects created in $V1$ can still be passed into $V1$ public functions, an attacker can bypass newly introduced $V2$ security patches by directly invoking $V1$ package ID entry points.
- **Mitigation:** Protocol MUST enforce a `Version` struct check (`require(config.version == CURRENT_VERSION)`) on all shared objects.

### 5. Check-vs-Settlement Asymmetry (DeFi Timing)
- Reading prices or balances in command 1 and executing settlement in command 3 of a PTB allows intervening commands to distort state before settlement occurs.

### 6. Abort-Before-Checkpoint Incomplete Rollbacks
- Multi-object interactions where one shared object's state updates and an abort occurs before transaction checkpointing. Ensure clean abort semantics across all branches.

### 7. Balance Splitting & Coin Dust Rounding
- Sui `Coin<T>` / `Balance<T>` math: Splitting balances (`coin::split`) with integer rounding. Rounding in fee splits must strictly favor the protocol balance.

## 3. Tooling & Verification

- `sui move test` / `aptos move test` for local regression execution.
- SUIZERO Move bytecode scanner.
- On-chain object state inspection via `sui client object <OBJECT_ID>`.


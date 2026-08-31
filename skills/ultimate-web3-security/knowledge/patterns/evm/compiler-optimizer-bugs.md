# Solidity Compiler & Yul Optimizer Hazards

The Solidity compiler optimizer (`via-ir`, Yul IR pipeline) and specific compiler versions have known code generation bugs and de-optimization hazards.

---

## 1. Yul Optimizer Memory-Safe Assembly Clobbering
- When `via_ir = true` is enabled, the Yul IR optimizer assumes that all inline assembly blocks are **memory-safe** unless specified otherwise.
- If an inline assembly block writes to arbitrary memory without allocating via the free-memory pointer (`0x40`) and is NOT annotated with `assembly ("memory-safe")`, the optimizer may **reorder or eliminate memory writes**, resulting in silent state corruption.
- *Fix:* Ensure all assembly blocks use `assembly ("memory-safe") { ... }` or disable `via_ir` if raw memory pointers are manipulated.

---

## 2. Dirty Bytes Array to Storage Bug (Solidity 0.8.15)
- Copying a `bytes` or `string` array from `calldata` or `memory` to `storage` in Solidity 0.8.15 fails to clean up dirty bytes in the last 32-byte storage slot, leaving residual memory garbage in storage.
- *Fix:* Upgrade compiler to Solidity $\ge 0.8.16$.

---

## 3. Inline Assembly Storage Pointer De-referencing
- In versions $\le 0.8.14$, nested storage pointer declarations in assembly could lead to incorrect slot offset calculations.

---

## 4. `via_ir` Legacy Stack Reordering Pitfall
- In complex contracts with $> 16$ local variables, `via_ir` reorders stack slots to prevent "Stack Too Deep" errors.
- In rare boundary conditions with high optimization runs (`runs: 1000000`), evaluation order of function arguments can change, breaking non-standard evaluation order assumptions.

---
name: zk-audit
description: ZK Circuit (Circom / Halo2 / Noir) deep-analysis sub-skill for the ultimate-web3-security pipeline. Loaded when auditing ZK circuits and verifiers.
---

# Zero-Knowledge Circuit Audit (Circom / Halo2 / Noir)

Loaded when auditing ZK circuits or verifier contracts. Evaluates circuits against the three pillars: **Soundness**, **Completeness**, and **Privacy (Zero-Knowledge)**.

## 1. Declarative Doctrine

**Circom and R1CS are declarative constraint systems, not imperative programs.**
- There is NO control flow or execution sequence.
- The auditor's central question: **"What malicious witness assignments satisfy all constraints while violating intended business logic?"**
- Rule: `<==` and `===` enforce R1CS constraints; `<--` and `-->` ONLY compute hints for the witness generator. Every `<--` is an unconstrained hole until bound by a `===` constraint.

## 2. Six Critical ZK Vulnerability Vectors

### 1. Under-Constrained Signals & Missing Equality Constraints
- Computing an intermediate output with `<--` without adding a corresponding `===` constraint allows a malicious prover to assign arbitrary values to the output signal.

### 2. Finite Field Arithmetic & Modulo $p$ Aliasing
- Values in BN254/BLS12-381 live in $\mathbb{F}_p$.
- **Field Aliasing:** If a signal is supposed to represent a 254-bit number, the prover can submit $x$ or $x + p \pmod{2^{256}}$, creating dual valid proofs. Ensure `Num2Bits_strict` is used instead of `Num2Bits(254)`.

### 3. Unchecked Division by Zero & Witness Collapses
- In Circom, `out <-- a / b` with constraint `out * b === a`:
- If $b = 0$ and $a = 0$, the constraint collapses to $0 \times \text{out} === 0$, which is **satisfied for ANY arbitrary value of `out`**.
- Mitigation: Must enforce `IsZero(b).out === 0` before division.

### 4. Unconstrained Selector Muxes
- Multiplexer selectors (`s`) must be strictly constrained to binary values ($s \in \{0, 1\}$) via $s \times (s - 1) === 0$. If unconstrained, a prover can supply $s = 2$ and synthesize non-existent inputs.

### 5. Smart Contract Verifier Integration & Public Input Desync
- On-chain verifier wrapper contract:
  - Are all intended public inputs actually passed into `verifyProof()`?
  - Are public inputs truncated or packed incorrectly (e.g. big-endian vs little-endian field elements)?
  - Is proof replay prevented (e.g. nullifier hash stored on-chain before token transfer)?

### 6. Privacy & Information Leakage
- Do public inputs or verifier events expose entropy that reveals private witness preimages (e.g. unblinded commitment hashes)?

## 3. Tooling & Verification

- `circom` compilation & R1CS inspection via `snarkjs r1cs info`.
- `circomspect` static analyzer for unconstrained signal detection.
- Malicious witness generation: Constructing an alternate witness file that satisfies constraints is the definitive PoC for soundness bugs.


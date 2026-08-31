# soundness (zk)

root cause: the R1CS does not pin every signal the protocol's semantics assume — a malicious prover submits a witness that satisfies all constraints yet violates intent (forged membership/signatures/ranges, aliased values, disabled checks).

protocol type: circom/SNARK circuits (membership, identity, range proofs, signatures, nullifiers, hashing, encoding)

affected architecture: witness-only `<--` assignments, comparators and bit decompositions, EC/signature gadgets, mux/selector gates, accumulators, public inputs.

attack preconditions: any prover with access to valid public inputs (default malicious-prover threat model; no trusted party needed — judging.md Gate 3).

invariant violated: "constraint-system soundness: only witnesses meeting the protocol's semantics satisfy the R1CS."

exploit pattern: (concrete variants, one line each)
- `<--`-computed signal never pinned by `<==`/`===` → free variable the prover sets at will (V-A1)
- `signal output` declared but never assigned → any field element provable (V-A2)
- `out <-- num/div; out*div === num` with `div = 0` → collapses to `0 === 0`, `out` free (division/EC slope) (V-A3)
- XOR via `a + b − 2ab` without booleanity + recomposition → forged bits (V-A4)
- rotation/decomposition pinned by one linear identity in two free halves → arbitrary 33-bit output (V-A5)
- `LessThan(N)` operand not range-checked → `p − k` alias mis-classified by the comparator (V-B1)
- comparator instantiated but `.out` never consumed → dead check (V-B2)
- `Num2Bits(254)` over BN254 without `_strict` → prover picks `x` or `x + p` bits per goal (V-B3)
- multi-limb modular reduction with per-limb bounds but no `BigLessThan(r, p)` → `r + k·p` accepted (V-B4)
- `PackBytes`/`BytesToField` inputs not byte-range-checked → `[0,1,0]` and `[256,0,0]` pack identically (V-B5)
- tag-issuing template never enforces its own invariant → downstream consumers misled (V-B6)
- selector-as-enabler `flag * (a+b)` → `flag = 0` collapses the gated check to `0 === 0` (V-D1)
- Merkle-path selector not boolean → prover linearly interpolates to forge leaves (V-D2)
- array index via `LessThan(idx, n)` → out-of-range returns all-zero, accepted as default (V-D3)
- `assert(...)` used as a constraint → witness-generator-only check, malicious prover bypasses (V-D5)
- one-sided decoder (`out[i]*(inp−i) === 0` without IsZero pairing) → decoder accepts any input (V-D6)
- accumulator seeded with input data instead of the identity `1` → `element = 0` collapses membership (V-E1)
- per-key accumulator filtered by the wrong side's key → smuggled entries (V-E2)
- narrow accumulator overflows mod p → two distinct chunk vectors hash to one field element (V-C1)
- EC AddUnequal collapses on equal inputs / point-at-infinity (V-C3); scalar `s = 0` accepted into multiplication (V-C4)
- public input declared but never constrained → verifier accepts any value (V-H4)
- verifier gadget `enabled <== 0` → signature/equality check silently disabled (V-H5)
- `/` used for integer division (it is field-inverse) → `q*k + r === a` satisfied by the inverse witness (V-L1)

detection strategy: (code shapes/triggers/tools)
- grep `<--` → require a paired `<==`/`===` or an `IsZero(div).out === 0` guard per occurrence; grep `signal output` → require assignment
- grep `LessThan|LessEqThan|GreaterThan|GreaterEqThan` → trace each operand to a `Num2Bits(M ≤ N)` chain or comparator `.out`
- grep `Num2Bits(254)` → require `_strict`; grep `assert(` → require a mirroring constraint gadget (`ForceLessThan`, `IsZero(...).out === 0`, `===`)
- grep `Mux|MultiMux` → require `s * (s − 1) === 0` on the selector; grep accumulator seeds → must be the operation's identity
- verify every public input appears in at least one `===`/`<==` constraint (anti-`circom -O2` dummy use)
- Feynman-test each template: explain what it proves in plain words; where the explanation gets fuzzy, an unconstrained signal hides (senior-auditor-sop.md)
- validate findings through the 4 gates of judging.md: attack execution (trace every constraint on the witness path), reachability, trigger, impact

false-positive indicators: `<==` everywhere; `Num2Bits_strict`/`Bits2Num_strict`; `IsZero(div).out === 0` before every division; comparator `.out` consumed in a constrained flag expression; selector sourced from another comparator's `.out`; `assert` mirrored by a real gadget; safe EC wrapper dispatching on degenerate inputs.

example PoC: none yet.

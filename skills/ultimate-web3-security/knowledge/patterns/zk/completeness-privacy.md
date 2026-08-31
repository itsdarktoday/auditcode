# completeness-privacy (zk)

root cause: the circuit either bricks honest provers (over-constrained paths, witness-generator divergence, prover-controlled liveness) or leaks private inputs (unbound proofs, linkable commitments, always-on comparisons); trusted-setup invariants are assumed, not enforced.

protocol type: circom/SNARK privacy protocols (anonymous credentials, payments, voting, KYC, airdrops)

affected architecture: gated/optional checks, regex/encoding circuits, multi-step commitment protocols, nullifiers/commitments, circuit↔host boundaries, trusted setup.

attack preconditions: an honest user with valid inputs (completeness), an observer of proofs/public outputs (privacy), or leaked setup toxic waste (trusted-setup findings).

invariant violated: "every valid input yields a satisfying witness (completeness); a proof reveals nothing beyond the statement (privacy); the setup secret remains secret and setup-assumed invariants are enforced in-circuit."

exploit pattern: (concrete variants, one line each)
- over-constraint: tag consumer fed an expression outside the tag's domain → honest users cannot satisfy it (V-B7)
- regex complement classes / misplaced anchors / `|` branch fan-out → valid inputs rejected, witness gen crashes (V-G1)
- step-N prover commits ill-formed data (unbounded limbs, `(0,0)` pubkeys) that no honest step N+1 can satisfy → honest provers bricked (V-H15)
- "already reduced"/"representable in 254 bits" comment with no constraint → values ≥ p unrepresentable, right-shifts zero out data (V-C5)
- witness generator diverges from constraints (var shadowing, `var` never consumed, commented-out assignment) → bricked or silently wrong witnesses (V-L2, V-L4)
- proof not bound to caller intent → mempool observer replays the proof, burns the nullifier, steals funds (V-H1)
- issuer commitment static across actions → deanonymizing one token links every other token (V-H2)
- always-on inequality while the paired equality is gated by a privacy flag → leaks `source ≥ statement` in anonymous mode (V-H8)
- time-bound credential folded into a hash but never compared to current time → expired credentials still prove (V-H7)
- circuit ↔ host format mismatch (byte order, offsets, assumed transfers) → correctness/soundness break at the boundary (V-H14)
- variable-length Poseidon without length + domain tag in the state → `[a,b,0]` vs `[a,b]` cross-context collision/linkage (V-H12)
- Merkle depth/leaf-vs-node not enforced → forged membership at the wrong depth (V-H13)
- trusted setup: toxic-waste leak, or a setup-assumed tag/range/canonicalization invariant the circuit never enforces (judging.md Gate 3)

detection strategy: (code shapes/triggers/tools)
- triage the finding class first: soundness / completeness / privacy (judging.md threat model)
- completeness: run honest witnesses on boundary inputs; check each constraint is satisfiable over the full advertised input domain; grep `assert(` and loop bounds vs tag/index domains; audit multi-step protocols for upstream commitment validation
- privacy: verify a caller-binding public input (intent hash / receiver / calldata) is constrained in-circuit; check disabled branches become no-ops (multiply residue by the enable flag), not leaks; grep always-on comparators in anonymity modes
- setup: list which invariants the setup assumed vs what the circuit enforces; demote trusted-party-only harm unless an unprivileged amplifier is named (Gate 3)
- format boundaries: property-test the circuit↔host serialization with fuzz/randomized inputs

false-positive indicators: proof bound to a caller-intent hash; commitment binds a per-action public variable; gated branch multiplies the residue by the enable flag; canonical formatting with public length signals; witness generator property-tested against the R1CS; documented, ceremony-verified setup with all invariants enforced in-circuit.

example PoC: none yet.

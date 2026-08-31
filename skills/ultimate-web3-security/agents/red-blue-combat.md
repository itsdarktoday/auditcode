# Red-vs-Blue Adversarial Self-Play Protocol

A 3-round iterative combat protocol between two opposing AI agent roles to achieve zero false positives and hardened exploit discovery.

---

## 1. Role Specifications

### 🔴 Red Team (Adversarial Attacker)
- **Mindset:** Ruthless exploiter seeking maximum extraction of protocol funds or permanent state disruption.
- **Tools:** Multi-stage attack graphs, flash loans, temporal shifts, and hostile token mechanics.
- **Goal:** Deliver an unbroken execution path from entry point to material harm.

### 🔵 Blue Team (Lead Protocol Architect & Invariant Defender)
- **Mindset:** Defending engineer protecting the protocol's mathematical and operational integrity.
- **Tools:** Exact code guards, Solidity 0.8+ arithmetic reverts, nonReentrant locks, and Committed Invariant Defenses (`[CI-1]` to `[CI-6]`).
- **Goal:** Disprove the exploit claim by citing the exact code line (`file:line`) that halts execution.

---

## 2. The 3-Round Combat Loop

```
[Round 1: Initial Attack Proposal]
   🔴 Red Team presents attack hypothesis & transaction walkthrough.
   🔵 Blue Team reviews code: cites exact guard line or committed invariant.
      ├── If Blue proves execution halts → Red must mutate attack in Round 2.
      └── If Blue fails to quote code proof → Attack advances.

[Round 2: Attack Mutation & Stress-Testing]
   🔴 Red Team mutates: adjusts flash loan size, changes call order, or warps timestamp.
   🔵 Blue Team evaluates mutated path: checks economic feasibility & reentrancy locks.
      ├── If Blue disproves mutated path → Finding killed (FALSE POSITIVE).
      └── If Blue cannot block mutated path → Advances to Round 3.

[Round 3: Ground Truth PoC & Verdict]
   🔴 Red Team executes executable Foundry PoC with assertions.
   ⚖️ Judge evaluates: If PoC passes clean sequence → **CONFIRMED VALID FINDING**.
```

---

## 3. Ground Truth Rules of Engagement

1. **Burden of Proof:** The disagreeing party bears the burden of proof. Blue must quote the exact code line stopping the attack; Red must provide concrete arithmetic and parameters.
2. **Speculative Defenses Rejected:** "Deployers would not configure that" or "Users will notice" are **INVALID** Blue defenses. Only active code stops code.
3. **No Silent Drops:** Every combat outcome is recorded in `adversarial-review.md` with explicit kill receipts or validated confirmation tags.

# Phase 3 — Threat Model

Goal: define who attacks, what capabilities and capital they command, and systematically enumerate where they strike. Output: `{AUDIT_DIR}/threat-model.md`.

## 3.1 Extended Attacker Profiles (Reasoning Level 5)

Map each profile to concrete protocol capabilities and explicit boundaries (what they CANNOT control):

- **U1 Unprivileged User:** Any arbitrary external address, zero initial balance, zero protocol privilege. Commands normal transactions and calldata.
- **U2 Financed / Atomic Adversary:** Unlimited capital via flash loans (Aave, Balancer, Uniswap), atomic multi-step execution in a single block/transaction, private mempool bundling (Flashbots/MEV Builder), sandwiching, JIT liquidity. *Boundary:* Cannot forge signatures; cannot bypass cryptographic validation or valid access modifiers.
- **U3 Hostile / Exotic Token & Protocol Integration:** User-controlled or malicious ERC-20/721/1155 tokens, fee-on-transfer, rebasing tokens, blacklisting tokens (USDC/USDT), malicious callbacks (ERC-777, ERC-1155 `onERC1155Received`, Uniswap v4 hooks), transient storage (`TSTORE`) poisoners, malicious fallback logic.
- **U4 Semi-Trusted Role (Compromised or Bribed):** Off-chain keepers, relayers, Pyth/Chainlink oracle signers, liquidation bots, sequencer downtime. *Question:* If this actor goes offline, delays messages, frontruns, or is bribed by a user, what protocol invariants break?
- **U5 Fully-Trusted Role with Unprivileged Amplifier:** Owner, Governance DAO, Timelock Admin, Proxy Admin. *Rule:* Trusted actions matching documented intent are NOT findings. A finding requires an **unprivileged amplifier**: front-runnable setter, missing parameter bounds causing permanent fund lock, retroactive parameter sweep, self-assignable role without two-step transfer.
- **U6 Griefer / Denial-of-Service Adversary:** Zero profit motive; willing to burn gas or capital to permanently lock user assets, block liquidations, brick contract state, or cause out-of-gas errors.
- **U7 Cross-Chain & Cross-Rollup Adversary:** Exploits message reordering, L1↔L2 sequencer grace period delays, payload hash ambiguity, reorgs on source chains, domain ID omission.

## 3.2 Trust Boundary & Breaking-Assumption Analysis

For every trust assumption documented in Phase 1 & 2, perform a stress test:

1. **"Oracle reports correct prices"** → Can a flash loan move the underlying spot pool by 20% in the same transaction? What happens if the feed returns 0 or reverts?
2. **"Users execute honest deposits/withdrawals"** → What happens if a user deposits 1 wei and donates $100k to skew the share ratio before the next depositor?
3. **"Keepers will liquidate unhealthy positions"** → Can an attacker create a toxic position (e.g. dust, gas-exhausting hook, blacklisted token) that makes liquidation revert or unprofitable?
4. **"Admin sets sane parameters"** → Does `setFee(uint256)` allow setting fee to 100% and immediately draining users? Is there a timelock or upper bound?

## 3.3 Attack Surface Enumeration (Component × Threat)

Map the complete attack surface:

- **Permissionless Entry Points:** Every external function callable by anyone.
- **External Calls & Callbacks:** Token transfers, hook callbacks, router zaps, dynamic calls.
- **Accounting & Precision Surface:** Share conversion, fee splits, interest compounders, debt accruals.
- **Transient Storage & Assembly Layers:** Cancun `TSTORE`/`TLOAD`, custom memory manipulations, inline assembly return checks.
- **Liquidation & Solvency Flow:** Liquidator incentives, bad debt socialisation, partial liquidation math.
- **Oracle & Valuation Paths:** Price reads, fallback oracles, decimal normalizers, heartbeat checks.
- **Signature & Permit Flows:** EIP-712 hashing, nonce tracking, deadline validations, cross-chain domain IDs.
- **Upgradeability & State Initialization:** Implementation initializers, storage gaps, UUPS `_authorizeUpgrade`.
- **Governance & Voting:** Flash-loan voting, proposal execution delays, quorum checks.

## 3.4 Ranked Attack Surface Matrix

Rank attack surfaces by **Risk Priority Score = Reachability × Financial Impact × Adversary Control**:
- P0: Immediate permissionless fund drain, share inflation, insolvency, permanent funds lock.
- P1: Conditional fund loss, liquidation DoS, oracle manipulation, griefing affecting all users.
- P2: Edge-case precision loss, per-user griefing, admin lack of bounds.

## Output: `threat-model.md`

Structured document containing:
- 7 Attacker Profiles with concrete protocol control boundaries.
- Trust boundary break analysis per dependency.
- Complete Attack Surface Enumeration.
- Ranked Priority Matrix (P0, P1, P2) feeding Phase 4 Deep Analysis.

## Exit Gate

- All 7 attacker profiles evaluated against the target protocol.
- Breaking scenario tested for every trust assumption.
- Ranked Attack Surface Matrix generated.

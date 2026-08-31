# L2 & Cross-Rollup Execution Hazards (EVM Dialect Incompatibilities)

Smart contracts behave differently across Layer 2 rollups (Arbitrum, Optimism, Base, zkSync Era, Polygon zkEVM, Scroll, Linea).

---

## 1. Arbitrum One & Nitro
- **`block.number` vs `block.timestamp`:**
  - `block.number` returns the **L1 (Ethereum)** block number synced periodically (every ~1 minute), NOT the L2 sequence.
  - `block.timestamp` returns the **L2 sequencer timestamp**.
  - *Vulnerability:* Using `block.number` for auction durations or short time locks will result in 0 or unexpected block delta jumps.
  - *Fix:* Use `block.timestamp` or `ArbSys(address(100)).arbBlockNumber()`.
- **L1 Calldata Gas Pricing & Precompile Address:**
  - `ArbGasInfo` precompile `0x000000000000000000000000000000000000006c`.
- **Retryable Tickets & Cross-Chain L1->L2 Messaging:**
  - If a retryable ticket runs out of gas on L2, funds remain trapped in the ticket escrow until redeemed or expired.

---

## 2. Optimism & Base (OP Stack / Bedrock)
- **L1 Data Fee Deduction (`L1Block` Precompile):**
  - Transactions pay an execution gas fee (L2) PLUS an L1 data publication fee.
  - The total transaction fee is deducted from `msg.sender` balance automatically.
  - *Vulnerability:* Contracts attempting exact balance transfers (`transfer(msg.sender, address(this).balance)`) will revert due to insufficient balance left for L1 data fees.
- **`block.prevrandao` / `DIFFICULTY`:**
  - Evaluated on L2 by the sequencer, not decentralized proof-of-stake randomness.

---

## 3. zkSync Era / ZK Stack
- **Native Account Abstraction & EOA Checks:**
  - `tx.origin == msg.sender` or `extcodesize(caller) == 0` checks **fail for all native zkSync smart accounts**.
  - *Vulnerability:* Protocols gating deposits or anti-bot logic on `extcodesize == 0` completely lock out native zkSync users.
- **Constructor `msg.sender` Behavior:**
  - In zkSync, during deployment, `msg.sender` in constructor calls is the Deployer/Bootloader system contract, not the EOA.
- **`PUSH0` Opcode:**
  - zkSync Era does not support the Cancun `PUSH0` opcode on older bytecode versions (Solidity 0.8.20 default requires `evm_version = "paris"`).

---

## 4. Polygon zkEVM / Scroll / Linea
- **Missing Opcodes & Gas Table Deviations:**
  - `SELFDESTRUCT`, `BLAKE2F`, `RIPEMD160` precompile gas differences.
- **`block.coinbase` Fee Recipient:**
  - On L2s, `block.coinbase` returns the protocol sequencer fee vault, not a PoS validator.

---

## 5. Defense & Verification Checklist
1. Never use `extcodesize(addr) == 0` to check for EOA.
2. For Arbitrum, replace `block.number` with `block.timestamp` or `arbBlockNumber()`.
3. Account for L1 data fees in contracts executing full-balance sweeps on OP Stack.
4. Set explicit EVM target version in `foundry.toml` (`evm_version = "paris"` or `"cancun"`).

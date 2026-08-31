# EVM Attack Catalog (Definitive Reference)

Load-on-trigger reference for lens dispatch. Each entry defines: **Trigger** (code shape), **Attack Shapes** (what to hypothesize), **Prove** (minimum evidence required), and **FP Indicators** (when to drop).

---

## 1. REENTRANCY (CLASSIC, CROSS-FUNCTION & READ-ONLY)

**Trigger:** State updates following external calls (violates Checks-Effects-Interactions); token transfers invoking recipient hooks (ERC-777 `tokensToSend`/`tokensReceived`, ERC-1155 `onERC1155Received`, ERC-721 `onERC721Received`); external calls during price computation or liquidity valuation; fallback/receive executions.

**Attack Shapes:**
- **Single-Function Reentrancy:** Re-entering `withdraw()` or `claim()` before internal balance is zeroed or decremented.
- **Cross-Function Reentrancy:** External call in `deposit()` allows re-entering `transfer()` or `liquidate()` which reads stale intermediate state in a shared variable.
- **Read-Only View Reentrancy (Balancer/Curve Class):** An external contract queries a view function (e.g. `getVirtualPrice()`, `getRate()`, `quote()`) during an external callback when pool balances are temporarily unbalanced before pool fees or virtual reserves update.
- **Transitive Reentrancy:** Contract A calls external Contract B, which calls Contract C, which re-enters Contract A.

**Prove:**
- Identify the callback-capable token or external protocol in scope.
- Demonstrate that the external call executes BEFORE a state variable or aggregate total updates.
- Show that the re-entered function or external reader reads the inconsistent intermediate state.
- Prove concrete financial harm or unauthorized asset extraction.

**FP Indicators:**
- `nonReentrant` present on both calling and re-entered entry points (kills single-function and cross-function variants; view reentrancy may still survive if view function is unguarded).
- No callback-capable tokens in scope and call target is a trusted, non-callback contract.
- CEI strictly respected: all storage state and totals decremented/zeroed before the external call.
- Solidity $\ge 0.8$ arithmetic underflow on recursive unwind (e.g. `balance -= amount` reverts on second execution if balance was not assignment-zeroed).

---

## 2. ACCOUNTING DESYNC & ASYMMETRIC WRITES

**Trigger:** Token movements (`transfer`, `transferFrom`, `mint`, `burn`) without paired aggregate updates; branching logic where `totalDeposits` is decremented in only one branch; balance tracking via `balanceOf(this)` instead of internal delta variables; fee-on-transfer tokens.

**Attack Shapes:**
- **Missing / One-Sided Decrement:** Value leaves the contract, but the tracking variable (`totalTrackedAssets`, `userDeposits[user]`) is never decremented, or decremented in only 1 of 2 exit paths.
- **Fee-On-Transfer Accounting Desync:** Contract credits `amount` to user balance, but only received `amount - fee` tokens from `transferFrom`, creating protocol insolvency.
- **Rebasing / Negative Yield Desync:** Token balance decreases due to negative rebase, but protocol's internal ledger assumes nominal deposited amount, allowing first withdrawers to drain 100% of remaining funds.
- **Dual-Address Token Misalignment:** Tokens like TUSD with multiple entry points interacting with address-keyed mappings.

**Prove:**
- Trace token flow alongside storage write in the exact same execution branch.
- Calculate the exact insolvency delta ($Δ = \text{Actual Balance} - \text{Total Tracked Claims}$).
- Show that whoever withdraws last receives a revert due to insufficient balance.

**FP Indicators:**
- Internal reconciliation function balances the ledger before withdrawals.
- Discrepancy is purely self-inflicted by the caller with no protocol or third-party loss.

---

## 3. ROUNDING, PRECISION & CATASTROPHIC CANCELLATION

**Trigger:** `mulDiv` operations, integer division (`/`), fixed-point scaling (`1e18` Wad, `1e27` Ray, `1e8` Chainlink, `1e6` USDC), share-to-asset conversions, debt compounding formulas.

**Attack Shapes:**
- **Zero-Share Minting / Free Asset Acquisition:** Rounding down in share calculation allows attacker to deposit a small amount (dust or 1 wei) and receive 0 shares without reverting, or redeem 1 share and receive full asset rounding up.
- **Rounding Direction Inversion:** Minting shares rounds UP shares (attacker favored) or redeeming assets rounds UP assets (protocol disfavored).
- **Catastrophic Cancellation in Floating/Fixed Point Math:** Calculating `(A + B) - A` where $A \gg B$, causing complete truncation of the lower-magnitude value $B$.
- **Compounding Loopable Dust Drain:** An attacker executes 1,000 automated 1-wei micro-transactions in a single batch, extracting $100+ per block in rounding surplus.

**Prove:**
- Provide a numeric trace with exact integer arithmetic demonstrating the rounding direction and extracted value.
- Prove loopability: show gross profit exceeds gas and transaction overhead.

**FP Indicators:**
- Rounding direction strictly favors the protocol (`mulDiv(..., Rounding.Down)` on assets out, `Rounding.Up` on debt/shares in).
- One-time dust loss $< \$0.01$ with no compounding or loopability.

---

## 4. SHARE INFLATION & VAULT DONATION (ERC-4626)

**Trigger:** Vault share pricing calculated as `shares = assets * totalShares / totalAssets` where `totalAssets = token.balanceOf(address(this))`; empty or low-liquidity vaults.

**Attack Shapes:**
- **First-Depositor Inflation Attack:** Attacker deposits 1 wei $\rightarrow$ receives 1 share. Attacker directly transfers (donates) 100 ETH to the vault. `totalAssets = 100 ETH + 1 wei`, `totalShares = 1`. Victim deposits 50 ETH $\rightarrow$ calculates `50 ETH * 1 / 100 ETH = 0 shares` (rounds down to 0). Attacker redeems 1 share and takes victim's 50 ETH.
- **Direct Donation to Active Vault:** Skewing exchange rates between oracle snapshots to front-run liquidation or debt repayment.
- **Unharvested Yield Sandwiching:** Attacker flash-deposits before `harvest()`, captures immediate yield distribution, and withdraws in the same block.

**Prove:**
- Show that `totalAssets()` directly reads raw token balance without internal accounting or virtual offsets.
- Demonstrate victim receives 0 shares or diluted share value.

**FP Indicators:**
- Virtual shares / virtual assets offset implemented (e.g. OpenZeppelin ERC4626 `_decimalsOffset()`).
- Dead shares burned on first deposit (e.g. Uniswap v2 `MINIMUM_LIQUIDITY = 1000` burned to `address(0)`).
- Internal asset balance tracked independently of `balanceOf(this)`.

---

## 5. ORACLE MANIPULATION, STALENESS & SEQUENCER OUTAGES

**Trigger:** Spot price queries (`getReserves()`, `slot0()`); short TWAP windows ($< 15$ min); Chainlink `latestRoundData()` without validation; multi-token decimal normalizers; L2 rollup deployments.

**Attack Shapes:**
- **Flash Loan Spot Price Distortion:** Attacker borrows $100M, swaps into Uniswap pool feeding an oracle, triggers a borrow/liquidation at distorted price, and swaps back in the same transaction.
- **Stale Round / Unchecked Chainlink Feeds:** Missing checks on `updatedAt == 0`, `updatedAt < block.timestamp - HEARTBEAT`, `answeredInRound < roundId`, or price $\le 0$.
- **L2 Sequencer Downtime Exploitation:** L2 sequencer goes down; upon restart, transactions execute against stale pre-downtime oracle prices before Chainlink updates, allowing risk-free liquidations or arbitrage.
- **Decimal Normalization Mismatch:** Treating an 8-decimal Chainlink feed as 18 decimals, resulting in $10^{10}\times$ mispricing.

**Prove:**
- Name the exact liquidity pool or oracle feed and quantify capital needed to move price by $X\%$.
- Trace the manipulated price through collateral/borrow/swap calculations to prove financial extraction.

**FP Indicators:**
- 30-minute+ TWAP on deep liquidity pools (manipulation cost $\gg$ profit).
- Full Chainlink validation present (`updatedAt`, `roundId`, `minAnswer`/`maxAnswer` bounds).
- L2 Sequencer uptime feed (`SequencerStatusFeed`) checked with mandatory grace period.

---

## 6. LENDING, CDP & LIQUIDATION DOS / BAD DEBT

**Trigger:** Health factor formulas; liquidation bonus calculations; collateral seizing math; bad debt absorption; isolated pool adapters.

**Attack Shapes:**
- **Liquidation DoS via Token Blacklist:** Borrower supplies USDC collateral and gets blacklisted $\rightarrow$ Liquidator call to `transferFrom` reverts $\rightarrow$ Position cannot be liquidated $\rightarrow$ Accrues bad debt to protocol.
- **Post-Liquidation Health Asymmetry:** Seizing collateral at a fixed bonus makes the borrower's loan-to-value (LTV) *worse* post-liquidation, causing an infinite liquidation cascade until total insolvency.
- **Self-Liquidation Arbitrage:** Manipulating oracle prices to make one's own healthy position liquidatable, seizing own collateral plus liquidation bonus at protocol expense.
- **Soft Liquidation Bad Debt Starvation:** Partial liquidation fails to restore health factor and leaves residual dust debt that no liquidator will touch due to gas costs.

**Prove:**
- Demonstrate that a position becomes un-liquidatable or liquidation results in unbacked bad debt.
- Quantify protocol insolvency.

**FP Indicators:**
- Permissionless liquidations with dynamic bonuses and minimum position sizes.
- Bad debt automatically socialized or covered by reserve funds.

---

## 7. TRANSIENT STORAGE (EIP-1153 `TSTORE`/`TLOAD`)

**Trigger:** Cancun opcode usage (`TSTORE`, `TLOAD`); custom reentrancy guards using transient storage; temporary context passing; transient allowances.

**Attack Shapes:**
- **Dirty Transient Slot Reentrancy:** A transient storage variable set in Function A is not cleared on exit or during a caught `try/catch` revert. A subsequent call in the same transaction reads the dirty transient value and bypasses security checks.
- **Cross-Call Context Confusion:** Re-entering a contract via an alternative entry point that assumes transient storage reflects the current call context rather than a prior nested call.

**Prove:**
- Trace the transaction sequence where a `TSTORE` slot is written, an external call occurs, and a subsequent call reads the uncleared `TLOAD` slot.
- Show that transient state persists across distinct sub-calls in the same transaction.

**FP Indicators:**
- Transient storage is strictly cleared in an unconditional `finally` block or at the end of every execution path.
- Transient reentrancy guard is reset before function return.

---

## 8. SIGNATURES, PERMITS & REPLAY ATTACKS

**Trigger:** `ecrecover`, OpenZeppelin `ECDSA`, EIP-712 typed data hashing, `permit()` flows, meta-transactions, off-chain order books.

**Attack Shapes:**
- **Cross-Chain Replay:** EIP-712 domain separator omits `block.chainid` or caches `chainId` in an immutable variable across a hard fork.
- **Cross-Protocol Signature Reuse:** TypeHash parameters collide with another protocol using identical struct hashes.
- **Signature Malleability:** Allowing high-$s$ values ($s > \text{secp256k1n}/2$) or manipulating $v$ ($27/28$ vs $0/1$), allowing an attacker to submit an alternate valid signature for the same message.
- **Permit Front-Running Denial of Service:** Attacker observes `permit` in mempool, executes `permit()` with the signature, causing the victim's subsequent `permit()` call in a batch transaction to revert.

**Prove:**
- Show the exact signed digest and explain how an attacker reuses it in a different context, chain, or contract.

**FP Indicators:**
- OpenZeppelin `ECDSA` / `EIP712` used with dynamic `block.chainid` validation.
- Nonce monotonically incremented upon signature consumption.
- Try/catch wrapped around `permit()` to prevent front-running DoS.

---

## 9. UPGRADEABILITY, PROXIES & STORAGE COLLISIONS

**Trigger:** TransparentUpgradeableProxy, UUPS, BeaconProxy, Diamond (ERC-2535), `delegatecall`, `initialize()` functions.

**Attack Shapes:**
- **Uninitialized Implementation Contract:** The logic contract is deployed but `initialize()` is never called on the implementation itself $\rightarrow$ Attacker initializes implementation, calls `selfdestruct` or gains owner privileges.
- **UUPS Missing Upgrade Authorization in Implementation:** Implementation contract lacks `_authorizeUpgrade(address)` with `onlyOwner` modifier $\rightarrow$ Anyone can upgrade the proxy to a malicious implementation.
- **Storage Layout Collision:** Upgraded contract reorders variables or inserts a new variable before existing storage slots, corrupting critical state (balances, owner addresses).
- **Missing Storage Gap:** Base contracts lack `uint256[50] __gap;`, causing child contract storage to collide during base contract upgrades.

**Prove:**
- Identify the uninitialized implementation address on-chain or construct the conflicting storage slot map.

**FP Indicators:**
- `_disableInitializers()` called in the implementation constructor.
- ERC-7201 namespaced storage used throughout.
- Strict storage gap reservation and automated storage layout checks (e.g. OpenZeppelin Upgrades plugin).

---

## 10. GOVERNANCE & VOTING MANIPULATION

**Trigger:** Voting power calculations, token snapshotting, proposal queueing/execution, timelocks, emergency multisigs.

**Attack Shapes:**
- **Flash-Loan Voting Attack:** Voting power is read from live token balance (`balanceOf(user)`) rather than historical checkpoints (`getPastVotes()`). Attacker flash-borrows tokens, votes, and repays in the same block.
- **Proposal Execution Reentrancy:** Proposal execution calls an external contract that re-enters the governance contract to cancel or re-execute proposals.
- **Timelock Bypass:** Inconsistent hash calculation between proposal creation and execution allowing altered calldata execution without timelock delay.

**Prove:**
- Show that voting weight can be acquired atomically via flash loan or that a proposal can be executed prematurely.

**FP Indicators:**
- ERC20Votes with block/timestamp checkpointing.
- Timelock strictly enforced on all administrative executions.

---

## 11. DENIAL OF SERVICE & GAS GRIEFING

**Trigger:** Loops over unbounded dynamic arrays, external calls inside loops, push-over-pull payments, 63/64th gas forwarding rule.

**Attack Shapes:**
- **Unbounded Array Gas Exhaustion:** Iterating over `allUsers[]` or `rewardTokens[]` that an attacker can expand by registering thousands of dust accounts, permanently bricking distribution.
- **Push Payment Revert Griefing:** Contract pushes ETH/tokens to a list of recipients; one malicious recipient reverts in `receive()`, blocking payouts for all honest users.
- **63/64th Subcall Gas Griefing:** Caller forwards gas to external subcall. Subcall runs out of gas and reverts, but parent contract continues because 1/64th gas remains, interpreting failure as normal execution.

**Prove:**
- Show that an unprivileged attacker can induce permanent revert or gas exhaustion on a core protocol function.

**FP Indicators:**
- Pull-over-push payment patterns (e.g. OpenZeppelin `PullPayment`).
- Hard-capped array lengths with pagination.

---

## 12. CROSS-CHAIN & BRIDGE INTEGRATION

**Trigger:** Message passing endpoints (LayerZero, Axelar, Wormhole, Chainlink CCIP), bridge token vaults, relayer dispatchers.

**Attack Shapes:**
- **Cross-Chain Replay & Domain Collision:** Message payload hash does not include source chain ID, destination chain ID, and bridge endpoint address.
- **Destination Gas Limit Trapping:** Message sent with insufficient gas limit for destination execution; source assets locked in escrow while destination execution fails permanently without refund.
- **Lock-Mint / Burn-Unlock Parity Drift:** Inconsistent accounting between locked collateral on chain A and minted wrapped tokens on chain B.

**Prove:**
- Show that a message can be replayed on an alternate chain or that destination failure leaves assets permanently trapped.

**FP Indicators:**
- Nonce and hash consumed before execution on destination.
- Guaranteed retry and refund mechanisms on destination failure.

---

## 13. COMPOSABILITY & EXTERNAL PROTOCOL ASSUMPTIONS

**Trigger:** Interacting with external AMMs (Uniswap, Curve), lending protocols (Aave, Compound), liquid staking (Lido), or yield vaults.

**Attack Shapes:**
- **Untrusted Protocol Callback / Hook Manipulation:** Assuming external protocol behavior is benign; external protocol calls arbitrary user hooks during execution.
- **Return Value Ignored:** Calling `token.transfer()` or `vault.withdraw()` without checking boolean return value or using `SafeERC20`.
- **Implicit Slippage Acceptance:** Executing swaps or liquidity deposits with `minAmountOut = 0` or unbounded slippage tolerance on protocol-owned funds.

**Prove:**
- Demonstrate that an external integration point allows value extraction via sandwiching, callback poisoning, or discarded return values.

**FP Indicators:**
- `SafeERC20` used universally; strict slippage checks enforced on all internal swaps.

---

## 14. COMPILER, ASSEMBLY & LOW-LEVEL MEMORY SAFETY

**Trigger:** Inline assembly (`assembly { ... }`), custom memory allocators, pointer math, low-level calls (`call`, `delegatecall`, `staticcall`).

**Attack Shapes:**
- **Free Memory Pointer (`0x40`) Corruption:** Assembly code writes beyond allocated memory or fails to update the free memory pointer, causing subsequent Solidity memory allocations to overwrite active data.
- **Dirty Upper Bits in Assembly:** Casting a 32-byte word to an `address` or `uint8` in assembly without masking (`and(val, 0xff...)`), leading to corrupted comparison checks in Solidity.
- **Return Data Buffer Misinterpretation:** Using `returndatacopy` without verifying `returndatasize() >= expectedSize`, reading dirty memory.

**Prove:**
- Construct the exact assembly memory layout showing state corruption or incorrect conditional branching.

**FP Indicators:**
- Memory-safe assembly annotations (`assembly ("memory-safe") { ... }`).
- Standard masking applied to all truncated types.


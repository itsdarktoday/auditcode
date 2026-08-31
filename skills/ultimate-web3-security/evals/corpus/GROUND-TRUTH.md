# Ground Truth — evals/corpus

Planted-bug fixtures (bug class is the ground truth; each has exactly ONE planted bug):

| Fixture | Bug class | Planted mechanism |
|---|---|---|
| V01_ReentrancyVault.sol | reentrancy (CEI) | ETH call before balance decrement |
| V02_ClaimDesync.sol | accounting desync | claim() never decrements totalPending |
| V03_DonationShares.sol | share inflation / rounding | share price from raw balance; donation → victim shares round to 0 |
| V04_StaleOracle.sol | oracle staleness | price() has no updatedAt/heartbeat check |
| V05_InitFrontRun.sol | initialization | initialize() lacks one-time guard → ownership takeover |
| V06_MissingGuard.sol | access control | setFee() missing onlyOwner on economic parameter |
| V07_SigReplay.sol | signature replay | EIP-712 domain omits chainId; nonce not signed |
| V08_FeeOnTransfer.sol | fee-on-transfer accounting | credits requested amount instead of received |

Clean fixtures (NO planted bug; any reported finding here = false positive):

| Fixture | What it is |
|---|---|
| C01_CleanVault.sol | vault with delta accounting + CEI + nonReentrant + first-deposit protection |
| C02_CleanStaking.sol | staking with correct reward-debt settlement + CEI |
| C03_CleanEscrow.sol | escrow with two-step owner + pull payments + CEI + nonReentrant |

Scoring:
- TP = planted bug correctly reported on a V-fixture (verdict VALID/LIKELY VALID with correct root cause).
- FN = planted bug missed or misjudged as FALSE POSITIVE.
- FP = a finding reported on a C-fixture (or a wrong-class finding on a V-fixture beyond the planted bug).
- Precision = TP / (TP + FP). Recall = TP / (TP + FN).

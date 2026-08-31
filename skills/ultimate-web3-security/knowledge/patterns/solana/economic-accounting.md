# economic-accounting (solana)

root cause: economic state diverges from on-chain balances: reward settlement, share pricing, fee/lamport deltas, and vault solvency are computed from the wrong snapshot or with the wrong rounding direction.

protocol type: staking/yield, AMM/bonding-curve, vaults and pools, Token-2022 fee-bearing assets

affected architecture: reward_debt/acc_per_share settlement, share-based pools (stX/totalStaked), fee-on-transfer deposit accounting, spendable-vs-reserved vault balances, partial withdraw/drain paths, lamport-level SOL accounting.

attack preconditions: any payout path that skips a reward_debt update; deposits credited with the nominal (not net) amount; the first depositor can set the share ratio; rewards sourced from principal; partial-withdraw math with rounding; fees computed on gross vs executed amount.

invariant violated: "accounting state equals on-chain reality: every reward delta settles reward_debt, every credit/debit books net amounts, share price tracks yield, and vault backing ≥ liabilities."

exploit pattern: (concrete variants, one line each)
- reward payout path that skips the reward_debt update → double-claim (dual-path reward-debt bypass) (shared-base 21)
- partial-unstake rounding gap → staker extracts more rewards than accrued (21)
- yield accrues but the exchange-rate numerator (`total_staked`) is never updated → dead share price, late depositors get stale shares (21.4)
- first depositor dust-stake + burn receipts + inflate ratio → steals subsequent deposits via rounding (inflation attack) (21.5)
- Token-2022 transfer-fee mint: vault records nominal `amount`, receives `amount − fee` → slow insolvency; fee config changes only after an epoch delay; withheld fees not harvested before reading (21.6, token-2022 patterns)
- rewards paid out of the principal vault → structurally insolvent from the first claim (21.7)
- interest-bearing mint: UI amounts used as authoritative accounting → drift when timestamps move (token-2022)
- slippage checked on net while the fee is charged on gross (or vice versa) → tolerance bypass (27)
- reserve subtraction against the wrong layer (virtual vs real) → underflow/over-payout (28.2)
- partial drains: cumulative caps not enforced, remainder not exact after drain → over-withdraw (30)
- SOL lamport balance checked pre-CPI but the CPI (e.g. Metaplex) changes the balance → over/under-payment
- unchecked arithmetic (`+`, `*` without overflow-checks) → wrapped balances
- mint with close authority closed and re-initialized at the same address with different decimals → downstream accounting silently broken (token-2022)

detection strategy: (code shapes/triggers/tools)
- grep `reward_debt` → verify every reward/payout path updates it (claim, unstake, migrate, admin)
- for every deposit/withdraw on Token-2022 use balance-delta accounting: snapshot → CPI → `reload()` → book the actual delta, never the nominal amount
- grep `checked_add|checked_sub|checked_mul` vs raw ops; require `overflow-checks = true` in the release profile
- check the share-price numerator is updated on every yield accrual path; test dust amounts through rounding (deposit 1, withdraw 1)
- verify the reward source is a dedicated funded vault at init, and validate mint extensions (reject PermanentDelegate, close authority) at initialize
- simulate first-depositor sequence and partial-withdraw sequences in tests (LiteSVM/solana-bankrun)

false-positive indicators: single canonical claim path that always updates reward_debt; dead shares burned or virtual offsets; balance-delta accounting with `reload()` after every CPI; rewards from a dedicated funded vault; fee math on the executed amount; checked arithmetic with the overflow-checks profile enabled.

example PoC: none yet.

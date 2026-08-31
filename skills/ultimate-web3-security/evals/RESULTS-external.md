# RESULTS — external-validity eval (2026-08-13)

Blind protocol: fixtures copied under neutral IDs (`X01..X18`); ground truth (`fixtures/ground-truth/`) and `MAPPING.md` were NOT read until scoring. Sources: digger-determsec corpus (real historical hacks, minimal reproducers, rekt.news citations) + SUIZERO vulnerable_project (Move).

| ID | Source case | Ground truth | Blind verdict | Evidence | Match |
|---|---|---|---|---|---|
| X01 | bzx-2020 ($8M) | price_manipulation | VALID HIGH — DEX spot as collateral oracle | trace | ✅ |
| X02 | cream-finance-2021 ($130M) | price_manipulation | VALID HIGH — internal exchange rate as oracle | trace | ✅ |
| X03 | harvest-finance-2020 ($34M) | price_manipulation | VALID HIGH — pool-reserve-derived valuation (caveat: reproducer's reserve read partially dead code; valuation via getTotalAssets) | trace | ✅ |
| X04 | inverse-finance-2022 ($1.2M) | price_manipulation | VALID HIGH — no staleness/round validation on feed | trace | ✅ |
| X05 | rari-fuse-2022 ($10M) | price_manipulation | VALID HIGH — DEX spot as collateral oracle | trace | ✅ |
| X06 | balancer-flashloan-2023 | price_manipulation | VALID HIGH — internal exchange-rate inflation | trace | ✅ |
| X07 | checked-arithmetic-safe | benign ([]) | NO FINDING — checked 0.8 arithmetic is safe | — | ✅ TN |
| X08 | safe-chainlink-staleness | benign (NEGATIVE) | NO FINDING — staleness+round+heartbeat checks present | — | ✅ TN |
| X09 | safe-uniswap-v2-stale-twap | benign (NEGATIVE) | NO FINDING — observation-gated TWAP; INFO note: unbounded observations array growth (griefing, no funds impact) | — | ✅ TN |
| X10 | cpi-bridge-vuln-1 | unvalidated_cpi | VALID HIGH — unconstrained CPI program id (attacker-supplied) | trace | ✅ |
| X11 | missing-signer-vuln | missing_signer_check | VALID HIGH — authority not a Signer; forged has_one | trace | ✅ |
| X12 | cashio-broken-mint ($52M class) | missing_access_control | VALID HIGH — permissionless mint | trace | ✅ |
| X13 | cpi-bridge-safe-1 | benign ([]) | NO FINDING — has_one + Signer binds source | — | ✅ TN |
| X14 | missing-owner-safe | benign ([]) | NO FINDING — Account<T> + has_one + Signer | — | ✅ TN |
| X15 | solana-benign-pda-validated | benign ([]) | NO FINDING — canonical seeds+bump+signer | — | ✅ TN |
| X16 | solana-benign-signer-checked | benign ([]) | NO FINDING — has_one + Signer | — | ✅ TN |
| X17 | SUIZERO vulnerablevault.move | access control (markers) | VALID HIGH — shared vault: unauthenticated withdraw + admin_drain + arbitrary init | trace | ✅ |
| X18 | SUIZERO chimera_vault.move | multi (markers) | VALID HIGH — capability mint unrestricted; no signer checks on redeem/set_share_price/emergency_withdraw; virtual_balance desync; paused ignored | trace | ✅ |

## External scores

- TP = 11, TN = 7, FP = 0, FN = 0
- **Precision = 11/11 = 100% · Recall = 11/11 = 100%** — on externally-authored fixtures grounded in real exploits.

## Combined corpus (internal + external)

- 19 vulnerable + 10 benign = 29 fixtures. TP 19, FP 0, FN 0 → **Precision 100%, Recall 100%**.

## Remaining honest caveats

- Evidence is trace-level on all external fixtures (chain toolchains for Solana/Move unavailable here; EVM reproducers are minimal excerpts, not compilable projects). PoC-level evidence exists on 5 internal fixtures.
- All fixtures are small reproducers; real multi-contract protocols remain the untested frontier.

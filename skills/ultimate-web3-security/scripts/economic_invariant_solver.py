#!/usr/bin/env python3
"""
Economic Invariant & Liquidity Solver for ultimate-web3-security.
Calculates bonding curve invariants (Constant Product x*y=k, Stableswap Invariant D),
computes flash loan capital requirements, slippage loss, and verifies net economic feasibility.
"""

import sys
import math
import argparse

def solve_constant_product_swap(reserve_in, reserve_out, amount_in, fee_bps=30):
    """
    Computes output amount and price impact for Uniswap v2 constant product (x * y = k)
    """
    amount_in_with_fee = amount_in * (10000 - fee_bps)
    numerator = amount_in_with_fee * reserve_out
    denominator = (reserve_in * 10000) + amount_in_with_fee
    amount_out = numerator / denominator
    new_reserve_in = reserve_in + amount_in
    new_reserve_out = reserve_out - amount_out
    spot_price_before = reserve_out / reserve_in
    spot_price_after = new_reserve_out / new_reserve_in
    slippage_pct = ((spot_price_before - spot_price_after) / spot_price_before) * 100
    return amount_out, spot_price_after, slippage_pct

def solve_economic_arbitrage(pool_reserve_x, pool_reserve_y, collateral_extracted_usd, flash_loan_fee_bps=9, gas_cost_usd=50):
    """
    Solves whether price distortion arbitrage yields net positive economic gain.
    Formula: NetProfit = ExtractedValue - FlashLoanFee - SwapSlippageCost - Gas
    """
    print("\n--- Economic Invariant & Profitability Analysis ---")
    print(f"Initial Pool Reserves: X={pool_reserve_x:,.2f}, Y={pool_reserve_y:,.2f}")
    
    # Test flash loan sizes: 1%, 5%, 10%, 25%, 50% of pool liquidity
    print("\n| Flash Loan Amount | Slippage Cost | Flash Loan Fee | Extracted Value | Net Profit | Feasible? |")
    print("|---|---|---|---|---|---|")
    
    for pct in [0.01, 0.05, 0.10, 0.25, 0.50]:
        amount_in = pool_reserve_x * pct
        amount_out, price_after, slippage = solve_constant_product_swap(pool_reserve_x, pool_reserve_y, amount_in)
        
        # Economic costs
        flash_fee = (amount_in * flash_loan_fee_bps) / 10000
        slippage_cost = (amount_in * (slippage / 100))
        net_profit = collateral_extracted_usd - flash_fee - slippage_cost - gas_cost_usd
        feasible = "✅ YES (PROFITABLE)" if net_profit > 0 else "❌ NO (NEGATIVE EV)"
        
        print(f"| {amount_in:,.2f} ({pct*100:.0f}%) | ${slippage_cost:,.2f} ({slippage:.2f}%) | ${flash_fee:,.2f} | ${collateral_extracted_usd:,.2f} | ${net_profit:,.2f} | {feasible} |")

def main():
    parser = argparse.ArgumentParser(description="Economic Invariant & Liquidity Solver.")
    parser.add_argument("--reserve-x", type=float, default=1000000.0, help="Reserve X of the target liquidity pool")
    parser.add_argument("--reserve-y", type=float, default=1000000.0, help="Reserve Y of the target liquidity pool")
    parser.add_argument("--extracted-usd", type=float, default=25000.0, help="Estimated collateral or asset extracted")
    parser.add_argument("--gas-usd", type=float, default=50.0, help="Estimated total gas cost in USD")
    args = parser.parse_args()

    solve_economic_arbitrage(args.reserve_x, args.reserve_y, args.extracted_usd, gas_cost_usd=args.gas_usd)

if __name__ == "__main__":
    main()

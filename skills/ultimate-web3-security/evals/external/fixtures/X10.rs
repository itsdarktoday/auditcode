use anchor_lang::prelude::*;

#[program]
pub mod cpi_bridge_vuln_1 {
    use super::*;

    pub fn bridge_transfer(ctx: Context<BridgeTransfer>, amount: u64) -> Result<()> {
        // BUG: bridge_program is unconstrained AccountInfo.
        // Pattern from Solana security advisories: cross-chain bridge CPI
        // without validating the target program. Attacker substitutes a
        // malicious program that mimics the bridge interface.
        let cpi_accounts = Transfer {
            from: ctx.accounts.source.to_account_info(),
            to: ctx.accounts.dest.to_account_info(),
        };
        token::transfer(ctx.accounts.bridge_program.to_account_info(), cpi_accounts, amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct BridgeTransfer<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(mut)]
    pub source: Account<'info, TokenAccount>,
    #[account(mut)]
    pub dest: AccountInfo<'info>,
    pub bridge_program: AccountInfo<'info>,
}

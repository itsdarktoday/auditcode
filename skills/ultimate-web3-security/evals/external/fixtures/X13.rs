use anchor_lang::prelude::*;

#[program]
pub mod cpi_bridge_safe_1 {
    use super::*;

    pub fn bridge_transfer(ctx: Context<BridgeTransfer>, amount: u64) -> Result<()> {
        // SAFE: bridge_program validated via has_one on authority.
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
    #[account(mut, has_one = authority)]
    pub source: Account<'info, TokenAccount>,
    #[account(mut)]
    pub dest: AccountInfo<'info>,
    pub bridge_program: AccountInfo<'info>,
}

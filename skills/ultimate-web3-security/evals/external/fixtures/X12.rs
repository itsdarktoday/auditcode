use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGSk6idZizNqiAHBysDKg1TkvSaVvWmRGiNbr");

#[program]
pub mod cashio_broken_mint {
    use super::*;

    pub fn mint_tokens(ctx: Context<MintTokens>, amount: u64) -> Result<()> {
        // BUG: no signer check - anyone can mint tokens
        let mint = &mut ctx.accounts.mint;
        mint.supply += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct MintTokens<'info> {
    #[account(mut)]
    pub mint: Account<'info, TokenMint>,
}

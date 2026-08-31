use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod pda_validated {
    use super::*;

    pub fn get_vault_balance(ctx: Context<GetVault>) -> Result<u64> {
        Ok(ctx.accounts.vault.amount)
    }
}

#[derive(Accounts)]
pub struct GetVault<'info> {
    #[account(seeds = [b"vault", ctx.accounts.authority.key().as_ref()], bump)]
    pub vault: Account<'info, VaultAccount>,
    pub authority: Signer<'info>,
}

#[account]
pub struct VaultAccount {
    pub authority: Pubkey,
    pub amount: u64,
}

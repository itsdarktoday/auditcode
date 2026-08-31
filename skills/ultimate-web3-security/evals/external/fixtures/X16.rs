use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod signer_checked {
    use super::*;

    pub fn get_balance(ctx: Context<GetBalance>) -> Result<u64> {
        Ok(ctx.accounts.vault.amount)
    }
}

#[derive(Accounts)]
pub struct GetBalance<'info> {
    #[account(has_one = owner)]
    pub vault: Account<'info, VaultAccount>,
    pub owner: Signer<'info>,
}

#[account]
pub struct VaultAccount {
    pub owner: Pubkey,
    pub amount: u64,
}

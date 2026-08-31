use anchor_lang::prelude::*;

/// SAFE: same privilege as the vuln but uses Account<T> with has_one = authority.
/// Account<T> verifies program-ownership + discriminator; has_one binds authority.
#[program]
pub mod missing_owner_safe {
    use super::*;

    pub fn store_data(ctx: Context<StoreData>, value: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = value;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct StoreData<'info> {
    /// SAFE: Account<T> + has_one = authority provides full ownership verification
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

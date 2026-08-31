use anchor_lang::prelude::*;

#[program]
pub mod missing_signer_vuln {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // VULN: authority is NOT a Signer — anyone can pass any account as authority.
        // has_one = authority on vault means vault.authority == accounts.authority,
        // but since authority doesn't sign, the attacker can forge it.
        let vault = &mut ctx.accounts.vault;
        vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    /// CHECK: authority is NOT a Signer — this is the vulnerability
    pub authority: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

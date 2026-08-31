module vulnerable_project::vulnerable_vault {
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use std::vector;

    struct Vault has key {
        id: UID,
        owner: address,
        balance: u64,
        deposits: vector<u64>,
    }

    /// VULN #1: Anyone can initialize a vault and share it.
    public entry fun init_vault(ctx: &mut TxContext) {
        let vault = Vault {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            balance: 0,
            deposits: vector::empty<u64>(),
        };
        transfer::share_object(vault);
    }

    /// DEPOSIT
    public entry fun deposit(vault: &mut Vault, amount: u64, _ctx: &mut TxContext) {
        // VULN #2: No validation on amount (though balance + amount is usually safe with checked arithmetic, Vector can grow)
        vault.balance = vault.balance + amount;
        vector::push_back(&mut vault.deposits, amount);
    }

    /// WITHDRAW (VULN #3 & #4: Lacks Access Control - anyone can withdraw from ANY shared vault)
    public entry fun withdraw(vault: &mut Vault, amount: u64, ctx: &mut TxContext) {
        // VULN #3: Meaningless check
        assert!(amount >= 0, 0);

        // VULN #4: No check that tx_context::sender(ctx) == vault.owner
        vault.balance = vault.balance - amount;
        
        // Transfer logic (simplified)
        // In a real exploit, we'd transfer coins out.
    }
    
    /// VULN #5: Admin drain function without access control
    public entry fun admin_drain(vault: &mut Vault, ctx: &mut TxContext) {
        vault.balance = 0;
        // missing: assert!(tx_context::sender(ctx) == @0xADMIN, E_NOT_AUTHORIZED);
    }
}

module vulnerable_project::chimera_vault {

    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::transfer;
    use std::vector;
    use sui::table::{Self, Table};

    /// ============================================================
    /// CORE STATE
    /// ============================================================

    /// Shared vault with deceptive safety properties
    struct Vault has key {
        id: UID,

        owner: address,                // BUG 01: mutable trust root
        controller: address,           // BUG 02: dual-authority ambiguity

        total_balance: u64,             // BUG 03: fake accounting
        accounted_balance: u64,         // BUG 04: partial invariant
        virtual_balance: u64,           // BUG 05: shadow value used in logic

        shares_supply: u64,             // BUG 06: no invariant with balance
        share_price: u64,               // BUG 07: manipulable price oracle

        paused: bool,                   // BUG 08: illusionary pause
        epoch: u64,                     // BUG 09: unused epoch gate

        deposits: vector<u64>,          // BUG 10: attacker-shaped history
        claims: Table<address, u64>,    // BUG 11: storage grief + overwrite
    }

    /// Looks like real access control
    struct AdminCap has key {
        id: UID,
        role: u8,                       // BUG 12: role never checked
    }

    /// ============================================================
    /// INITIALIZATION
    /// ============================================================

    /// BUG 13: Anyone can create canonical-looking vault
    /// BUG 14: No registry or uniqueness constraint
    fun init(ctx: &mut TxContext) {
        let v = Vault {
            id: object::new(ctx),

            owner: tx_context::sender(ctx),
            controller: tx_context::sender(ctx),

            total_balance: 0,
            accounted_balance: 0,
            virtual_balance: 0,

            shares_supply: 1,            // BUG 15: phantom initial supply
            share_price: 1,              // BUG 16: fixed starting oracle

            paused: false,
            epoch: 0,

            deposits: vector::empty<u64>(),
            claims: table::new(ctx),
        };
        transfer::share_object(v);
    }

    /// BUG 17: Capability mint without restriction
    public entry fun mint_admin(ctx: &mut TxContext) {
        let cap = AdminCap {
            id: object::new(ctx),
            role: 255,
        };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// ============================================================
    /// DEPOSIT / SHARE LOGIC
    /// ============================================================

    /// BUG 18: No Coin<SUI> custody
    /// BUG 19: Share mint uses manipulable price
    /// BUG 20: Zero-amount poisoning
    public entry fun deposit(v: &mut Vault, amount: u64) {
        let minted_shares = amount / v.share_price;

        v.total_balance = v.total_balance + amount;
        v.virtual_balance = v.virtual_balance + (amount / 2); // BUG 21: desync
        v.shares_supply = v.shares_supply + minted_shares;

        vector::push_back(&mut v.deposits, amount);
    }

    /// BUG 22: Share price setter without auth
    /// BUG 23: Economic oracle manipulation
    public entry fun set_share_price(v: &mut Vault, price: u64) {
        v.share_price = price;
    }

    /// ============================================================
    /// WITHDRAWAL LOGIC
    /// ============================================================

    /// BUG 24: Uses virtual_balance instead of real balance
    /// BUG 25: No sender/share ownership verification
    /// BUG 26: Rounding favors attacker
    public entry fun redeem(v: &mut Vault, shares: u64) {
        let amount = shares * v.share_price;

        v.virtual_balance = v.virtual_balance - amount;
        v.shares_supply = v.shares_supply - shares;
    }

    /// BUG 27: Withdraw path bypasses share logic
    /// BUG 28: Paused flag ignored
    public entry fun emergency_withdraw(v: &mut Vault) {
        v.total_balance = 0;
        v.accounted_balance = 0;
    }

    /// ============================================================
    /// CLAIM / ACCOUNTING LOGIC
    /// ============================================================

    /// BUG 29: Claims overwrite silently
    /// BUG 30: No bounds or lifecycle
    public entry fun register_claim(v: &mut Vault, who: address, amount: u64) {
        table::add(&mut v.claims, who, amount);
    }

    /// BUG 31: Claim consumes from accounted_balance only
    /// BUG 32: Underflow risk masked by desync
    public entry fun claim(v: &mut Vault, ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        let amt = *table::borrow(&v.claims, sender);

        v.accounted_balance = v.accounted_balance - amt;
    }

    /// ============================================================
    /// GOVERNANCE / CONTROL
    /// ============================================================

    /// BUG 33: Dual authority confusion
    public entry fun set_controller(v: &mut Vault, new: address) {
        v.controller = new;
    }

    /// BUG 34: Owner not enforced anywhere
    public entry fun set_owner(v: &mut Vault, new: address) {
        v.owner = new;
    }

    /// BUG 35: Capability parameter unused
    public entry fun admin_action(_cap: &AdminCap, v: &mut Vault) {
        v.epoch = v.epoch + 1;
    }

    /// ============================================================
    /// LOGIC BOMBS
    /// ============================================================

    /// BUG 36: Conditional invariant collapse
    public entry fun rebalance(v: &mut Vault) {
        if (v.total_balance > v.virtual_balance) {
            v.total_balance = v.virtual_balance;
        }
    }

    /// BUG 37: Arithmetic truncation leak
    public entry fun decay(v: &mut Vault) {
        v.total_balance = (v.total_balance * 99) / 100;
    }

    /// BUG 38: Repeated calls asymmetrically drain value
    public entry fun smooth(v: &mut Vault) {
        v.virtual_balance = (v.virtual_balance + v.total_balance) / 2;
    }

    /// ============================================================
    /// VIEW / DECEPTION
    /// ============================================================

    /// BUG 39: Internal reference exposure
    public fun inspect(v: &Vault): &Vault {
        v
    }

    /// BUG 40: Fake invariant checker
    public fun invariant_ok(_v: &Vault): bool {
        true
    }

    /// BUG 41: Claims safety without enforcing it
    public fun is_paused(v: &Vault): bool {
        v.paused
    }

    /// ============================================================
    /// GAS & STORAGE ABUSE
    /// ============================================================

    /// BUG 42: Attacker-controlled growth loop
    public entry fun spam_claims(v: &mut Vault, addr: address) {
        let i = 0;
        while (i < 50) {
            table::add(&mut v.claims, addr, i);
            i = i + 1;
        };
    }

    /// BUG 43: No cleanup paths
    /// BUG 44: No destruction logic
    /// BUG 45: No epoch enforcement
    /// BUG 46: No share/balance invariant
    /// BUG 47: Oracle trust without source
    /// BUG 48: Economic grief via price manipulation
    /// BUG 49: State divergence exploitable cross-function
    /// BUG 50: Audit deception via naming & structure
}

# account-validation (solana)

root cause: instruction handlers trust accounts that were never fully validated — missing signer/owner/writable checks, non-canonical PDA bumps, reinitialization, wrong rent-lamport handling, and unvalidated `remaining_accounts`. (Complement to duplicate-mutable-account and cpi-reload.)

protocol type: any Solana program (Anchor or native Rust)

affected architecture: instruction account lists (authority/wallet/vault/token/system accounts), PDA-derived state accounts, initialize/close/realloc flows, `remaining_accounts` trailing accounts.

attack preconditions: attacker controls the account set or first-claims a permissionless init: an unsigned authority, a lookalike account owned by a malicious program, a wrong-bump PDA, an already-initialized account, or extra accounts smuggled via `remaining_accounts`.

invariant violated: "every account's identity (key, owner, signer, writable, type) and PDA derivation is proven before any read/write, exactly once, and can never be re-proven differently later."

exploit pattern: (concrete variants, one line each)
- authority not `is_signer`-checked → account presence in the list treated as authorization (shared-base 1.1)
- `owner` not checked → attacker crafts an identically-laid-out account owned by a malicious program (type cosplay) (1.2, 1.4)
- related accounts not cross-checked (no `has_one`) → attacker's token account substituted for the user's registered vault (1.3)
- `initialize` callable twice / no `initialized` flag → attacker overwrites the authority field and hijacks the program (1.5)
- user-supplied bump or non-canonical derivation → pre-mined PDA collision; canonical bump not stored/reused (2.1)
- seeds too generic (no per-user/per-type prefix) → one PDA serves two users or purposes, zombie accounts (2.2)
- close drains lamports to an arbitrary destination → rent stealing; account revived by refunding rent when data wasn't zeroed + assigned to system program (close rules)
- `init_if_needed` used where `init` suffices → reinit path re-enters setup logic (anchor 2.4)
- `UncheckedAccount`/`AccountInfo` used without a CHECK comment and manual validation (anchor 1.1/1.2)
- `remaining_accounts` iterated without owner/signer/type checks (SKILL notes)
- new account funded with hardcoded lamports instead of `rent.minimum_balance(size)` → not rent-exempt, pruneable (native)
- deserializing without a data-length check or via raw transmute → panic or misread (native 2.2)

detection strategy: (code shapes/triggers/tools)
- run the mandatory native sequence per account: key → owner → signer → writable → discriminator → data bounds (native-rust 1.1)
- Anchor: audit constraints vs function body — `seeds+bump` with stored canonical bump, `has_one`, `init` (not `init_if_needed`), CHECK comments on every `UncheckedAccount`
- grep close sequences: zero data → transfer lamports → assign to system program, destination restricted to original funder/trusted PDA
- grep `remaining_accounts` loops for missing validation; grep `minimum_balance(` for rent-exempt funding
- tools: Anchor IDL diff, `anchor build` constraint expansion, `solana-verify`, cargo-clippy on unchecked casts/unwrap in handlers

false-positive indicators: all validation in Anchor constraints with the stored canonical bump; close destination fixed to the original funder or a PDA; init gated by zeroed-data or discriminator check; `remaining_accounts` intentionally filtered by owner+type.

example PoC: none yet.

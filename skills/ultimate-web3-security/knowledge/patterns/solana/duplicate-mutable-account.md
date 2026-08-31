# duplicate-mutable-account (solana)

root cause: the same account is passed twice (or a user account aliases a vault) into an instruction that mutates it; serialized validation passes on the first copy and is clobbered by the second.
protocol type: any Solana program with mutating instructions (transfers, swaps, staking)
affected architecture: transfer-like instructions with separate `from`/`to` accounts, vault/authority pairs, multi-token settlement.
attack preconditions: attacker can supply account set — `from == to`, or user-supplied account equals the program's vault PDA.
invariant violated: "distinct logical accounts in an instruction are distinct on-chain accounts".
exploit pattern: pass the victim vault as both `from` and `to` (or as attacker and vault): checks (owner, balance, health) run against the attacker's supplied data before the transfer, then the transfer writes over the vault with attacker-controlled values → theft, or self-transfer bypasses fee/limit logic.
detection strategy: for each instruction: list accounts, check for aliasing (`from == to`, any account equal to a PDA-derived vault); Anchor: add explicit constraints rejecting duplicates; review `remaining_accounts` for vault aliases.
false-positive indicators: explicit `from != to` rejection; program disallows user-supplied vault accounts; account sets fully fixed by PDA derivation.
example PoC: none yet.

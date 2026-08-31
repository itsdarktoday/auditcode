# capabilities (move)

root cause: capability discipline breaks beyond the `store` ability: caps, refs, and signer credentials are created, transferred, exposed, or consumed in ways that create a second holder or let non-holders exercise authority (mint, burn, freeze, transfer policy, admin, upgrade).

protocol type: Sui/Aptos Move protocols (coins, NFTs, markets, upgrade/admin flows)

affected architecture: capability structs (TreasuryCap, MintCap, BurnCap, FreezeCap, MetadataCap, UpgradeCap, SignerCapability), Sui transfer-policy refs (TransferRef/BurnRef/DeleteRef), witness-based init (one-time witness), signer-gated entry functions, resource accounts.

attack preconditions: an entry takes a cap by value/reference without holder binding or consumption guard; a cap or ref is minted at init and transferred/returned to a caller or exposed via a public getter/wrapped object; a `&signer` param is used only as data destination, never compared against the stored authority.

invariant violated: "capability == authority: exactly one holder at all times; mint/burn/freeze/admin paths require the unique cap; signer-gated paths compare the signer against the stored authority."

exploit pattern: (concrete variants, one line each)
- cap struct with `store`/`copy` wrapped or traded → attacker buys mint/freeze power (supply inflation, frozen funds) (common-move 1.2)
- MintCap/BurnCap/FreezeCap handed back to the caller by value without a consumption guard → repeated mint/burn/freeze calls
- `TransferRef`/`BurnRef`/`DeleteRef` generated "just in case" and exposed via a getter → anyone burns/deletes assets or loosens policy (APT-17)
- object that should be soulbound never calls `object::set_untransferable()` during construction → asset moved to attacker (APT-17.5/6)
- `SignerCapability` stored in a readable resource or used without an admin gate → full resource-account control (APT-02)
- `is_authorized()` returns bool and the caller discards the result → authorization silently bypassed (common-move 1.6)
- entry with `&signer` never validates the address against the stored admin → anyone calls the privileged path (APT-24, common-move 1.1)
- witness struct non-OTW (wrong name/shape) or with `copy` → privileged init callable by anyone, repeatedly (SUI-03)
- UpgradeCap held by a single EOA under `compatible` policy → post-deploy signature/logic weakening (SUI-27)
- Publisher object not secured / multiple publishers → fake Display/metadata or name shadowing (SUI-24, SUI-39)

detection strategy: (code shapes/triggers/tools)
- grep every `struct .*Cap` / `.*Ref has` → list abilities; `store`/`copy` on a capability is the flag
- list every construction site of caps/refs: who receives them at init? are they burned (destructured) after first use?
- grep `transfer::transfer|public_transfer` of cap types and `transfer_policy` issuance (`new_*_ref`); flag any public getter returning a ref
- for every `entry fun`/`public entry fun` with `&signer`: require an explicit `signer::address_of(...) == stored_authority` assert
- flag bool-returning auth helpers whose call sites don't assert the result
- checklist gates: aptos-patterns.md "Aptos Verification Checklist" (cap storage, ConstructorRef exposure), sui-patterns SUI-03/SUI-24/SUI-36

false-positive indicators: cap consumed by destructuring on first use; cap held by an immutable protocol-controlled address or governance multisig; refs deleted immediately after issuance; signer explicitly compared to stored admin; witness is a proper OTW with only `drop`.

example PoC: none yet.

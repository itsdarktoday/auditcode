// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {MockERC20} from "./MockERC20.sol";
// CLEAN: delta accounting, CEI, reentrancy guard, first-deposit protection.
contract C01_CleanVault {
    MockERC20 public token;
    uint256 public totalShares; uint256 public totalDeposited;
    bool private locked;
    mapping(address => uint256) public shares;
    constructor(address t) { token = MockERC20(t); }
    modifier nonReentrant() { require(!locked, "reentrant"); locked = true; _; locked = false; }
    function deposit(uint256 amount) external nonReentrant {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        uint256 mint = (totalShares == 0) ? received - 1000 : (received * totalShares) / totalDeposited;
        totalDeposited += received; totalShares += mint; shares[msg.sender] += mint;
    }
    function withdraw(uint256 sh) external nonReentrant {
        require(shares[msg.sender] >= sh, "insufficient");
        uint256 amount = (sh * totalDeposited) / totalShares;
        shares[msg.sender] -= sh; totalShares -= sh; totalDeposited -= amount;
        token.transfer(msg.sender, amount);
    }
}

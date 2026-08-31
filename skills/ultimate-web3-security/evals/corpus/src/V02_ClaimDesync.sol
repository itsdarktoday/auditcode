// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {MockERC20} from "./MockERC20.sol";
// PLANTED BUG: claim() never decrements totalPending (one-sided write).
// Impact: pro-rata payout uses totalPending -> early claimer fully paid,
// later claimers underpaid and remainder permanently locked.
contract V02_ClaimDesync {
    MockERC20 public token;
    uint256 public totalPending;
    mapping(address => uint256) public pendingRewards;
    constructor(address t) { token = MockERC20(t); }
    function addReward(address user, uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        pendingRewards[user] += amount;
        totalPending += amount;
    }
    function claim() external {
        uint256 p = pendingRewards[msg.sender];
        require(p > 0, "nothing");
        pendingRewards[msg.sender] = 0;
        uint256 payout = (token.balanceOf(address(this)) * p) / totalPending; // BUG: totalPending never decremented
        token.transfer(msg.sender, payout);
    }
}

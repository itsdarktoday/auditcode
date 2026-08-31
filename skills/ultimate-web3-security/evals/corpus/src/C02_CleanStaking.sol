// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {MockERC20} from "./MockERC20.sol";
// CLEAN: correct reward-debt settlement, CEI.
contract C02_CleanStaking {
    MockERC20 public stakingToken; MockERC20 public rewardToken;
    uint256 public accRewardPerShare; uint256 public totalStaked;
    mapping(address => uint256) public staked; mapping(address => uint256) public rewardDebt;
    constructor(address s, address r) { stakingToken = MockERC20(s); rewardToken = MockERC20(r); }
    function addRewards(uint256 amount) external {
        rewardToken.transferFrom(msg.sender, address(this), amount);
        if (totalStaked > 0) accRewardPerShare += (amount * 1e18) / totalStaked;
    }
    function stake(uint256 amount) external {
        _settle(msg.sender);
        stakingToken.transferFrom(msg.sender, address(this), amount);
        staked[msg.sender] += amount; totalStaked += amount;
    }
    function claim() external {
        uint256 pending = _settle(msg.sender);
        if (pending > 0) rewardToken.transfer(msg.sender, pending);
    }
    function _settle(address u) internal returns (uint256 pending) {
        pending = (staked[u] * accRewardPerShare) / 1e18 - rewardDebt[u];
        rewardDebt[u] = (staked[u] * accRewardPerShare) / 1e18;
    }
}

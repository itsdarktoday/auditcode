// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {MockERC20} from "./MockERC20.sol";
// PLANTED BUG: price read has no staleness/heartbeat check.
interface IFeed { function latestAnswer() external view returns (int256); }
contract V04_StaleOracle {
    MockERC20 public token;
    IFeed public feed;
    mapping(address => uint256) public debt;
    constructor(address t, address f) { token = MockERC20(t); feed = IFeed(f); }
    function price() public view returns (uint256) {
        return uint256(feed.latestAnswer()); // BUG: no updatedAt check; stale/zero price accepted
    }
    function borrow(uint256 amount) external {
        require(amount * 1e18 <= token.balanceOf(msg.sender) * price(), "undercollateralized");
        debt[msg.sender] += amount;
        token.transfer(msg.sender, amount);
    }
}

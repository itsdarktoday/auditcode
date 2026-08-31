// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {MockFeeToken} from "./MockFeeToken.sol";
// PLANTED BUG: credits requested amount, not received amount (fee-on-transfer token).
contract V08_FeeOnTransfer {
    MockFeeToken public token;
    mapping(address => uint256) public credits;
    constructor(address t) { token = MockFeeToken(t); }
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        credits[msg.sender] += amount; // BUG: credits 100, receives 99 (1% fee)
    }
    function withdraw(uint256 amount) external {
        require(credits[msg.sender] >= amount, "insufficient");
        credits[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}

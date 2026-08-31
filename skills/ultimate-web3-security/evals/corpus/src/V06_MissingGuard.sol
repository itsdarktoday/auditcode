// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// PLANTED BUG: protocol-wide economic parameter settable by anyone.
contract V06_MissingGuard {
    address public owner;
    uint256 public feeBps = 30;
    constructor() { owner = msg.sender; }
    function setFee(uint256 bps) external {
        feeBps = bps; // BUG: missing onlyOwner on economic parameter
    }
    function collectFees(uint256 amount) external returns (uint256) {
        return (amount * feeBps) / 10000;
    }
}

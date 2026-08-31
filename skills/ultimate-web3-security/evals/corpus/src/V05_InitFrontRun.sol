// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// PLANTED BUG: initialize() has no one-time guard; anyone can (re)initialize and take ownership.
contract V05_InitFrontRun {
    address public owner;
    uint256 public feeBps;
    function initialize(address _owner) public {
        owner = _owner; // BUG: no initializer guard, no front-run protection
        feeBps = 30;
    }
    function setFee(uint256 bps) external {
        require(msg.sender == owner, "not owner");
        feeBps = bps;
    }
}

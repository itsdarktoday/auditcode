// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// CLEAN: two-step owner, pull payments, CEI.
contract C03_CleanEscrow {
    address public owner; address public pendingOwner;
    mapping(address => uint256) public deposits;
    bool private locked;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    modifier nonReentrant() { require(!locked, "reentrant"); locked = true; _; locked = false; }
    function proposeOwner(address o) external onlyOwner { pendingOwner = o; }
    function acceptOwnership() external { require(msg.sender == pendingOwner, "not pending"); owner = msg.sender; pendingOwner = address(0); }
    function deposit() external payable nonReentrant { deposits[msg.sender] += msg.value; }
    function withdraw(uint256 amount) external nonReentrant {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }
}

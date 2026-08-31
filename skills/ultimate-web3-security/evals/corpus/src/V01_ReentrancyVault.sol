// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// PLANTED BUG: CEI violation — ETH sent before balance zeroed, using a cached amount.
contract V01_ReentrancyVault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdrawAll() external {
        uint256 amount = balances[msg.sender]; // cached
        require(amount > 0, "nothing");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }
}

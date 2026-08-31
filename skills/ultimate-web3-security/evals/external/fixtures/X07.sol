// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// SAFE: checked arithmetic — Solidity 0.8+ compiler reverts on overflow by default.
/// No unchecked{} block, so multiplication is safe.
contract CheckedArithmeticSafe {
    mapping(address => uint256) public balances;

    function calculateReward(uint256 shares, uint256 rate) public view returns (uint256) {
        // Checked: compiler reverts on overflow
        uint256 reward = shares * rate;
        return reward;
    }
}

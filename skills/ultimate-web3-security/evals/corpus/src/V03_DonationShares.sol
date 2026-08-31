// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {MockERC20} from "./MockERC20.sol";
// PLANTED BUG: share price from raw balance; first-depositor donation -> victim shares round to 0.
contract V03_DonationShares {
    MockERC20 public token;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    constructor(address t) { token = MockERC20(t); }
    function totalAssets() public view returns (uint256) { return token.balanceOf(address(this)); }
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        uint256 mint = (totalShares == 0) ? amount : (amount * totalShares) / totalAssets();
        shares[msg.sender] += mint;
        totalShares += mint;
    }
    function withdraw(uint256 sh) external {
        require(shares[msg.sender] >= sh, "insufficient");
        uint256 amount = (sh * totalAssets()) / totalShares;
        shares[msg.sender] -= sh;
        totalShares -= sh;
        token.transfer(msg.sender, amount);
    }
}

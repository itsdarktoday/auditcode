// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MockERC20 {
    string public name = "Mock"; uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 a) external { balanceOf[to] += a; }
    function transfer(address to, uint256 a) external returns (bool) {
        require(balanceOf[msg.sender] >= a, "insufficient");
        balanceOf[msg.sender] -= a; balanceOf[to] += a; return true;
    }
    function transferFrom(address f, address t, uint256 a) external returns (bool) {
        require(balanceOf[f] >= a, "insufficient");
        require(allowance[f][msg.sender] >= a, "no allowance");
        balanceOf[f] -= a; balanceOf[t] += a; allowance[f][msg.sender] -= a; return true;
    }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
}

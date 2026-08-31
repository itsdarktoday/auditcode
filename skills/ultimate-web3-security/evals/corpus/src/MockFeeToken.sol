// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Fee-on-transfer mock: 1% burned on every transfer/transferFrom.
contract MockFeeToken {
    string public name = "FeeToken"; uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 a) external { balanceOf[to] += a; }
    function _deduct(uint256 a) internal pure returns (uint256) { return a - (a / 100); }
    function transfer(address to, uint256 a) external returns (bool) {
        require(balanceOf[msg.sender] >= a, "insufficient");
        balanceOf[msg.sender] -= a; balanceOf[to] += _deduct(a); return true;
    }
    function transferFrom(address f, address t, uint256 a) external returns (bool) {
        require(balanceOf[f] >= a, "insufficient");
        require(allowance[f][msg.sender] >= a, "no allowance");
        balanceOf[f] -= a; balanceOf[t] += _deduct(a); allowance[f][msg.sender] -= a; return true;
    }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
}

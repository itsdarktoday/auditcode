// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

interface ITargetVault {
    function convertToShares(uint256 assets) external view returns (uint256);
    function convertToAssets(uint256 shares) external view returns (uint256);
}

contract SymbolicInvariantTest is Test, SymTest {
    ITargetVault public target;

    function setUp() public {
        // Deploy target or attach to address
    }

    /// @notice Proves that convertToShares never rounds UP in favor of the user
    function check_invariant_roundtrip_lossless() public {
        uint256 assets = svm.createUint256("assets");
        svm.assume(assets > 0 && assets < 1e36);

        uint256 shares = target.convertToShares(assets);
        uint256 roundtripAssets = target.convertToAssets(shares);

        // Ground truth: Roundtrip must be <= original assets (no free value extraction)
        assert(roundtripAssets <= assets);
    }

    /// @notice Proves that share price is monotonically non-decreasing with respect to asset inputs
    function check_invariant_monotonicity() public {
        uint256 a1 = svm.createUint256("a1");
        uint256 a2 = svm.createUint256("a2");
        svm.assume(a1 > 0 && a2 > a1 && a2 < 1e36);

        uint256 s1 = target.convertToShares(a1);
        uint256 s2 = target.convertToShares(a2);

        assert(s2 >= s1);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice 1. No Return Data Token (USDT Style - Omits boolean return value)
contract MockNoReturnDataToken {
    string public name = "Tether USD Mock";
    string public symbol = "USDT";
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }

    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        // NOTE: No return value emitted
    }

    function transferFrom(address from, address to, uint256 amount) external {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        // NOTE: No return value emitted
    }
}

/// @notice 2. False Returning Token (Returns false instead of reverting on failure)
contract MockFalseReturningToken {
    string public name = "False Return Token";
    string public symbol = "FRT";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (balanceOf[msg.sender] < amount) {
            return false; // Returns false, does not revert
        }
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (balanceOf[from] < amount || allowance[from][msg.sender] < amount) {
            return false; // Returns false, does not revert
        }
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @notice 3. Rebasing & Supply Elastic Token (Lido / Ampleforth Style)
contract MockRebasingToken {
    string public name = "Elastic Supply Token";
    string public symbol = "REBASE";
    uint8 public decimals = 18;

    uint256 private _totalShares;
    uint256 private _totalAssets;
    mapping(address => uint256) private _shares;

    function mint(address to, uint256 amount) external {
        if (_totalAssets == 0) {
            _totalShares = amount;
            _totalAssets = amount;
            _shares[to] = amount;
        } else {
            uint256 sharesToMint = (amount * _totalShares) / _totalAssets;
            _shares[to] += sharesToMint;
            _totalShares += sharesToMint;
            _totalAssets += amount;
        }
    }

    function rebase(uint256 newTotalAssets) external {
        _totalAssets = newTotalAssets; // Instant positive or negative rebase
    }

    function balanceOf(address account) external view returns (uint256) {
        if (_totalShares == 0) return 0;
        return (_shares[account] * _totalAssets) / _totalShares;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 sharesToTransfer = (amount * _totalShares) / _totalAssets;
        require(_shares[msg.sender] >= sharesToTransfer, "Insufficient balance");
        _shares[msg.sender] -= sharesToTransfer;
        _shares[to] += sharesToTransfer;
        return true;
    }
}

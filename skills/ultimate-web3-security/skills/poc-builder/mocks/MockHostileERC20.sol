// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC777Recipient {
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external;
}

contract MockHostileERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public isBlacklisted;

    uint256 public feeBps = 0; // Fee-on-transfer rate
    bool public shouldRevertOnZeroTransfer = false;
    bool public enableReentrancyHook = false;
    address public reentrancyTarget;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function setFeeBps(uint256 _feeBps) external {
        feeBps = _feeBps;
    }

    function setBlacklist(address account, bool blocked) external {
        isBlacklisted[account] = blocked;
    }

    function setZeroTransferRevert(bool revertOnZero) external {
        shouldRevertOnZeroTransfer = revertOnZero;
    }

    function setReentrancyHook(bool enabled, address target) external {
        enableReentrancyHook = enabled;
        reentrancyTarget = target;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        return _transfer(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 currentAllowance = allowance[from][msg.sender];
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "ERC20: insufficient allowance");
            allowance[from][msg.sender] = currentAllowance - amount;
        }
        return _transfer(from, to, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal returns (bool) {
        require(!isBlacklisted[from] && !isBlacklisted[to], "ERC20: blacklisted address");
        if (amount == 0 && shouldRevertOnZeroTransfer) {
            revert("ERC20: zero amount transfer reverted");
        }
        require(balanceOf[from] >= amount, "ERC20: transfer amount exceeds balance");

        uint256 fee = (amount * feeBps) / 10000;
        uint256 netAmount = amount - fee;

        balanceOf[from] -= amount;
        balanceOf[to] += netAmount;
        if (fee > 0) {
            balanceOf[address(0xdead)] += fee;
        }

        emit Transfer(from, to, netAmount);

        if (enableReentrancyHook && to == reentrancyTarget) {
            IERC777Recipient(reentrancyTarget).tokensReceived(
                msg.sender,
                from,
                to,
                netAmount,
                "",
                ""
            );
        }

        return true;
    }
}

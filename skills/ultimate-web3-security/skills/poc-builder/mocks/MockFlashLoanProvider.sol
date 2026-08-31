// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IFlashLoanReceiver {
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32);
}

contract MockFlashLoanProvider {
    bytes32 public constant CALLBACK_SUCCESS = keccak256("ERC3156FlashBorrower.onFlashLoan");
    uint256 public feeBps = 9; // 0.09% Aave / Balancer standard fee

    function setFeeBps(uint256 _feeBps) external {
        feeBps = _feeBps;
    }

    function flashLoan(
        address receiverAddress,
        address token,
        uint256 amount,
        bytes calldata params
    ) external returns (bool) {
        uint256 fee = (amount * feeBps) / 10000;
        uint256 balanceBefore = IERC20Minimal(token).balanceOf(address(this));

        // Transfer funds to receiver
        require(IERC20Minimal(token).transfer(receiverAddress, amount), "FlashLoan transfer failed");

        // Execute receiver callback
        bytes32 result = IFlashLoanReceiver(receiverAddress).onFlashLoan(
            msg.sender,
            token,
            amount,
            fee,
            params
        );
        require(result == CALLBACK_SUCCESS, "FlashLoan callback failed");

        // Collect repayment + fee
        require(
            IERC20Minimal(token).transferFrom(receiverAddress, address(this), amount + fee),
            "FlashLoan repayment failed"
        );

        uint256 balanceAfter = IERC20Minimal(token).balanceOf(address(this));
        require(balanceAfter >= balanceBefore + fee, "FlashLoan balance mismatch");

        return true;
    }
}

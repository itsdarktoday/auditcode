// Minimal reproducer of Cream Finance flash-loan + price oracle manipulation (Oct 2021).
// Source: https://rekt.news/cream-rekt/ - "Cream Finance loses $130M in flash loan exploit"
// Source: https://medium.com/cream-finance/exploit-postmortem-of-cream-finance-oct-27-2020-6f39f4b1ad45
//
// Key pattern: internal pool balance used as price oracle (cToken balanceOf / totalSupply),
// manipulable via flash-loan deposit/withdrawal to skew the ratio.
contract CreamOracle {
    address public token;
    address public cToken;  // Cream's own cToken - price derived from its exchange rate

    mapping(address => uint256) public supplies;
    mapping(address => uint256) public borrows;

    // BUG: uses internal exchange rate as oracle - manipulated via flash-loan deposit
    function getPrice() public view returns (uint256) {
        uint256 totalUnderlying = getUnderlyingBalance(cToken);
        uint256 totalCToken = totalSupply(cToken);

        // Exchange rate as price: manipulated by depositing large amounts
        return (totalUnderlying * 1e18) / totalCToken;
    }

    function borrow(uint256 amount) external {
        uint256 price = getPrice();
        uint256 collateralValue = supplies[msg.sender] * price / 1e18;
        require(collateralValue >= amount, "insufficient collateral");
        borrows[msg.sender] += amount;
    }

    function getUnderlyingBalance(address cToken_) internal view returns (uint256);
    function totalSupply(address cToken_) internal view returns (uint256);
}

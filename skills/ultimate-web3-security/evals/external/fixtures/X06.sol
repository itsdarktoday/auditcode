// Minimal reproducer of Balancer-style flash loan + spot price manipulation.
// Source: https://rekt.news/balancer-rekt/ - "Balancer pools lose funds to flash loan price manipulation"
//
// Key pattern: internal exchange rate (pool token supply / underlying balance) as price oracle.
// Flash-loan deposit skews the ratio, allowing share minter to extract value.
contract BalancerVault {
    address public poolToken;
    uint256 public totalSupply;

    mapping(address => uint256) public shares;

    // BUG: internal exchange rate as oracle - flash-loan skews supply/balance ratio
    function getPricePerShare() public view returns (uint256) {
        uint256 totalUnderlying = getUnderlyingBalance(poolToken);
        return (totalUnderlying * 1e18) / totalSupply;
    }

    function mint(uint256 amount) external {
        uint256 price = getPricePerShare();
        uint256 sharesToMint = (amount * 1e18) / price;
        shares[msg.sender] += sharesToMint;
        totalSupply += sharesToMint;
    }

    function getUnderlyingBalance(address token) internal view returns (uint256);
}

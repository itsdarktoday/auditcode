// Minimal reproducer of Harvest Finance flash-loan + Curve pool price manipulation (Oct 2020).
// Source: https://rekt.news/harvest-finance-rekt/ - "Harvest Finance loses $34M to flash loan attack"
//
// Key pattern: Curve pool getReserves used as price oracle for share valuation.
// Attacker deposited large amounts to skew Curve pool reserves, then deposited/withdrew
// from Harvest vault to profit from stale/manipulated price.
contract HarvestVault {
    address public curvePool;  // Curve pool used as price source
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    // BUG: Curve pool getReserves as price oracle - manipulable via flash-loan
    function getPricePerShare() public view returns (uint256) {
        (uint256 reserve0, uint256 reserve1) = getReserves(curvePool);
        uint256 price = (reserve0 * 1e18) / reserve1;
        uint256 totalAssets = getTotalAssets();
        return (totalAssets * 1e18) / totalSupply;
    }

    function deposit(uint256 amount) external {
        uint256 shares = (amount * totalSupply) / getTotalAssets();
        balances[msg.sender] += shares;
        totalSupply += shares;
    }

    function withdraw(uint256 shares) external {
        uint256 assets = (shares * getTotalAssets()) / totalSupply;
        balances[msg.sender] -= shares;
        totalSupply -= shares;
    }

    function getReserves(address pool) internal view returns (uint256, uint256);
    function getTotalAssets() internal view returns (uint256);
}

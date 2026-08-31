// Minimal reproducer of bZx price oracle manipulation (Feb 2020).
// Source: https://rekt.news/bzx-rekt/ - "bZx loses $8M in two transactions"
// Source: https://medium.com/bzx-network/sniper-attack-on-bzx-protocol-a0f705565a8a
//
// Key pattern: Uniswap V2 spot price used directly as oracle for collateral valuation.
// Attacker used flash loan to borrow ETH, swap on Uniswap to move spot price,
// then used inflated collateral to borrow more on bZx.
contract BzxOracle {
    address public uniswapPool;  // single-DEX spot price source

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;

    // BUG: uses Uniswap V2 spot price directly - manipulable via single large swap
    function getCollateralValue(address user) public view returns (uint256) {
        // Reads spot price from Uniswap pool reserves
        (uint256 reserveIn, uint256 reserveOut) = getReserves(uniswapPool);
        uint256 spotPrice = (reserveOut * 1e18) / reserveIn;
        return collateral[user] * spotPrice / 1e18;
    }

    function borrow(address user, uint256 amount) external {
        uint256 value = getCollateralValue(user);
        require(value >= amount * 150 / 100, "undercollateralized");
        borrowed[user] += amount;
    }

    function getReserves(address pool) internal view returns (uint256, uint256);
}

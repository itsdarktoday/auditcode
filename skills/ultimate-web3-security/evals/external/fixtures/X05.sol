// Minimal reproducer of Rari Fuse Pool oracle manipulation (Nov 2022).
// Source: https://rekt.news/rari-rekt/ - "Rari Fuse pools lose $10M to price oracle exploit"
//
// Key pattern: single-DEX getReserves used as price oracle for Fuse pool collateral.
// Attacker manipulated Uniswap V2 pool reserves to inflate collateral value, then borrowed.
contract RariFusePool {
    address public uniswapPool;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;

    // BUG: Uniswap V2 getReserves as oracle - manipulable via single swap
    function getCollateralValue(address user) public view returns (uint256) {
        (uint256 reserveIn, uint256 reserveOut) = getReserves(uniswapPool);
        uint256 price = (reserveOut * 1e18) / reserveIn;
        return collateral[user] * price / 1e18;
    }

    function borrow(address user, uint256 amount) external {
        uint256 value = getCollateralValue(user);
        require(value >= amount, "undercollateralized");
        borrowed[user] += amount;
    }

    function getReserves(address pool) internal view returns (uint256, uint256);
}

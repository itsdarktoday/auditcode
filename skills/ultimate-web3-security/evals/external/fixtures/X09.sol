// SAFE: Uniswap V2 TWAP with observation tracking and minimum time window.
// Uses priceCumulative (detected) with observations.length + timeDelta checks.
// Has a borrow() critical action but TWAP resistance is genuine.
contract SafeUniswapV2StaleTwap {
    address public pool;
    uint256 public immutable minObservations;
    uint256 public immutable minTimeDelta;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;

    struct Observation {
        uint256 timestamp;
        uint256 priceCumulative;
    }
    Observation[] public observations;

    // SAFE: TWAP with observation tracking - single-block manipulation diluted
    function getPrice() public view returns (uint256) {
        require(observations.length >= minObservations, "insufficient observations");

        Observation memory first = observations[observations.length - minObservations];
        Observation memory last = observations[observations.length - 1];

        uint256 timeDelta = last.timestamp - first.timestamp;
        require(timeDelta >= minTimeDelta, "time window too short");

        uint256 priceCumDelta = last.priceCumulative - first.priceCumulative;
        return priceCumDelta / timeDelta;
    }

    function borrow(address user, uint256 amount) external {
        uint256 price = getPrice();
        uint256 value = collateral[user] * price / 1e18;
        require(value >= amount, "undercollateralized");
        borrowed[user] += amount;
    }

    function record() external {
        observations.push(
            Observation({
                timestamp: block.timestamp,
                priceCumulative: getPoolPriceCumulative(pool)
            })
        );
    }

    function getPoolPriceCumulative(
        address pool_
    ) internal view returns (uint256);
}

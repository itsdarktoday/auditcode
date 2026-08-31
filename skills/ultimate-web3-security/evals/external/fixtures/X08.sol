// SAFE: Chainlink oracle with staleness check + heartbeat validation.
// This is the recommended pattern for DeFi price feeds.
// NOT manipulable: Chainlink's decentralized oracle network provides
// manipulation-resistant prices, and staleness/heartbeat checks ensure
// freshness.
contract SafeChainlinkOracle {
    AggregatorV3Interface internal priceFeed;
    uint256 public maxStaleness;

    constructor(address feed, uint256 staleness) {
        priceFeed = AggregatorV3Interface(feed);
        maxStaleness = staleness;
    }

    function getPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
        ) = priceFeed.latestRoundData();

        require(roundId > 0, "invalid round");
        require(answer > 0, "invalid price");
        require(
            block.timestamp - updatedAt <= maxStaleness,
            "stale price"
        );

        // Heartbeat: check that price was updated within expected interval
        require(
            block.timestamp - updatedAt <= priceFeed.phaseId() * 3600,
            "heartbeat exceeded"
        );

        return uint256(answer);
    }
}

interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
    function phaseId() external view returns (uint256);
}

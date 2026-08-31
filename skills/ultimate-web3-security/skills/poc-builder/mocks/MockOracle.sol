// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function decimals() external view returns (uint8);
    function description() external view returns (string memory);
    function version() external view returns (uint256);
    function getRoundData(uint80 _roundId)
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
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
}

contract MockOracle is AggregatorV3Interface {
    uint8 public override decimals;
    string public override description;
    uint256 public override version = 1;

    uint80 public mockRoundId = 1;
    int256 public mockAnswer;
    uint256 public mockStartedAt;
    uint256 public mockUpdatedAt;
    uint80 public mockAnsweredInRound = 1;

    constructor(uint8 _decimals, int256 _initialPrice, string memory _desc) {
        decimals = _decimals;
        mockAnswer = _initialPrice;
        description = _desc;
        mockStartedAt = block.timestamp;
        mockUpdatedAt = block.timestamp;
    }

    function setPrice(int256 _newPrice) external {
        mockAnswer = _newPrice;
        mockRoundId++;
        mockAnsweredInRound = mockRoundId;
        mockUpdatedAt = block.timestamp;
    }

    function setStaleTime(uint256 _updatedAt) external {
        mockUpdatedAt = _updatedAt;
    }

    function latestRoundData()
        external
        view
        override
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        )
    {
        return (mockRoundId, mockAnswer, mockStartedAt, mockUpdatedAt, mockAnsweredInRound);
    }

    function getRoundData(uint80 _roundId)
        external
        view
        override
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        )
    {
        return (_roundId, mockAnswer, mockStartedAt, mockUpdatedAt, mockAnsweredInRound);
    }
}

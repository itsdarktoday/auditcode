// Minimal reproducer of Inverse Finance oracle manipulation (June 2022).
// Source: https://rekt.news/inverse-rekt/ - "Inverse Finance hit by $1.2M oracle manipulation"
// Source: https://blog.inverse.finance/exploit-postmortem-2022-06-16
//
// Key pattern: Oracle called latestPrice() on a single Chainlink feed but with NO staleness
// check and NO round validation. The feed's TWAP window was irrelevant - the price was read
// as a single instantaneous value. The attacker manipulated the underlying DEX pool that
// the Chainlink feed referenced, inflating the reported price within one block.
contract InverseOracle {
    address public priceFeed;   // single Chainlink feed - no staleness check
    address public vault;

    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;

    // BUG: reads single feed with no staleness/round validation - manipulable
    function getPrice() public view returns (uint256) {
        // Reads single Chainlink feed - no updatedAt check, no roundId check
        return latestPrice(priceFeed);
    }

    function depositAndBorrow(uint256 depositAmount, uint256 borrowAmount) external {
        deposits[msg.sender] += depositAmount;
        uint256 price = getPrice();
        uint256 collateral = deposits[msg.sender] * price / 1e18;
        require(collateral >= borrowAmount, "insufficient");
        borrows[msg.sender] += borrowAmount;
    }

    function latestPrice(address feed) internal view returns (uint256);
}

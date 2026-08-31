// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// PLANTED BUG: EIP-712 domain omits chainId -> signatures replay across chains.
contract V07_SigReplay {
    address public admin;
    uint256 public nonce;
    constructor() { admin = msg.sender; }
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode("MetaTx", "1", address(this))); // BUG: no chainId, no version change
    }
    function execute(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 full = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), digest));
        address signer = ecrecover(full, v, r, s);
        require(signer == admin, "bad sig");
        nonce += 1; // BUG: nonce not part of signed message -> replay within protocol
    }
}

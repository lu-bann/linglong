// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title Subnetwork
/// @notice Library for handling subnetwork identifiers
/// @dev The subnetwork is a combination of a network address and an identifier
library Subnetwork {
    /// @notice Combines a network address and a subnetwork identifier into a bytes32
    /// @param network The network address
    /// @param identifier The subnetwork identifier
    /// @return subnetwork The combined subnetwork bytes32
    function subnetwork(
        address network,
        uint96 identifier
    )
        internal
        pure
        returns (bytes32)
    {
        return bytes32(uint256(uint160(network)) << 96 | uint256(identifier));
    }

    /// @notice Extracts the network address from a subnetwork bytes32
    /// @param subnetwork The combined subnetwork bytes32
    /// @return network The network address
    function network(bytes32 subnetwork) internal pure returns (address) {
        return address(uint160(uint256(subnetwork) >> 96));
    }

    /// @notice Extracts the identifier from a subnetwork bytes32
    /// @param subnetwork The combined subnetwork bytes32
    /// @return identifier The subnetwork identifier
    function identifier(bytes32 subnetwork) internal pure returns (uint96) {
        return uint96(uint256(subnetwork));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";

// @title OperatorSubsetLib
// @notice Library for handling operator set IDs with embedded protocol type information
// @dev Uses bit manipulation to efficiently encode/decode protocol type in operator set IDs
library OperatorSubsetLib {
    // Reserve the highest 5 bits for protocol type (allows up to 32 protocol types)
    // This leaves 27 bits for the actual operator set ID (supports up to ~134 million sets)
    uint32 private constant PROTOCOL_BITS = 5;
    uint32 private constant PROTOCOL_SHIFT = 27; // 32 - PROTOCOL_BITS
    uint32 private constant PROTOCOL_MASK = 0xF8000000; // Highest 5 bits set
    uint32 private constant ID_MASK = 0x07FFFFFF; // Lowest 27 bits set

    // @notice Encodes a protocol type and base ID into a single ID
    // @param baseId The original operator set ID (must be < 2^27)
    // @param protocol The restaking protocol type
    // @return The encoded operator set ID with protocol information
    function encodeOperatorSetId(
        uint32 baseId,
        ITaiyiRegistryCoordinator.RestakingProtocol protocol
    )
        internal
        pure
        returns (uint32)
    {
        // Ensure baseId doesn't use the reserved bits
        require(baseId <= ID_MASK, "OperatorSubsetLib: ID too large");

        // Convert protocol enum to uint32 and shift to the reserved bits position
        uint32 protocolBits = (uint32(protocol) << PROTOCOL_SHIFT);

        // Combine the protocol bits with the base ID
        return protocolBits | baseId;
    }

    // @notice Decodes an operator set ID to extract the protocol type and base ID
    // @param encodedId The encoded operator set ID
    // @return protocol The restaking protocol type
    // @return baseId The original operator set ID
    function decodeOperatorSetId(uint32 encodedId)
        internal
        pure
        returns (ITaiyiRegistryCoordinator.RestakingProtocol protocol, uint32 baseId)
    {
        // Extract the protocol bits and convert to enum
        protocol =
            ITaiyiRegistryCoordinator.RestakingProtocol(encodedId >> PROTOCOL_SHIFT);

        // Extract the base ID by masking out the protocol bits
        baseId = encodedId & ID_MASK;

        return (protocol, baseId);
    }

    // @notice Gets just the protocol type from an encoded operator set ID
    // @param encodedId The encoded operator set ID
    // @return The restaking protocol type
    function getProtocolType(uint32 encodedId)
        internal
        pure
        returns (ITaiyiRegistryCoordinator.RestakingProtocol)
    {
        return ITaiyiRegistryCoordinator.RestakingProtocol(encodedId >> PROTOCOL_SHIFT);
    }

    // @notice Gets just the base ID from an encoded operator set ID
    // @param encodedId The encoded operator set ID
    // @return The original operator set ID
    function getBaseId(uint32 encodedId) internal pure returns (uint32) {
        return encodedId & ID_MASK;
    }

    // @notice Creates an extended operator set with protocol information
    // @param avs The AVS address
    // @param encodedId The encoded operator set ID
    // @return An operator set with the encoded ID
    function createOperatorSet(
        address avs,
        uint32 encodedId
    )
        internal
        pure
        returns (OperatorSet memory)
    {
        return OperatorSet({ avs: avs, id: encodedId });
    }
}

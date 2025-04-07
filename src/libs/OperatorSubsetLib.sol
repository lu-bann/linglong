// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

/// @title OperatorSubsetLib
/// @notice Library for handling operator set IDs with embedded protocol type information
/// @dev Uses bit manipulation to efficiently encode/decode protocol type in operator set IDs
/// and provides methods to manipulate operator sets
library OperatorSubsetLib {
    using EnumerableSet for EnumerableSet.AddressSet;

    // Reserve the highest 5 bits for protocol type (allows up to 32 protocol types)
    // This leaves 27 bits for the actual operator set ID (supports up to ~134 million sets)
    uint32 private constant PROTOCOL_BITS = 5;
    uint32 private constant PROTOCOL_SHIFT = 27; // 32 - PROTOCOL_BITS
    uint32 private constant PROTOCOL_MASK = 0xF8000000; // Highest 5 bits set
    uint32 private constant ID_MASK = 0x07FFFFFF; // Lowest 27 bits set

    /// @notice Structure to store operator sets with their members
    struct OperatorSets {
        mapping(uint32 => EnumerableSet.AddressSet) sets;
    }

    /// @notice Encodes a protocol type and base ID into a single ID
    /// @param baseId The original operator set ID (must be < 2^27)
    /// @param protocol The restaking protocol type
    /// @return The encoded operator set ID with protocol information
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

    /// @notice Decodes an operator set ID to extract the protocol type and base ID
    /// @param encodedId The encoded operator set ID
    /// @return protocol The restaking protocol type
    /// @return baseId The original operator set ID
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

    /// @notice Gets just the protocol type from an encoded operator set ID
    /// @param encodedId The encoded operator set ID
    /// @return The restaking protocol type
    function getProtocolType(uint32 encodedId)
        internal
        pure
        returns (ITaiyiRegistryCoordinator.RestakingProtocol)
    {
        return ITaiyiRegistryCoordinator.RestakingProtocol(encodedId >> PROTOCOL_SHIFT);
    }

    /// @notice Gets just the base ID from an encoded operator set ID
    /// @param encodedId The encoded operator set ID
    /// @return The original operator set ID
    function getBaseId(uint32 encodedId) internal pure returns (uint32) {
        return encodedId & ID_MASK;
    }

    /// @notice Creates an extended operator set with protocol information
    /// @param avs The AVS address
    /// @param encodedId The encoded operator set ID
    /// @return An operator set with the encoded ID
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

    // ======== OPERATOR SET MANAGEMENT FUNCTIONS ========

    /// @notice Adds an operator to a specific operator set
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set
    /// @param operator The address of the operator to add
    /// @return True if the operator was added, false if already present
    function addOperatorToSet(
        OperatorSets storage operatorSets,
        uint32 operatorSetId,
        address operator
    )
        internal
        returns (bool)
    {
        return operatorSets.sets[operatorSetId].add(operator);
    }

    /// @notice Adds an operator to multiple operator sets at once
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param baseIds Array of base IDs (not encoded) to add the operator to
    /// @param protocol The protocol type to encode with the base IDs
    /// @param operator The address of the operator to add
    function addOperatorToSets(
        OperatorSets storage operatorSets,
        uint32[] memory baseIds,
        ITaiyiRegistryCoordinator.RestakingProtocol protocol,
        address operator
    )
        internal
    {
        for (uint32 i = 0; i < baseIds.length; i++) {
            uint32 encodedId = encodeOperatorSetId(baseIds[i], protocol);
            addOperatorToSet(operatorSets, encodedId, operator);
        }
    }

    /// @notice Removes an operator from a specific operator set
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set
    /// @param operator The address of the operator to remove
    /// @return True if the operator was removed, false if not present
    function removeOperatorFromSet(
        OperatorSets storage operatorSets,
        uint32 operatorSetId,
        address operator
    )
        internal
        returns (bool)
    {
        return operatorSets.sets[operatorSetId].remove(operator);
    }

    /// @notice Removes an operator from multiple operator sets at once
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param baseIds Array of base IDs (not encoded) to remove the operator from
    /// @param protocol The protocol type to encode with the base IDs
    /// @param operator The address of the operator to remove
    function removeOperatorFromSets(
        OperatorSets storage operatorSets,
        uint32[] memory baseIds,
        ITaiyiRegistryCoordinator.RestakingProtocol protocol,
        address operator
    )
        internal
    {
        for (uint32 i = 0; i < baseIds.length; i++) {
            uint32 encodedId = encodeOperatorSetId(baseIds[i], protocol);
            removeOperatorFromSet(operatorSets, encodedId, operator);
        }
    }

    /// @notice Checks if an operator is in a specific operator set
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set
    /// @param operator The address of the operator to check
    /// @return True if the operator is in the set, false otherwise
    function isOperatorInSet(
        OperatorSets storage operatorSets,
        uint32 operatorSetId,
        address operator
    )
        internal
        view
        returns (bool)
    {
        return operatorSets.sets[operatorSetId].contains(operator);
    }

    /// @notice Gets all operators in a specific operator set
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set
    /// @return Array of operator addresses in the set
    function getOperatorsInSet(
        OperatorSets storage operatorSets,
        uint32 operatorSetId
    )
        internal
        view
        returns (address[] memory)
    {
        return operatorSets.sets[operatorSetId].values();
    }

    /// @notice Gets the number of operators in a specific operator set
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set
    /// @return The number of operators in the set
    function getOperatorSetLength(
        OperatorSets storage operatorSets,
        uint32 operatorSetId
    )
        internal
        view
        returns (uint256)
    {
        return operatorSets.sets[operatorSetId].length();
    }

    /// @notice Gets an operator from a set by index
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set
    /// @param index The index of the operator to retrieve
    /// @return The operator address at the given index
    function getOperatorAt(
        OperatorSets storage operatorSets,
        uint32 operatorSetId,
        uint256 index
    )
        internal
        view
        returns (address)
    {
        return operatorSets.sets[operatorSetId].at(index);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @title OperatorSubsetLib
/// @notice Library for handling operator set IDs with embedded protocol type information
/// @dev Uses bit manipulation to efficiently encode/decode protocol type in operator set IDs
/// and provides methods to manipulate operator sets
library OperatorSubsetLib {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.UintSet;

    // Constants for uint96 encoding (5 bits protocol, 91 bits baseId)
    // Reserve the highest 5 bits for protocol type (allows up to 32 protocol types)
    // This leaves 91 bits for the actual operator set ID
    uint8 private constant PROTOCOL_BITS = 5;
    uint8 private constant PROTOCOL_SHIFT_96 = 91; // 96 - PROTOCOL_BITS
    uint96 private constant PROTOCOL_MASK_96 =
        (uint96(1) << PROTOCOL_BITS) - 1 << PROTOCOL_SHIFT_96; // Generates mask dynamically e.g., 0xF800...00
    uint96 private constant ID_MASK_96 = (uint96(1) << PROTOCOL_SHIFT_96) - 1; // Generates mask for lowest 91 bits e.g., 0x07FF...FF

    // Constants for uint32 encoding (5 bits protocol, 27 bits baseId)
    uint8 private constant PROTOCOL_SHIFT_32 = 27; // 32 - PROTOCOL_BITS
    uint32 private constant PROTOCOL_MASK_32 = 0xF8000000; // Highest 5 bits set
    uint32 private constant ID_MASK_32 = 0x07FFFFFF; // Lowest 27 bits set

    error OperatorSetLib__OperatorSetDoesNotExist();
    error OperatorSetLib__IdTooLarge();
    error OperatorSetLib__IdTooLarge32();

    /// @notice Structure to store operator sets with their members
    struct OperatorSets {
        EnumerableSet.UintSet operatorSetIds96; // For 96-bit IDs
        EnumerableSet.UintSet operatorSetIds32; // For 32-bit IDs
        // set id to operator address mapping for 96-bit IDs
        mapping(uint96 => EnumerableSet.AddressSet) sets96;
        // set id to operator address mapping for 32-bit IDs
        mapping(uint32 => EnumerableSet.AddressSet) sets32;
    }

    /// @notice Encodes a protocol type and base ID into a single ID using uint96 (5 bits protocol, 91 bits baseId)
    /// @dev Uses uint96 for larger operator set IDs
    /// @param baseId The original operator set ID (must be < 2^91)
    /// @param protocol The restaking protocol type
    /// @return The encoded operator set ID with protocol information as uint96
    function encodeOperatorSetId96(
        uint96 baseId,
        ITaiyiRegistryCoordinator.RestakingProtocol protocol
    )
        internal
        pure
        returns (uint96)
    {
        // Ensure baseId doesn't use the reserved bits
        if (baseId > ID_MASK_96) {
            revert OperatorSetLib__IdTooLarge();
        }

        // Convert protocol enum to uint96 and shift to the reserved bits position
        uint96 protocolBits = (uint96(uint8(protocol)) << PROTOCOL_SHIFT_96);

        // Combine the protocol bits with the base ID
        return protocolBits | baseId;
    }

    /// @notice Encodes a protocol type and base ID into a single ID using uint32 (5 bits protocol, 27 bits baseId)
    /// @dev Uses uint32 for smaller operator set IDs
    /// @param baseId The original operator set ID (must be < 2^27)
    /// @param protocol The restaking protocol type
    /// @return The encoded operator set ID with protocol information as uint32
    function encodeOperatorSetId32(
        uint32 baseId,
        ITaiyiRegistryCoordinator.RestakingProtocol protocol
    )
        internal
        pure
        returns (uint32)
    {
        // Ensure baseId doesn't use the reserved bits
        if (baseId > ID_MASK_32) {
            revert OperatorSetLib__IdTooLarge32();
        }

        // Convert protocol enum to uint32 and shift to the reserved bits position
        uint32 protocolBits = (uint32(uint8(protocol)) << PROTOCOL_SHIFT_32);

        // Combine the protocol bits with the base ID
        return protocolBits | baseId;
    }

    /// @notice Encodes a protocol type and base ID into a single ID using uint32 for IAVSRegistrar compatibility
    /// @dev Special version that constrains both the protocol and base ID to ensure the result fits in uint32
    /// @param baseId The original operator set ID (must be < 2^27)
    /// @param protocol The restaking protocol type
    /// @return The encoded operator set ID with protocol information as uint32, safe for IAVSRegistrar
    function encodeOperatorSetIdForIAVS(
        uint96 baseId,
        ITaiyiRegistryCoordinator.RestakingProtocol protocol
    )
        internal
        pure
        returns (uint32)
    {
        // For IAVSRegistrar compatibility, we must ensure the base ID is small
        // Limit to 27 bits (2^27-1 = 134,217,727) to leave room for protocol
        if (baseId > ID_MASK_32) {
            revert OperatorSetLib__IdTooLarge32();
        }

        // Convert protocol enum to uint32 and shift to the reserved bits position
        uint32 protocolBits = (uint32(uint8(protocol)) << PROTOCOL_SHIFT_32);

        // Combine the protocol bits with the base ID
        return protocolBits | uint32(baseId);
    }

    /// @notice Decodes a uint96 operator set ID to extract the protocol type and base ID
    /// @dev Works with uint96 encoded IDs (5 bits protocol, 91 bits baseId)
    /// @param encodedId The encoded operator set ID as uint96
    /// @return protocol The restaking protocol type
    /// @return baseId The original operator set ID as uint96
    function decodeOperatorSetId96(uint96 encodedId)
        internal
        pure
        returns (ITaiyiRegistryCoordinator.RestakingProtocol protocol, uint96 baseId)
    {
        // Extract the protocol bits and convert to enum
        protocol = ITaiyiRegistryCoordinator.RestakingProtocol(
            uint8(encodedId >> PROTOCOL_SHIFT_96)
        );

        // Extract the base ID by masking out the protocol bits
        baseId = encodedId & ID_MASK_96;

        return (protocol, baseId);
    }

    /// @notice Decodes a uint32 operator set ID to extract the protocol type and base ID
    /// @dev Works with uint32 encoded IDs (5 bits protocol, 27 bits baseId)
    /// @param encodedId The encoded operator set ID as uint32
    /// @return protocol The restaking protocol type
    /// @return baseId The original operator set ID as uint32
    function decodeOperatorSetId32(uint32 encodedId)
        internal
        pure
        returns (ITaiyiRegistryCoordinator.RestakingProtocol protocol, uint32 baseId)
    {
        // Extract the protocol bits and convert to enum
        protocol = ITaiyiRegistryCoordinator.RestakingProtocol(
            uint8(encodedId >> PROTOCOL_SHIFT_32)
        );

        // Extract the base ID by masking out the protocol bits
        baseId = encodedId & ID_MASK_32;

        return (protocol, baseId);
    }

    /// @notice Decodes an encoded uint32 operator set ID back to its original uint96 baseId
    /// @dev Extracts the baseId part from the encoded ID, removing protocol information
    /// @param encodedId The encoded operator set ID with protocol information
    /// @return The original baseId as uint96
    function decodeOperatorSetIdFromIAVS(uint32 encodedId)
        internal
        pure
        returns (uint96)
    {
        // Extract only the baseId bits by masking out the protocol bits
        return uint96(encodedId & ID_MASK_32);
    }

    /// @notice Gets just the protocol type from a uint96 encoded operator set ID
    /// @dev Works with uint96 encoded IDs (5 bits protocol, 91 bits baseId)
    /// @param encodedId The encoded operator set ID as uint96
    /// @return The restaking protocol type
    function getProtocolType96(uint96 encodedId)
        internal
        pure
        returns (ITaiyiRegistryCoordinator.RestakingProtocol)
    {
        return ITaiyiRegistryCoordinator.RestakingProtocol(
            uint8(encodedId >> PROTOCOL_SHIFT_96)
        );
    }

    /// @notice Gets just the protocol type from a uint32 encoded operator set ID
    /// @dev Works with uint32 encoded IDs (5 bits protocol, 27 bits baseId)
    /// @param encodedId The encoded operator set ID as uint32
    /// @return The restaking protocol type
    function getProtocolType32(uint32 encodedId)
        internal
        pure
        returns (ITaiyiRegistryCoordinator.RestakingProtocol)
    {
        return ITaiyiRegistryCoordinator.RestakingProtocol(
            uint8(encodedId >> PROTOCOL_SHIFT_32)
        );
    }

    /// @notice Gets just the base ID from a uint96 encoded operator set ID
    /// @dev Works with uint96 encoded IDs (5 bits protocol, 91 bits baseId)
    /// @param encodedId The encoded operator set ID as uint96
    /// @return The original operator set ID as uint96
    function getBaseId96(uint96 encodedId) internal pure returns (uint96) {
        return encodedId & ID_MASK_96;
    }

    /// @notice Gets just the base ID from a uint32 encoded operator set ID
    /// @dev Works with uint32 encoded IDs (5 bits protocol, 27 bits baseId)
    /// @param encodedId The encoded operator set ID as uint32
    /// @return The original operator set ID as uint32
    function getBaseId32(uint32 encodedId) internal pure returns (uint32) {
        return encodedId & ID_MASK_32;
    }

    /// @notice Creates an extended operator set with protocol information using uint96 ID
    /// @dev Uses uint96 for larger operator set IDs
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param encodedId The encoded operator set ID as uint96
    /// @return Success boolean
    function createOperatorSet96(
        OperatorSets storage operatorSets,
        uint96 encodedId
    )
        internal
        returns (bool)
    {
        return operatorSets.operatorSetIds96.add(uint256(encodedId));
    }

    /// @notice Creates an extended operator set with protocol information using uint32 ID
    /// @dev Uses uint32 for smaller operator set IDs
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param encodedId The encoded operator set ID as uint32
    /// @return Success boolean
    function createOperatorSet32(
        OperatorSets storage operatorSets,
        uint32 encodedId
    )
        internal
        returns (bool)
    {
        return operatorSets.operatorSetIds32.add(uint256(encodedId));
    }

    // ======== OPERATOR SET MANAGEMENT FUNCTIONS ========

    /// @notice Adds an operator to a specific operator set using uint96 ID
    /// @dev Works with uint96 encoded operator set IDs
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set as uint96
    /// @param operator The address of the operator to add
    /// @return True if the operator was added, false if already present
    function addOperatorToSet96(
        OperatorSets storage operatorSets,
        uint96 operatorSetId,
        address operator
    )
        internal
        returns (bool)
    {
        if (operatorSets.operatorSetIds96.contains(uint256(operatorSetId))) {
            return operatorSets.sets96[operatorSetId].add(operator);
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    /// @notice Adds an operator to a specific operator set using uint32 ID
    /// @dev Works with uint32 encoded operator set IDs
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set as uint32
    /// @param operator The address of the operator to add
    /// @return True if the operator was added, false if already present
    function addOperatorToSet32(
        OperatorSets storage operatorSets,
        uint32 operatorSetId,
        address operator
    )
        internal
        returns (bool)
    {
        if (operatorSets.operatorSetIds32.contains(uint256(operatorSetId))) {
            return operatorSets.sets32[operatorSetId].add(operator);
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    /// @notice Adds an operator to multiple operator sets at once using uint96 IDs
    /// @dev Works with uint96 base IDs and encoded IDs
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetIds Array of operator set IDs as uint96[] (encoded)
    /// @param protocol The protocol type to encode with the base IDs
    /// @param operator The address of the operator to add
    function addOperatorToSets96(
        OperatorSets storage operatorSets,
        uint96[] memory operatorSetIds,
        ITaiyiRegistryCoordinator.RestakingProtocol protocol,
        address operator
    )
        internal
    {
        for (uint256 i = 0; i < operatorSetIds.length; i++) {
            addOperatorToSet96(operatorSets, operatorSetIds[i], operator);
        }
    }

    /// @notice Adds an operator to multiple operator sets at once using uint32 IDs
    /// @dev Works with uint32 base IDs and encoded IDs
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetIds Array of operator set IDs as uint32[] (not encoded)
    /// @param protocol The protocol type to encode with the base IDs
    /// @param operator The address of the operator to add
    function addOperatorToSets32(
        OperatorSets storage operatorSets,
        uint32[] memory operatorSetIds,
        ITaiyiRegistryCoordinator.RestakingProtocol protocol,
        address operator
    )
        internal
    {
        for (uint256 i = 0; i < operatorSetIds.length; i++) {
            addOperatorToSet32(operatorSets, operatorSetIds[i], operator);
        }
    }

    /// @notice Removes an operator from a specific operator set
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set
    /// @param operator The address of the operator to remove
    /// @return True if the operator was removed, false if not present
    function removeOperatorFromSet96(
        OperatorSets storage operatorSets,
        uint96 operatorSetId,
        address operator
    )
        internal
        returns (bool)
    {
        if (operatorSets.operatorSetIds96.contains(uint256(operatorSetId))) {
            return operatorSets.sets96[operatorSetId].remove(operator);
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    /// @notice Removes an operator from a specific operator set
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set
    /// @param operator The address of the operator to remove
    /// @return True if the operator was removed, false if not present
    function removeOperatorFromSet32(
        OperatorSets storage operatorSets,
        uint32 operatorSetId,
        address operator
    )
        internal
        returns (bool)
    {
        if (operatorSets.operatorSetIds32.contains(uint256(operatorSetId))) {
            return operatorSets.sets32[operatorSetId].remove(operator);
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    /// @notice Removes an operator from multiple operator sets at once
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param baseIds Array of base IDs (not encoded) to remove the operator from
    /// @param protocol The protocol type to encode with the base IDs
    /// @param operator The address of the operator to remove
    function removeOperatorFromSets96(
        OperatorSets storage operatorSets,
        uint96[] memory baseIds,
        ITaiyiRegistryCoordinator.RestakingProtocol protocol,
        address operator
    )
        internal
    {
        for (uint256 i = 0; i < baseIds.length; i++) {
            uint96 encodedId = encodeOperatorSetId96(baseIds[i], protocol);
            removeOperatorFromSet96(operatorSets, encodedId, operator);
        }
    }

    /// @notice Removes an operator from multiple operator sets at once
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param baseIds Array of base IDs (not encoded) to remove the operator from
    /// @param protocol The protocol type to encode with the base IDs
    /// @param operator The address of the operator to remove
    function removeOperatorFromSets32(
        OperatorSets storage operatorSets,
        uint32[] memory baseIds,
        ITaiyiRegistryCoordinator.RestakingProtocol protocol,
        address operator
    )
        internal
    {
        for (uint256 i = 0; i < baseIds.length; i++) {
            uint32 encodedId = encodeOperatorSetId32(baseIds[i], protocol);
            removeOperatorFromSet32(operatorSets, encodedId, operator);
        }
    }

    /// @notice Checks if an operator is in a specific operator set
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set
    /// @param operator The address of the operator to check
    /// @return True if the operator is in the set, false otherwise
    function isOperatorInSet96(
        OperatorSets storage operatorSets,
        uint96 operatorSetId,
        address operator
    )
        internal
        view
        returns (bool)
    {
        if (operatorSets.operatorSetIds96.contains(uint256(operatorSetId))) {
            return operatorSets.sets96[operatorSetId].contains(operator);
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    /// @notice Checks if an operator is in a specific operator set
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set
    /// @param operator The address of the operator to check
    /// @return True if the operator is in the set, false otherwise
    function isOperatorInSet32(
        OperatorSets storage operatorSets,
        uint32 operatorSetId,
        address operator
    )
        internal
        view
        returns (bool)
    {
        if (operatorSets.operatorSetIds32.contains(uint256(operatorSetId))) {
            return operatorSets.sets32[operatorSetId].contains(operator);
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    /// @notice Gets all operators in a specific operator set using uint96 ID
    /// @dev Works with uint96 encoded operator set IDs
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set as uint96
    /// @return Array of operator addresses in the set
    function getOperatorsInSet96(
        OperatorSets storage operatorSets,
        uint96 operatorSetId
    )
        internal
        view
        returns (address[] memory)
    {
        if (operatorSets.operatorSetIds96.contains(uint256(operatorSetId))) {
            return operatorSets.sets96[operatorSetId].values();
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    /// @notice Gets all operators in a specific operator set using uint32 ID
    /// @dev Works with uint32 encoded operator set IDs
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set as uint32
    /// @return Array of operator addresses in the set
    function getOperatorsInSet32(
        OperatorSets storage operatorSets,
        uint32 operatorSetId
    )
        internal
        view
        returns (address[] memory)
    {
        if (operatorSets.operatorSetIds32.contains(uint256(operatorSetId))) {
            return operatorSets.sets32[operatorSetId].values();
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    /// @notice Gets all operator sets that an operator has allocated to
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operator The address of the operator to check
    /// @return Array of operator sets that the operator has allocated magnitude to
    function getOperatorSetsFromOperator96(
        OperatorSets storage operatorSets,
        address operator
    )
        internal
        view
        returns (uint96[] memory)
    {
        uint256[] memory rawValues = operatorSets.operatorSetIds96.values();
        uint96[] memory result = new uint96[](rawValues.length);
        for (uint256 i = 0; i < rawValues.length; i++) {
            uint96 operatorSetId = SafeCast.toUint96(rawValues[i]);
            if (isOperatorInSet96(operatorSets, operatorSetId, operator)) {
                result[i] = operatorSetId;
            }
        }
        return result;
    }

    /// @notice Gets the number of operators in a specific operator set
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set
    /// @return The number of operators in the set
    function getOperatorSetLength96(
        OperatorSets storage operatorSets,
        uint96 operatorSetId
    )
        internal
        view
        returns (uint256)
    {
        if (operatorSets.operatorSetIds96.contains(uint256(operatorSetId))) {
            return operatorSets.sets96[operatorSetId].length();
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    /// @notice Gets the number of operators in a specific operator set
    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set
    /// @return The number of operators in the set
    function getOperatorSetLength32(
        OperatorSets storage operatorSets,
        uint32 operatorSetId
    )
        internal
        view
        returns (uint256)
    {
        if (operatorSets.operatorSetIds32.contains(uint256(operatorSetId))) {
            return operatorSets.sets32[operatorSetId].length();
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    /// @notice Gets all operator sets
    /// @param operatorSets The storage reference to operator sets mapping
    /// @return Array of operator set IDs
    function getOperatorSets96(OperatorSets storage operatorSets)
        internal
        view
        returns (uint96[] memory)
    {
        uint256[] memory rawValues = operatorSets.operatorSetIds96.values();
        uint96[] memory result = new uint96[](rawValues.length);
        for (uint256 i = 0; i < rawValues.length; i++) {
            result[i] = SafeCast.toUint96(rawValues[i]);
        }
        return result;
    }

    /// @notice Gets all operator sets
    /// @param operatorSets The storage reference to operator sets mapping
    /// @return Array of operator set IDs
    function getOperatorSets32(OperatorSets storage operatorSets)
        internal
        view
        returns (uint32[] memory)
    {
        uint256[] memory rawValues = operatorSets.operatorSetIds32.values();
        uint32[] memory result = new uint32[](rawValues.length);
        for (uint256 i = 0; i < rawValues.length; i++) {
            result[i] = SafeCast.toUint32(rawValues[i]);
        }
        return result;
    }

    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set
    /// @param index The index of the operator to retrieve
    /// @return The operator address at the given index
    function getOperatorAt96(
        OperatorSets storage operatorSets,
        uint96 operatorSetId,
        uint256 index
    )
        internal
        view
        returns (address)
    {
        if (operatorSets.operatorSetIds96.contains(uint256(operatorSetId))) {
            return operatorSets.sets96[operatorSetId].at(index);
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    /// @param operatorSets The storage reference to operator sets mapping
    /// @param operatorSetId The encoded ID of the operator set
    /// @param index The index of the operator to retrieve
    /// @return The operator address at the given index
    function getOperatorAt32(
        OperatorSets storage operatorSets,
        uint32 operatorSetId,
        uint256 index
    )
        internal
        view
        returns (address)
    {
        if (operatorSets.operatorSetIds32.contains(uint256(operatorSetId))) {
            return operatorSets.sets32[operatorSetId].at(index);
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }
}

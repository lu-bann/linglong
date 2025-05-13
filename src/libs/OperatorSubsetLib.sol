// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @title OperatorSubsetLib
/// @notice Library for handling linglong subset IDs with embedded protocol type information
/// @dev Uses bit manipulation to efficiently encode/decode protocol type in linglong subset IDs
/// and provides methods to manipulate linglong subsets
library OperatorSubsetLib {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.UintSet;

    error OperatorSetLib__OperatorSetDoesNotExist();

    // the below are the available linglong subset id
    uint32 constant EIGENLAYER_VALIDATOR_SUBSET_ID = 0;
    uint32 constant EIGENLAYER_UNDERWRITER_SUBSET_ID = 1;
    uint32 constant SYMBIOTIC_VALIDATOR_SUBSET_ID = 2;
    uint32 constant SYMBIOTIC_UNDERWRITER_SUBSET_ID = 3;

    /// @notice Structure to store linglong subsets with their members
    struct LinglongSubsets {
        // linglong subset id
        EnumerableSet.UintSet linglongSubsetIds;
        // linglong subset id => subset members
        mapping(uint32 => EnumerableSet.AddressSet) operatorSetMembers;
        // linglong subset id => subset min stake
        mapping(uint32 => uint256) minStake;
    }

    function isEigenlayerProtocolID(uint32 linglongSubsetId)
        internal
        pure
        returns (bool)
    {
        return linglongSubsetId == EIGENLAYER_VALIDATOR_SUBSET_ID
            || linglongSubsetId == EIGENLAYER_UNDERWRITER_SUBSET_ID;
    }

    function isSymbioticProtocolID(uint32 linglongSubsetId)
        internal
        pure
        returns (bool)
    {
        return linglongSubsetId == SYMBIOTIC_VALIDATOR_SUBSET_ID
            || linglongSubsetId == SYMBIOTIC_UNDERWRITER_SUBSET_ID;
    }
    /// @notice Creates a linglong subset with protocol information using uint32 ID
    /// @dev Uses uint32 for linglong subset IDs
    /// @param linglongSubsets The storage reference to linglong subsets mapping
    /// @param linglongSubsetId The linglong subset ID as uint32
    /// @param minStake The minimum stake required for this subset
    /// @return Success boolean

    function createLinglongSubset(
        LinglongSubsets storage linglongSubsets,
        uint32 linglongSubsetId,
        uint256 minStake
    )
        internal
        returns (bool)
    {
        linglongSubsets.minStake[linglongSubsetId] = minStake;
        return linglongSubsets.linglongSubsetIds.add(linglongSubsetId);
    }

    // ======== LINGLONG SUBSET MANAGEMENT FUNCTIONS ========

    /// @notice Adds an operator to a specific linglong subset using uint32 ID
    /// @dev Works with uint32 linglong subset IDs
    /// @param linglongSubsets The storage reference to linglong subsets mapping
    /// @param linglongSubsetId The ID of the linglong subset as uint32
    /// @param operator The address of the operator to add
    /// @return True if the operator was added, false if already present
    function addOperatorToLinglongSubset(
        LinglongSubsets storage linglongSubsets,
        uint32 linglongSubsetId,
        address operator
    )
        internal
        returns (bool)
    {
        if (linglongSubsets.linglongSubsetIds.contains(linglongSubsetId)) {
            return linglongSubsets.operatorSetMembers[linglongSubsetId].add(operator);
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    function isLinglongSubsetIdCreated(
        LinglongSubsets storage linglongSubsets,
        uint32 linglongSubsetId
    )
        internal
        view
        returns (bool)
    {
        return linglongSubsets.linglongSubsetIds.contains(linglongSubsetId);
    }

    /// @notice Adds an operator to multiple linglong subsets at once using uint32 IDs
    /// @dev Works with uint32 IDs
    /// @param linglongSubsets The storage reference to linglong subsets mapping
    /// @param linglongSubsetIds Array of linglong subset IDs as uint32[]
    /// @param operator The address of the operator to add
    function addOperatorToLinglongSubsets(
        LinglongSubsets storage linglongSubsets,
        uint32[] memory linglongSubsetIds,
        address operator
    )
        internal
    {
        for (uint256 i = 0; i < linglongSubsetIds.length; i++) {
            addOperatorToLinglongSubset(linglongSubsets, linglongSubsetIds[i], operator);
        }
    }

    /// @notice Removes an operator from a specific linglong subset
    /// @param linglongSubsets The storage reference to linglong subsets mapping
    /// @param linglongSubsetId The ID of the linglong subset
    /// @param operator The address of the operator to remove
    /// @return True if the operator was removed, false if not present
    function removeOperatorFromLinglongSubset(
        LinglongSubsets storage linglongSubsets,
        uint32 linglongSubsetId,
        address operator
    )
        internal
        returns (bool)
    {
        if (linglongSubsets.linglongSubsetIds.contains(linglongSubsetId)) {
            return linglongSubsets.operatorSetMembers[linglongSubsetId].remove(operator);
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    /// @notice Removes an operator from multiple linglong subsets at once
    /// @param linglongSubsets The storage reference to linglong subsets mapping
    /// @param linglongSubsetIds Array of linglong subset IDs to remove the operator from
    /// @param operator The address of the operator to remove
    function removeOperatorFromLinglongSubsets(
        LinglongSubsets storage linglongSubsets,
        uint32[] memory linglongSubsetIds,
        address operator
    )
        internal
    {
        for (uint256 i = 0; i < linglongSubsetIds.length; i++) {
            removeOperatorFromLinglongSubset(
                linglongSubsets, linglongSubsetIds[i], operator
            );
        }
    }

    /// @notice Checks if an operator is in a specific linglong subset
    /// @param linglongSubsets The storage reference to linglong subsets mapping
    /// @param linglongSubsetId The ID of the linglong subset
    /// @param operator The address of the operator to check
    /// @return True if the operator is in the subset, false otherwise
    function isOperatorInLinglongSubset(
        LinglongSubsets storage linglongSubsets,
        uint32 linglongSubsetId,
        address operator
    )
        internal
        view
        returns (bool)
    {
        if (linglongSubsets.linglongSubsetIds.contains(linglongSubsetId)) {
            return linglongSubsets.operatorSetMembers[linglongSubsetId].contains(operator);
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    /// @notice Gets all operators in a specific linglong subset using uint32 ID
    /// @dev Works with uint32 linglong subset IDs
    /// @param linglongSubsets The storage reference to linglong subsets mapping
    /// @param linglongSubsetId The ID of the linglong subset as uint32
    /// @return Array of operator addresses in the subset
    function getOperatorsInLinglongSubset(
        LinglongSubsets storage linglongSubsets,
        uint32 linglongSubsetId
    )
        internal
        view
        returns (address[] memory)
    {
        if (linglongSubsets.linglongSubsetIds.contains(linglongSubsetId)) {
            return linglongSubsets.operatorSetMembers[linglongSubsetId].values();
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    /// @notice Gets all linglong subsets that an operator has allocated to
    /// @param linglongSubsets The storage reference to linglong subsets mapping
    /// @param operator The address of the operator to check
    /// @return Array of linglong subsets that the operator has allocated magnitude to
    function getLinglongSubsetsFromOperator(
        LinglongSubsets storage linglongSubsets,
        address operator
    )
        internal
        view
        returns (uint32[] memory)
    {
        uint256[] memory rawValues = linglongSubsets.linglongSubsetIds.values();
        uint32[] memory result = new uint32[](rawValues.length);
        for (uint256 i = 0; i < rawValues.length; i++) {
            uint32 linglongSubsetId = SafeCast.toUint32(rawValues[i]);
            if (isOperatorInLinglongSubset(linglongSubsets, linglongSubsetId, operator)) {
                result[i] = linglongSubsetId;
            }
        }
        return result;
    }

    /// @notice Gets the number of operators in a specific linglong subset
    /// @param linglongSubsets The storage reference to linglong subsets mapping
    /// @param linglongSubsetId The ID of the linglong subset
    /// @return The number of operators in the subset
    function getLinglongSubsetLength(
        LinglongSubsets storage linglongSubsets,
        uint32 linglongSubsetId
    )
        internal
        view
        returns (uint256)
    {
        if (linglongSubsets.linglongSubsetIds.contains(linglongSubsetId)) {
            return linglongSubsets.operatorSetMembers[linglongSubsetId].length();
        } else {
            revert OperatorSetLib__OperatorSetDoesNotExist();
        }
    }

    /* ========== MIN STAKE HELPERS ========== */

    /// @notice Returns the minimum stake required for a linglong subset
    function getMinStake(
        LinglongSubsets storage linglongSubsets,
        uint32 linglongSubsetId
    )
        internal
        view
        returns (uint256)
    {
        return linglongSubsets.minStake[linglongSubsetId];
    }
}

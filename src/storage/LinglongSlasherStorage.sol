// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ILinglongSlasher } from "../interfaces/ILinglongSlasher.sol";
import { IAllocationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/// @title LinglongSlasherStorage
/// @notice Storage contract for LinglongSlasher
abstract contract LinglongSlasherStorage is ILinglongSlasher {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @notice Common/predefined violation types
    bytes32 public constant VIOLATION_TYPE_NONE = bytes32(0);

    /// @notice Address of the EigenLayer middleware contract
    address public EIGENLAYER_MIDDLEWARE;

    /// @notice Address of the Symbiotic middleware contract
    address public SYMBIOTIC_MIDDLEWARE;

    /// @notice Address of the Taiyi Registry Coordinator contract
    address public TAIYI_REGISTRY_COORDINATOR;

    /// @notice Address of the allocation manager
    address public ALLOCATION_MANAGER;

    /// @notice Mapping to track commitments that have been slashed
    mapping(bytes32 => bool) public slashedCommitments;

    /// @notice Set of registered challenger implementations
    EnumerableSet.AddressSet internal registeredChallengers;

    /// @notice Mapping from challenger address to its implementation details
    mapping(address => ILinglongSlasher.ChallengerImpl) public challengerImpls;

    /// @notice Mapping from violation type to challenger implementations that support it
    mapping(bytes32 => address) internal violationTypeChallengers;

    /// @notice Mapping from URC commitment type to violation type
    mapping(uint64 => bytes32) public URCCommitmentTypeToViolationType;

    /// @notice Set of registered violation types
    EnumerableSet.Bytes32Set internal registeredViolationTypes;
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { DelegationStore } from "./DelegationStore.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

/// @title SymbioticNetworkStorage
/// @notice Storage contract for SymbioticNetworkMiddleware
abstract contract SymbioticNetworkStorage {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @notice Subnetwork ID for validators
    uint96 internal constant VALIDATOR_SUBNETWORK = 0;

    /// @notice Subnetwork ID for underwriters
    uint96 internal constant UNDERWRITER_SUBNETWORK = 1;

    /// @notice Registry contract reference
    address public REGISTRY;

    /// @notice Owner of the contract
    address public owner;

    /// @notice Total count of subnetworks
    uint96 public SUBNETWORK_COUNT;

    /// @notice Registry coordinator contract reference
    ITaiyiRegistryCoordinator public REGISTRY_COORDINATOR;

    /// @notice Store validation registrations by operator
    mapping(address => mapping(bytes32 => DelegationStore)) internal operatorDelegations;

    /// @notice Keep track of registration roots for each operator
    mapping(address => EnumerableSet.Bytes32Set) internal operatorRegistrationRoots;

    uint256[50] private __GAP;
}

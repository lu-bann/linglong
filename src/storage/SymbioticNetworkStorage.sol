// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";

import { DelegationStore } from "./DelegationStore.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { EnumerableMapLib } from "@solady/utils/EnumerableMapLib.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { Registry } from "@urc/Registry.sol";

/// @title SymbioticNetworkStorage
/// @notice Storage contract for SymbioticNetworkMiddleware
abstract contract SymbioticNetworkStorage {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMapLib for EnumerableMapLib.Uint256ToBytes32Map;

    /// @notice Registry contract reference
    Registry public REGISTRY;

    /// @notice Store validation registrations by operator
    mapping(address => mapping(bytes32 => DelegationStore)) internal operatorDelegations;

    /// @notice Keep track of registration roots for each operator
    mapping(address => EnumerableSet.Bytes32Set) internal operatorRegistrationRoots;

    /// @notice Registry coordinator contract reference
    ITaiyiRegistryCoordinator public REGISTRY_COORDINATOR;

    /// @notice Subnetwork ID for validators
    uint96 public constant VALIDATOR_SUBNETWORK = 0;

    /// @notice Subnetwork ID for underwriters
    uint96 public constant UNDERWRITER_SUBNETWORK = 1;

    /// @notice Total count of subnetworks
    uint96 public SUBNETWORK_COUNT;
}

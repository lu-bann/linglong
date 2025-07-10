// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";

import { DelegationStore } from "../types/CommonTypes.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { IRegistry } from "@urc/IRegistry.sol";

/// @title SSVBasedAppMiddlewareStorage
/// @notice Storage contract for SSV-based application middleware
/// @dev Contains all storage variables for the SSV middleware contract
abstract contract SSVBasedAppMiddlewareStorage {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // ==============================================================================================
    // ================================= IMMUTABLE VARIABLES =======================================
    // ==============================================================================================

    /// @notice Address of the Taiyi Registry Coordinator
    ITaiyiRegistryCoordinator public REGISTRY_COORDINATOR;

    /// @notice Address of the URC Registry contract
    address public REGISTRY;

    /// @notice Address of the Linglong Slasher contract
    address public SLASHER;

    /// @notice Address of the gateway operator set for SSV delegation
    address public GATEWAY_OPERATOR_SET;

    /// @notice Address of the gateway network for SSV delegation
    address public GATEWAY_NETWORK;

    /// @notice Minimum collateral required for validator registration
    uint256 public REGISTRATION_MIN_COLLATERAL;

    // ==============================================================================================
    // ================================= STORAGE VARIABLES =========================================
    // ==============================================================================================

    /// @notice Mapping from operator address to registration root to delegation store
    /// @dev Stores all delegation information for each operator's registration
    mapping(address => mapping(bytes32 => DelegationStore)) internal operatorDelegations;

    /// @notice Mapping from operator address to set of their registration roots
    /// @dev Tracks all registration roots owned by each operator
    mapping(address => EnumerableSet.Bytes32Set) internal operatorRegistrationRoots;

    /// @notice Mapping from operator to their gateway delegation status
    /// @dev Tracks whether an operator has opted into gateway delegation
    mapping(address => bool) public operatorGatewayDelegationStatus;

    /// @notice Mapping from operator to their gateway operator address
    /// @dev Stores the gateway operator each operator has delegated to
    mapping(address => address) public operatorGatewayOperator;

    /// @notice Mapping from operator to their gateway network address
    /// @dev Stores the gateway network each operator has delegated to
    mapping(address => address) public operatorGatewayNetwork;

    // Config struct is defined in ISsvBasedAppMiddleware interface

    // ==============================================================================================
    // ================================= STORAGE GAPS =============================================
    // ==============================================================================================

    /// @notice Storage gap for future contract upgrades
    /// @dev Reserve space for future storage variables
    uint256[44] private __gap;
}

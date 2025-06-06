// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IEigenLayerMiddleware } from "../interfaces/IEigenLayerMiddleware.sol";

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";

import { DelegationStore } from "../types/CommonTypes.sol";
import { DelegationManager } from
    "@eigenlayer-contracts/src/contracts/core/DelegationManager.sol";
import { StrategyManager } from
    "@eigenlayer-contracts/src/contracts/core/StrategyManager.sol";
import { IAVSDirectory } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAVSDirectory.sol";
import { IEigenPodManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IEigenPodManager.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

import { IRegistry } from "@urc/IRegistry.sol";
import { Registry } from "@urc/Registry.sol";

// Storage layout for EigenLayerMiddleware
// ╭---------------------------+-------------------------------------------------------------------------------+------+--------+-------+-------------------------------------------------------------------------╮
// | Name                      | Type                                                                          | Slot | Offset | Bytes | Contract                                                                |
// +===========================================================================================================================================================================+
// | AVS_DIRECTORY             | contract IAVSDirectory                                                        | 0    | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------------+-------------------------------------------------------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | DELEGATION_MANAGER        | contract DelegationManagerStorage                                             | 1    | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------------+-------------------------------------------------------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | STRATEGY_MANAGER          | contract StrategyManagerStorage                                               | 2    | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------------+-------------------------------------------------------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | EIGEN_POD_MANAGER         | contract IEigenPodManager                                                     | 3    | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------------+-------------------------------------------------------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | REWARDS_COORDINATOR       | contract IRewardsCoordinator                                                  | 4    | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------------+-------------------------------------------------------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | UNDERWRITER_SHARE_BIPS    | uint256                                                                       | 5    | 0      | 32    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------------+-------------------------------------------------------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | REGISTRY                  | contract Registry                                                             | 6    | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------------+-------------------------------------------------------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | REWARD_INITIATOR          | address                                                                       | 7    | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------------+-------------------------------------------------------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | REGISTRY_COORDINATOR      | contract ITaiyiRegistryCoordinator                                            | 8    | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------------+-------------------------------------------------------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | operatorDelegations       | mapping(address => mapping(bytes32 => struct IEigenLayerMiddleware.DelegationStore)) | 9    | 0      | 32    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------------+-------------------------------------------------------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | operatorRegistrationRoots | mapping(address => struct EnumerableSet.Bytes32Set)                           | 10   | 0      | 32    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------------+-------------------------------------------------------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | REWARD_DURATION           | uint256                                                                       | 11   | 0      | 32    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------------+-------------------------------------------------------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | SLASHER                   | address                                                                       | 12   | 0      | 20    | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// |---------------------------+-------------------------------------------------------------------------------+------+--------+-------+-------------------------------------------------------------------------|
// | __gap                     | uint256[50]                                                                   | 13   | 0      | 1600  | src/storage/EigenLayerMiddlewareStorage.sol:EigenLayerMiddlewareStorage |
// ╰---------------------------+-------------------------------------------------------------------------------+------+--------+-------+-------------------------------------------------------------------------╯

abstract contract EigenLayerMiddlewareStorage is IEigenLayerMiddleware {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @notice EigenLayer's AVS Directory contract
    IAVSDirectory public AVS_DIRECTORY;

    /// @notice EigenLayer's Delegation Manager contract
    DelegationManager public DELEGATION_MANAGER;

    /// @notice EigenLayer's Strategy Manager contract
    StrategyManager public STRATEGY_MANAGER;

    /// @notice EigenLayer's EigenPod Manager contract
    IEigenPodManager public EIGEN_POD_MANAGER;

    /// @notice EigenLayer's Reward Coordinator contract
    IRewardsCoordinator public REWARDS_COORDINATOR;

    /// @notice Underwriter share in basis points
    uint256 public UNDERWRITER_SHARE_BIPS;

    /// @notice Registry contract
    IRegistry public REGISTRY;

    /// @notice Reward Initiator address
    address public REWARD_INITIATOR;

    /// @notice Registry Coordinator contract
    ITaiyiRegistryCoordinator public REGISTRY_COORDINATOR;

    /// @notice Optimized storage for operator delegations
    /// @dev operator address -> registration root -> delegation store mapping
    mapping(address => mapping(bytes32 => DelegationStore)) internal operatorDelegations;

    /// @notice Optimized storage for operator registration roots
    /// @dev operator address -> registration root mapping
    mapping(address => EnumerableSet.Bytes32Set) internal operatorRegistrationRoots;

    /// @notice Reward duration
    uint256 public REWARD_DURATION;

    /// @notice Slasher contract
    address public SLASHER;

    /// @notice Allocation Manager contract
    address public ALLOCATION_MANAGER;

    /// @notice Minimum collateral required for validator registration
    uint256 public REGISTRATION_MIN_COLLATERAL;

    /// @notice Gap for future storage
    uint256[50] private __GAP;
}

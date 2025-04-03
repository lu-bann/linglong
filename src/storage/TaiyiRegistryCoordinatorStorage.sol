// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IPubkeyRegistry } from "../interfaces/IPubkeyRegistry.sol";
import { ISocketRegistry } from "../interfaces/ISocketRegistry.sol";
import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";

import { ServiceTypeLib } from "../libs/ServiceTypeLib.sol";
import {
    IAllocationManager,
    IAllocationManagerTypes
} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

// Storage layout for TaiyiRegistryCoordinatorStorage
// ╭----------------------+----------------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------------╮
// | Name                 | Type                                                                 | Slot | Offset | Bytes | Contract                                                                        |
// +===========================================================================================================================================================================================================================+
// | PAUSED_REGISTER_OPERATOR | uint8                                                            | 0    | 0      | 1     | src/storage/TaiyiRegistryCoordinatorStorage.sol:TaiyiRegistryCoordinatorStorage |
// |----------------------+----------------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------------|
// | PAUSED_DEREGISTER_OPERATOR | uint8                                                          | 0    | 1      | 1     | src/storage/TaiyiRegistryCoordinatorStorage.sol:TaiyiRegistryCoordinatorStorage |
// |----------------------+----------------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------------|
// | socketRegistry       | contract ISocketRegistry                                             | 1    | 0      | 20    | src/storage/TaiyiRegistryCoordinatorStorage.sol:TaiyiRegistryCoordinatorStorage |
// |----------------------+----------------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------------|
// | pubkeyRegistry       | contract IPubkeyRegistry                                             | 2    | 0      | 20    | src/storage/TaiyiRegistryCoordinatorStorage.sol:TaiyiRegistryCoordinatorStorage |
// |----------------------+----------------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------------|
// | allocationManager    | contract IAllocationManager                                          | 3    | 0      | 20    | src/storage/TaiyiRegistryCoordinatorStorage.sol:TaiyiRegistryCoordinatorStorage |
// |----------------------+----------------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------------|
// | _operatorSets        | mapping(uint32 => struct EnumerableSet.AddressSet)                   | 4    | 0      | 32    | src/storage/TaiyiRegistryCoordinatorStorage.sol:TaiyiRegistryCoordinatorStorage |
// |----------------------+----------------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------------|
// | _operatorInfo        | mapping(address => struct ITaiyiRegistryCoordinator.OperatorInfo)    | 5    | 0      | 32    | src/storage/TaiyiRegistryCoordinatorStorage.sol:TaiyiRegistryCoordinatorStorage |
// |----------------------+----------------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------------|
// | eigenlayerMiddleware | address                                                              | 6    | 0      | 20    | src/storage/TaiyiRegistryCoordinatorStorage.sol:TaiyiRegistryCoordinatorStorage |
// |----------------------+----------------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------------|
// | restakingMiddleware  | struct EnumerableSet.AddressSet                                      | 7    | 0      | 64    | src/storage/TaiyiRegistryCoordinatorStorage.sol:TaiyiRegistryCoordinatorStorage |
// |----------------------+----------------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------------|
// | restakingProtocol    | mapping(address => enum ITaiyiRegistryCoordinator.RestakingProtocol) | 9    | 0      | 32    | src/storage/TaiyiRegistryCoordinatorStorage.sol:TaiyiRegistryCoordinatorStorage |
// |----------------------+----------------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------------|
// | __GAP                | uint256[50]                                                          | 10   | 0      | 1600  | src/storage/TaiyiRegistryCoordinatorStorage.sol:TaiyiRegistryCoordinatorStorage |
// ╰----------------------+----------------------------------------------------------------------+------+--------+-------+---------------------------------------------------------------------------------╯

/// @title Storage contract for the RegistryCoordinator
abstract contract TaiyiRegistryCoordinatorStorage is ITaiyiRegistryCoordinator {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice The EIP-712 typehash used for registering BLS public keys
    bytes32 public constant PUBKEY_REGISTRATION_TYPEHASH =
        keccak256("BN254PubkeyRegistration(address operator)");

    /// @notice Index for flag that pauses operator registration
    uint8 internal PAUSED_REGISTER_OPERATOR;

    /// @notice Index for flag that pauses operator deregistration
    uint8 internal PAUSED_DEREGISTER_OPERATOR;

    /// @notice the Socket Registry contract that will keep track of operators' sockets (arbitrary strings)
    ISocketRegistry public socketRegistry;

    /// @notice the Pubkey Registry contract that will keep track of operators' public keys
    IPubkeyRegistry public pubkeyRegistry;

    /// EigenLayer contracts
    /// @notice the AllocationManager that tracks OperatorSets and Slashing in EigenLayer
    IAllocationManager public allocationManager;

    /// @notice maps operator set id => operator addresses
    mapping(uint32 => EnumerableSet.AddressSet) internal _operatorSets;

    /// @notice maps operator address => operator id and status
    mapping(address => OperatorInfo) internal _operatorInfo;

    /// @notice The avs address for this AVS (used for UAM integration in EigenLayer)
    address public eigenlayerMiddleware;

    /// @notice The restaking middleware addresses
    EnumerableSet.AddressSet internal restakingMiddleware;

    /// @notice The restaking protocol for each restaking middleware
    mapping(address => RestakingProtocol) internal restakingProtocol;

    constructor(IAllocationManager _allocationManager) {
        allocationManager = _allocationManager;
    }

    // storage gap for upgradeability
    // slither-disable-next-line shadowing-state
    uint256[50] private __GAP;
}

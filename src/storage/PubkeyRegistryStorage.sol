// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IPubkeyRegistry } from "../interfaces/IPubkeyRegistry.sol";
import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { BN254 } from "../libs/BN254.sol";

// Storage layout for PubkeyRegistryStorage
// ╭----------------------+------------------------------------------+------+--------+-------+------------------------------------------------------╮
// | Name                 | Type                                     | Slot | Offset | Bytes | Contract                                             |
// +=====================================================================================================================================+
// | registryCoordinator  | contract ITaiyiRegistryCoordinator       | 0    | 0      | 20    | src/storage/PubkeyRegistryStorage.sol:PubkeyRegistryStorage |
// |----------------------+------------------------------------------+------+--------+-------+------------------------------------------------------|
// | operatorToPubkey     | mapping(address => struct BN254.G1Point) | 1    | 0      | 32    | src/storage/PubkeyRegistryStorage.sol:PubkeyRegistryStorage |
// |----------------------+------------------------------------------+------+--------+-------+------------------------------------------------------|
// | operatorToPubkeyG2   | mapping(address => struct BN254.G2Point) | 2    | 0      | 32    | src/storage/PubkeyRegistryStorage.sol:PubkeyRegistryStorage |
// |----------------------+------------------------------------------+------+--------+-------+------------------------------------------------------|
// | operatorToPubkeyHash | mapping(address => bytes32)              | 3    | 0      | 32    | src/storage/PubkeyRegistryStorage.sol:PubkeyRegistryStorage |
// |----------------------+------------------------------------------+------+--------+-------+------------------------------------------------------|
// | pubkeyHashToOperator | mapping(bytes32 => address)              | 4    | 0      | 32    | src/storage/PubkeyRegistryStorage.sol:PubkeyRegistryStorage |
// ╰----------------------+------------------------------------------+------+--------+-------+------------------------------------------------------╯

/// @title Storage contract for the PubkeyRegistry
/// @notice Defines and manages the storage layout for the PubkeyRegistry contract
abstract contract PubkeyRegistryStorage {
    /// @dev Returns the hash of the zero pubkey aka BN254.G1Point(0,0)
    bytes32 internal constant ZERO_PK_HASH =
        hex"ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5";

    /// @notice The registry coordinator contract
    address public registryCoordinator;

    /// @notice Mapping from operator address to their public key hash
    mapping(address => bytes32) internal operatorToPubkeyHash;

    /// @notice Mapping from public key hash to operator address
    mapping(bytes32 => address) internal pubkeyHashToOperator;

    /// @notice Mapping from pubkey hash to pubkey
    mapping(bytes32 => bytes) internal pubkeyHashToPubkey;
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ISocketRegistry } from "../interfaces/ISocketRegistry.sol";

// Storage layout for SocketRegistryStorage
// ╭--------------------+----------------------------+------+--------+-------+-------------------------------------------╮
// | Name               | Type                       | Slot | Offset | Bytes | Contract                                  |
// +==========================================================================================================+
// | registryCoordinator | address                    | 0    | 0      | 20    | src/storage/SocketRegistryStorage.sol:SocketRegistryStorage |
// |--------------------+----------------------------+------+--------+-------+-------------------------------------------|
// | operatorIdToSocket | mapping(bytes32 => string) | 1    | 0      | 32    | src/storage/SocketRegistryStorage.sol:SocketRegistryStorage |
// |--------------------+----------------------------+------+--------+-------+-------------------------------------------|
// | __GAP              | uint256[50]                | 2    | 0      | 1600  | src/storage/SocketRegistryStorage.sol:SocketRegistryStorage |
// ╰--------------------+----------------------------+------+--------+-------+-------------------------------------------╯

/// @title Storage contract for the SocketRegistry
abstract contract SocketRegistryStorage is ISocketRegistry {
    /// @notice The address of the RegistryCoordinator
    address public registryCoordinator;

    /// @notice A mapping from operator IDs to their sockets
    mapping(bytes32 => string) public operatorIdToSocket;

    constructor(address _registryCoordinator) {
        registryCoordinator = _registryCoordinator;
    }

    uint256[50] private __GAP;
}

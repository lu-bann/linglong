// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

/// @title RestakingProtocolMap
/// @notice Library for managing a mapping from addresses to RestakingProtocol with enumeration capabilities
/// @dev Combines a mapping with an EnumerableSet to allow for O(1) lookups and enumeration of protocol types
library RestakingProtocolMap {
    using EnumerableSet for EnumerableSet.AddressSet;

    struct Map {
        // Mapping from address to RestakingProtocol
        mapping(address => ITaiyiRegistryCoordinator.RestakingProtocol) protocols;
        // Set of keys for enumeration
        EnumerableSet.AddressSet keys;
    }

    /// @notice Sets or remove a protocol type for an address
    /// @param map The storage map to modify
    /// @param addr The address key
    /// @param protocol The protocol type to set
    /// @return True if the address was newly added, false if protocol type is set to None
    function set(
        Map storage map,
        address addr,
        ITaiyiRegistryCoordinator.RestakingProtocol protocol
    )
        internal
        returns (bool)
    {
        if (protocol == ITaiyiRegistryCoordinator.RestakingProtocol.NONE) {
            // If setting to NONE, remove from the map
            if (contains(map, addr)) {
                return remove(map, addr);
            }
            return false;
        }

        map.protocols[addr] = protocol;
        return map.keys.add(addr);
    }

    /// @notice Removes an address from the map
    /// @param map The storage map to modify
    /// @param addr The address key to remove
    /// @return True if the address was removed, false if it wasn't present
    function remove(Map storage map, address addr) internal returns (bool) {
        delete map.protocols[addr];
        return map.keys.remove(addr);
    }

    /// @notice Gets the protocol type for an address
    /// @param map The storage map to query
    /// @param addr The address key to look up
    /// @return The protocol type associated with the address
    function get(
        Map storage map,
        address addr
    )
        internal
        view
        returns (ITaiyiRegistryCoordinator.RestakingProtocol)
    {
        return map.protocols[addr];
    }

    /// @notice Checks if an address exists in the map
    /// @param map The storage map to query
    /// @param addr The address key to check
    /// @return True if the address exists in the map
    function contains(Map storage map, address addr) internal view returns (bool) {
        return map.keys.contains(addr);
    }

    /// @notice Gets the number of addresses in the map
    /// @param map The storage map to query
    /// @return The number of addresses in the map
    function length(Map storage map) internal view returns (uint256) {
        return map.keys.length();
    }

    /// @notice Gets the address at a specific index in the map
    /// @param map The storage map to query
    /// @param index The index to look up
    /// @return The address at the specified index
    function addressAt(Map storage map, uint256 index) internal view returns (address) {
        return map.keys.at(index);
    }

    /// @notice Gets the protocol type at a specific index in the map
    /// @param map The storage map to query
    /// @param index The index to look up
    /// @return The protocol type at the specified index
    function protocolAt(
        Map storage map,
        uint256 index
    )
        internal
        view
        returns (ITaiyiRegistryCoordinator.RestakingProtocol)
    {
        address addr = addressAt(map, index);
        return map.protocols[addr];
    }

    /// @notice Gets all addresses in the map
    /// @param map The storage map to query
    /// @return An array of all addresses in the map
    function addresses(Map storage map) internal view returns (address[] memory) {
        return map.keys.values();
    }

    /// @notice Gets all addresses with a specific protocol type
    /// @param map The storage map to query
    /// @param protocol The protocol type to filter by
    /// @return An array of addresses with the specified protocol type
    function addressesByProtocol(
        Map storage map,
        ITaiyiRegistryCoordinator.RestakingProtocol protocol
    )
        internal
        view
        returns (address[] memory)
    {
        uint256 len = length(map);

        // First pass to count matching addresses
        uint256 count = 0;
        for (uint256 i = 0; i < len; i++) {
            address addr = addressAt(map, i);
            if (map.protocols[addr] == protocol) {
                count++;
            }
        }

        // Second pass to populate the array
        address[] memory result = new address[](count);
        uint256 resultIndex = 0;

        for (uint256 i = 0; i < len && resultIndex < count; i++) {
            address addr = addressAt(map, i);
            if (map.protocols[addr] == protocol) {
                result[resultIndex] = addr;
                resultIndex++;
            }
        }

        return result;
    }
}

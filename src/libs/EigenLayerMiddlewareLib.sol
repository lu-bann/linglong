// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { EnumerableMapLib } from "@solady/utils/EnumerableMapLib.sol";

/// @title EigenLayerMiddlewareLib
/// @notice Library with helper functions for EigenLayerMiddleware to reduce main contract size
library EigenLayerMiddlewareLib {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMapLib for EnumerableMapLib.Uint256ToBytes32Map;

    /// @notice Helper function to deduplicate strategies from operator sets
    /// @param operatorSets Array of operator sets
    /// @param registryCoordinator Reference to the registry coordinator contract
    /// @param operator Address of the operator
    /// @return strategies Array of unique strategy addresses
    function deduplicateStrategies(
        OperatorSet[] memory operatorSets,
        ITaiyiRegistryCoordinator registryCoordinator,
        address operator
    )
        internal
        view
        returns (IStrategy[] memory strategies)
    {
        // Cache array length to save gas on multiple accesses
        uint256 operatorSetsLength = operatorSets.length;

        // First collect all strategies across all operator sets
        uint256 totalStrategiesCount = 0;

        // Count total strategies first
        for (uint256 i = 0; i < operatorSetsLength;) {
            IStrategy[] memory setStrategies = registryCoordinator
                .getOperatorAllocatedStrategies(operator, operatorSets[i].id);
            totalStrategiesCount += setStrategies.length;
            unchecked {
                ++i;
            }
        }

        if (totalStrategiesCount == 0) {
            return new IStrategy[](0);
        }

        // Create array to store all strategies (with potential duplicates)
        address[] memory allStrategies = new address[](totalStrategiesCount);
        uint256 allStrategiesLength = 0;

        // Fill array with all strategies
        for (uint256 i = 0; i < operatorSetsLength;) {
            IStrategy[] memory setStrategies = registryCoordinator
                .getOperatorAllocatedStrategies(operator, operatorSets[i].id);
            uint256 setStrategiesLength = setStrategies.length;

            for (uint256 j = 0; j < setStrategiesLength;) {
                allStrategies[allStrategiesLength] = address(setStrategies[j]);
                unchecked {
                    ++allStrategiesLength;
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }

        // Use the deduplicate helper function to avoid code duplication
        address[] memory uniqueStrategies =
            _deduplicateAddresses(allStrategies, allStrategiesLength);

        // Convert addresses to IStrategy objects
        uint256 uniqueLength = uniqueStrategies.length;
        strategies = new IStrategy[](uniqueLength);

        for (uint256 i = 0; i < uniqueLength;) {
            strategies[i] = IStrategy(uniqueStrategies[i]);
            unchecked {
                ++i;
            }
        }

        return strategies;
    }

    /// @notice Helper function to deduplicate strategy addresses
    /// @param allStrategies Array of strategy addresses (potentially with duplicates)
    /// @param allStrategiesLength Length of valid entries in allStrategies array
    /// @return strategies Array of unique strategy addresses
    function deduplicateStrategyAddresses(
        address[] memory allStrategies,
        uint256 allStrategiesLength
    )
        internal
        pure
        returns (address[] memory)
    {
        return _deduplicateAddresses(allStrategies, allStrategiesLength);
    }

    /// @notice Internal helper for deduplication to avoid code duplication
    /// @param addresses Array of addresses that may contain duplicates
    /// @param length Number of valid elements in the addresses array
    /// @return result Array of unique addresses
    function _deduplicateAddresses(
        address[] memory addresses,
        uint256 length
    )
        private
        pure
        returns (address[] memory result)
    {
        if (length == 0) {
            return new address[](0);
        }

        // Count unique addresses
        uint256 uniqueCount = 0;

        // This is a temporary array to track which elements have been seen
        // We use an array of booleans instead of nested loops for better efficiency
        bool[] memory seen = new bool[](length);

        for (uint256 i = 0; i < length;) {
            address current = addresses[i];
            bool isDuplicate = false;

            // Check if this element already appeared earlier in the array
            for (uint256 j = 0; j < i;) {
                if (addresses[j] == current) {
                    isDuplicate = true;
                    break;
                }
                unchecked {
                    ++j;
                }
            }

            if (!isDuplicate) {
                seen[uniqueCount] = true;
                addresses[uniqueCount] = current; // Move unique addresses to the start of the array
                unchecked {
                    ++uniqueCount;
                }
            }

            unchecked {
                ++i;
            }
        }

        // Create result array with only the unique addresses
        result = new address[](uniqueCount);

        // Copy unique addresses to the result array
        for (uint256 i = 0; i < uniqueCount;) {
            result[i] = addresses[i];
            unchecked {
                ++i;
            }
        }

        return result;
    }
}

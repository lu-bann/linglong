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
        // First count all strategies across all operator sets
        uint256 totalStrategiesCount = 0;
        for (uint256 i = 0; i < operatorSets.length; i++) {
            IStrategy[] memory setStrategies = registryCoordinator
                .getOperatorAllocatedStrategies(operator, operatorSets[i].id);
            totalStrategiesCount += setStrategies.length;
        }

        // Create array to store all strategies (with potential duplicates)
        address[] memory allStrategies = new address[](totalStrategiesCount);
        uint256 allStrategiesLength = 0;

        // Fill array with all strategies
        for (uint256 i = 0; i < operatorSets.length; i++) {
            IStrategy[] memory setStrategies = registryCoordinator
                .getOperatorAllocatedStrategies(operator, operatorSets[i].id);
            for (uint256 j = 0; j < setStrategies.length; j++) {
                allStrategies[allStrategiesLength] = address(setStrategies[j]);
                allStrategiesLength++;
            }
        }

        // Count unique strategies
        uint256 uniqueCount = 0;
        for (uint256 i = 0; i < allStrategiesLength; i++) {
            bool isDuplicate = false;
            for (uint256 j = 0; j < i; j++) {
                if (allStrategies[j] == allStrategies[i]) {
                    isDuplicate = true;
                    break;
                }
            }
            if (!isDuplicate) {
                uniqueCount++;
            }
        }

        // Create result array with unique strategies
        strategies = new IStrategy[](uniqueCount);
        uint256 resultIndex = 0;

        for (uint256 i = 0; i < allStrategiesLength; i++) {
            bool isDuplicate = false;
            for (uint256 j = 0; j < resultIndex; j++) {
                if (allStrategies[i] == address(strategies[j])) {
                    isDuplicate = true;
                    break;
                }
            }
            if (!isDuplicate) {
                strategies[resultIndex] = IStrategy(allStrategies[i]);
                resultIndex++;
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
        returns (address[] memory strategies)
    {
        // Count unique strategies
        uint256 uniqueCount = 0;
        for (uint256 i = 0; i < allStrategiesLength; i++) {
            bool isDuplicate = false;
            for (uint256 j = 0; j < i; j++) {
                if (allStrategies[j] == allStrategies[i]) {
                    isDuplicate = true;
                    break;
                }
            }
            if (!isDuplicate) {
                uniqueCount++;
            }
        }

        // Create result array with unique strategies
        strategies = new address[](uniqueCount);
        uint256 resultIndex = 0;

        for (uint256 i = 0; i < allStrategiesLength; i++) {
            bool isDuplicate = false;
            for (uint256 j = 0; j < resultIndex; j++) {
                if (allStrategies[i] == strategies[j]) {
                    isDuplicate = true;
                    break;
                }
            }
            if (!isDuplicate) {
                strategies[resultIndex] = allStrategies[i];
                resultIndex++;
            }
        }

        return strategies;
    }
}

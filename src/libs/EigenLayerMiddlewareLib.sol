// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";

import { DelegationStore } from "../types/CommonTypes.sol";
import { OperatorSubsetLib } from "./OperatorSubsetLib.sol";
import { DelegationManager } from
    "@eigenlayer-contracts/src/contracts/core/DelegationManager.sol";
import { IAVSDirectory } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAVSDirectory.sol";
import { IAllocationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IAllocationManagerTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { EnumerableMapLib } from "@solady/utils/EnumerableMapLib.sol";
import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { Registry } from "@urc/Registry.sol";
import { BLS } from "@urc/lib/BLS.sol";
import { console } from "forge-std/console.sol";

/// @title EigenLayerMiddlewareLib
/// @notice Library with helper functions for EigenLayerMiddleware to reduce main contract size
library EigenLayerMiddlewareLib {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMapLib for EnumerableMapLib.Uint256ToBytes32Map;
    using OperatorSubsetLib for uint96;
    using OperatorSubsetLib for uint32;

    /// @notice Custom errors
    error OperatorNotRegisteredInEigenLayer();
    error OperatorNotRegisteredInAVS();
    error OperatorIsNotYetRegisteredInValidatorOperatorSet();
    error OperatorIsNotYetRegisteredInUnderwriterOperatorSet();
    error UseCreateOperatorDirectedAVSRewardsSubmission();
    error OnlyRegistryCoordinator();
    error OnlyRewardsInitiator();
    error OnlySlasher();
    error RegistrationRootNotFound();
    error OperatorNotOwnerOfRegistrationRoot();
    error PubKeyNotFound();
    error OperatorNotRegistered();
    error FraudProofWindowNotPassed();
    error InvalidDelegationSignaturesLength();
    error InvalidRegistrationsLength();
    error OperatorIsSlashed();

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
            (, uint32 baseId) = operatorSets[i].id.decodeOperatorSetId32();
            address[] memory setStrategies = registryCoordinator
                .getEigenLayerOperatorAllocatedStrategies(operator, baseId);
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
            (, uint32 baseId) = operatorSets[i].id.decodeOperatorSetId32();
            address[] memory setStrategies = registryCoordinator
                .getEigenLayerOperatorAllocatedStrategies(operator, baseId);
            uint256 setStrategiesLength = setStrategies.length;
            for (uint256 j = 0; j < setStrategiesLength;) {
                allStrategies[allStrategiesLength] = setStrategies[j];
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

    /// @notice Verify an operator's registration status in EigenLayer and this AVS
    /// @param operator The operator address to check
    /// @param delegationManager The delegation manager contract
    /// @param registryCoordinator The registry coordinator contract
    /// @return operatorSets Array of operator sets the operator is registered in
    /// @dev Reverts if operator is not registered in EigenLayer or this AVS
    function verifyEigenLayerOperatorRegistration(
        address operator,
        address avsAddress,
        DelegationManager delegationManager,
        ITaiyiRegistryCoordinator registryCoordinator
    )
        internal
        view
        returns (OperatorSet[] memory operatorSets)
    {
        // First check if operator is registered in delegation manager
        bool isDelegated = delegationManager.isOperator(operator);
        if (!isDelegated) {
            revert OperatorNotRegisteredInEigenLayer();
        }

        ITaiyiRegistryCoordinator.AllocatedOperatorSets memory operatorSetsIds =
        registryCoordinator.getOperatorAllocatedOperatorSets(
            operator, ITaiyiRegistryCoordinator.RestakingProtocol.EIGENLAYER
        );

        operatorSets = new OperatorSet[](operatorSetsIds.eigenLayerSets.length);
        for (uint256 i = 0; i < operatorSetsIds.eigenLayerSets.length; i++) {
            operatorSets[i] =
                OperatorSet({ avs: avsAddress, id: operatorSetsIds.eigenLayerSets[i] });
        }

        // Check operator's registration status in this AVS
        if (operatorSets.length == 0) {
            revert OperatorNotRegisteredInAVS();
        }

        return operatorSets;
    }

    /// @notice Create an operator set with the given strategies
    /// @param allocationManager The allocation manager contract address
    /// @param avsAddress The AVS contract address
    /// @param registryCoordinator The registry coordinator contract
    /// @param strategies Array of strategies for the operator set
    /// @return operatorSetId The ID of the created operator set
    function createOperatorSet(
        address allocationManager,
        address avsAddress,
        ITaiyiRegistryCoordinator registryCoordinator,
        IStrategy[] memory strategies,
        uint256 minStake,
        uint32 operatorSetType
    )
        internal
        returns (uint32 operatorSetId)
    {
        // Get the current operator set count from allocationManager
        operatorSetId = uint32(operatorSetType);
        operatorSetId = operatorSetId.encodeOperatorSetId32(
            ITaiyiRegistryCoordinator.RestakingProtocol.EIGENLAYER
        );

        IAllocationManagerTypes.CreateSetParams[] memory createSetParams =
            new IAllocationManagerTypes.CreateSetParams[](1);

        createSetParams[0] = IAllocationManagerTypes.CreateSetParams({
            operatorSetId: operatorSetId,
            strategies: strategies
        });

        // AllocationManager still expects uint32 for its internal ID
        IAllocationManager(allocationManager).createOperatorSets(
            avsAddress, createSetParams
        );

        registryCoordinator.createOperatorSet(operatorSetId, minStake);

        return operatorSetId;
    }

    /// @notice Add strategies to an operator set
    /// @param allocationManager The allocation manager contract address
    /// @param avsAddress The AVS contract address
    /// @param operatorSetId ID of the operator set
    /// @param strategies Array of strategies to add
    function addStrategiesToOperatorSet(
        address allocationManager,
        address avsAddress,
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        internal
    {
        IAllocationManager(allocationManager).addStrategiesToOperatorSet(
            avsAddress, operatorSetId, strategies
        );
    }

    /// @notice Remove strategies from an operator set
    /// @param allocationManager The allocation manager contract address
    /// @param avsAddress The AVS contract address
    /// @param operatorSetId ID of the operator set
    /// @param strategies Array of strategies to remove
    function removeStrategiesFromOperatorSet(
        address allocationManager,
        address avsAddress,
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        internal
    {
        IAllocationManager(allocationManager).removeStrategiesFromOperatorSet(
            avsAddress, operatorSetId, strategies
        );
    }

    /// @notice Process a rewards claim
    /// @param rewardsCoordinator The rewards coordinator contract
    /// @param claim The merkle claim information
    /// @param recipient Address to receive the claimed rewards
    function processClaim(
        IRewardsCoordinator rewardsCoordinator,
        IRewardsCoordinator.RewardsMerkleClaim calldata claim,
        address recipient
    )
        internal
    {
        rewardsCoordinator.processClaim(claim, recipient);
    }

    /// @notice Update AVS metadata URI
    /// @param avsDirectory The AVS directory contract
    /// @param metadataURI New metadata URI
    function updateAVSMetadataURI(
        IAVSDirectory avsDirectory,
        string calldata metadataURI
    )
        internal
    {
        avsDirectory.updateAVSMetadataURI(metadataURI);
    }

    /// @notice Set the claimer for rewards
    /// @param rewardsCoordinator The rewards coordinator contract
    /// @param claimer Address of the claimer
    function setClaimerFor(
        IRewardsCoordinator rewardsCoordinator,
        address claimer
    )
        internal
    {
        rewardsCoordinator.setClaimerFor(claimer);
    }

    function registerValidators(
        IRegistry registry,
        IRegistry.SignedRegistration[] calldata registrations,
        uint256 registrationMinCollateral
    )
        internal
        returns (bytes32 registrationRoot)
    {
        registrationRoot = registry.register{ value: registrationMinCollateral }(
            registrations, address(this)
        );
    }

    /// @notice Unregister validators associated with a registration root
    /// @param registry The Registry contract
    /// @param registrationRoot The registration root to unregister
    function unregisterValidators(
        IRegistry registry,
        bytes32 registrationRoot
    )
        internal
    {
        registry.unregister(registrationRoot);
    }

    /// @notice Validates rewards submissions for underwriters and validators
    /// @param rewardsSubmissions Array of rewards submissions
    /// @return True if submissions are valid, false otherwise
    function validateRewardsSubmissions(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata
            rewardsSubmissions
    )
        internal
        view
        returns (bool)
    {
        if (rewardsSubmissions.length != 2) {
            return false;
        }

        if (
            keccak256(bytes(rewardsSubmissions[0].description))
                != keccak256(bytes("underwriter"))
        ) {
            return false;
        }

        if (
            keccak256(bytes(rewardsSubmissions[1].description))
                != keccak256(bytes("validator"))
        ) {
            return false;
        }

        if (
            rewardsSubmissions[0].startTimestamp != block.timestamp
                || rewardsSubmissions[1].startTimestamp != block.timestamp
        ) {
            return false;
        }

        // Check the validator rewards are all zero (will be calculated by the rewards handler)
        IRewardsCoordinator.OperatorReward[] memory validatorRewards =
            rewardsSubmissions[1].operatorRewards;
        for (uint256 i = 0; i < validatorRewards.length; i++) {
            if (validatorRewards[i].amount != 0) {
                return false;
            }
        }

        return true;
    }

    /// @notice Gets a delegation for an operator by validator pubkey
    /// @param registry The registry contract
    /// @param delegationStore Storage mapping for delegations
    /// @param operator The operator address
    /// @param registrationRoot The registration root
    /// @param pubkey BLS public key of the validator
    /// @return The signed delegation information
    function getDelegation(
        IRegistry registry,
        DelegationStore storage delegationStore,
        address operator,
        bytes32 registrationRoot,
        BLS.G1Point calldata pubkey
    )
        internal
        view
        returns (ISlasher.SignedDelegation memory)
    {
        IRegistry.OperatorData memory operatorData =
            registry.getOperatorData(registrationRoot);
        address owner = operatorData.owner;
        uint48 registeredAt = operatorData.registeredAt;

        if (registeredAt == 0) {
            revert RegistrationRootNotFound();
        }

        if (owner != operator) {
            revert OperatorNotOwnerOfRegistrationRoot();
        }

        bytes32 pubkeyHash = keccak256(abi.encode(pubkey));

        if (delegationStore.delegations[pubkeyHash].delegation.committer != address(0)) {
            return delegationStore.delegations[pubkeyHash];
        } else {
            revert PubKeyNotFound();
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { Math } from "@openzeppelin-contracts/contracts/utils/math/Math.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { EnumerableMapLib } from "@solady/utils/EnumerableMapLib.sol";

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { IBaseDelegator } from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import { IVault } from "@symbiotic/interfaces/vault/IVault.sol";

import { IRegistry } from "@urc/IRegistry.sol";

import { DelegationStore } from "../types/CommonTypes.sol";
import { ECDSALib } from "./ECDSALib.sol";
import { OperatorSubsetLib } from "./OperatorSubsetLib.sol";
import { SafeCast96To32Lib } from "./SafeCast96To32Lib.sol";

import { SafeCast96To32Lib } from "./SafeCast96To32Lib.sol";

import { SafeCast } from "@openzeppelin-contracts/contracts/utils/math/SafeCast.sol";
import { Subnetworks } from "@symbiotic-middleware-sdk/extensions/Subnetworks.sol";
import { Subnetwork } from "@symbiotic/contracts/libraries/Subnetwork.sol";

/// @title SymbioticNetworkMiddlewareLib
/// @notice Library containing core logic for the SymbioticNetworkMiddleware contract
library SymbioticNetworkMiddlewareLib {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMapLib for EnumerableMapLib.Uint256ToBytes32Map;
    using SafeCast96To32Lib for uint96[];
    using SafeCast96To32Lib for uint96;

    // Custom errors
    error InvalidSignature();
    error NoVaultsToSlash();
    error InactiveKeySlash();
    error InactiveOperatorSlash();
    error OperatorNotRegistered();
    error OperatorIsNotYetRegisteredInValidatorOperatorSet();
    error OperatorIsNotYetRegisteredInUnderwriterOperatorSet();
    error InvalidRegistrationsLength();
    error InvalidDelegationSignaturesLength();
    error OperatorIsSlashed();

    /// @notice Register an operator with the registry coordinator
    /// @param registryCoordinator The registry coordinator
    /// @param operator The operator address
    /// @param baseSubnetworks The base subnetworks to register with
    function registerOperatorWithCoordinator(
        ITaiyiRegistryCoordinator registryCoordinator,
        address operator,
        uint96[] memory baseSubnetworks
    )
        internal
    {
        // Create a direct uint32 array for IAVSRegistrar compatibility
        uint32[] memory compatibleIds = new uint32[](baseSubnetworks.length);

        for (uint256 i = 0; i < baseSubnetworks.length; i++) {
            // Use the specialized function that ensures values stay within uint32 bounds
            compatibleIds[i] = baseSubnetworks[i].toUint32();
        }

        // Pass the compatible uint32 array directly
        registryCoordinator.registerOperator(
            operator, address(this), compatibleIds, bytes("")
        );
    }

    /// @notice Verify an operator's key
    /// @param operator The operator address
    /// @param key The address key
    /// @param signature The signature to verify
    function verifyKey(
        address operator,
        bytes memory key,
        bytes memory signature
    )
        internal
        pure
    {
        // Hash the key for verification
        bytes32 messageHash = keccak256(key);

        // Use ECDSALib to verify the signature
        ECDSALib.verifySignature(
            messageHash, operator, signature, "Invalid operator signature"
        );
    }

    /// @notice Unregister validators associated with a registration root
    /// @param registry The Registry contract
    /// @param operatorDelegations Mapping to store operator delegations
    /// @param operatorRegistrationRoots Set of registration roots for the operator
    /// @param operator The operator address
    /// @param registrationRoot The registration root to unregister
    function unregisterValidators(
        IRegistry registry,
        mapping(address => mapping(bytes32 => DelegationStore)) storage
            operatorDelegations,
        mapping(address => EnumerableSet.Bytes32Set) storage operatorRegistrationRoots,
        address operator,
        bytes32 registrationRoot
    )
        internal
    {
        // Ensure the registration root is valid for this operator
        if (
            registrationRoot == bytes32(0)
                || operatorDelegations[operator][registrationRoot].delegationMap.length() == 0
        ) {
            revert OperatorNotRegistered();
        }

        // Get reference to the delegation store
        DelegationStore storage delegationStore =
            operatorDelegations[operator][registrationRoot];

        // Clear all delegations
        for (uint256 i = 0; i < delegationStore.delegationMap.length(); i++) {
            (uint256 index, bytes32 pubkeyHash) = delegationStore.delegationMap.at(i);
            delete delegationStore.delegations[pubkeyHash];
            delegationStore.delegationMap.remove(index);
        }

        // Delete the pubkey hashes array
        delete operatorDelegations[operator][registrationRoot];
        EnumerableSet.Bytes32Set storage roots = operatorRegistrationRoots[operator];
        roots.remove(registrationRoot);

        // Unregister from the registry
        registry.unregister(registrationRoot);
    }

    /// @notice Calculate slash amounts across multiple vaults
    /// @param vaults Array of vault addresses
    /// @param operator The operator address
    /// @param subnetwork The subnetwork being slashed
    /// @param timestamp The timestamp of the slash
    /// @param amount The total amount to slash
    /// @param slashHints Hints for slashing
    /// @return totalStake The total stake across all vaults
    /// @return slashAmounts Array of amounts to slash from each vault
    function calculateSlashAmounts(
        address[] memory vaults,
        address operator,
        uint96 subnetwork,
        uint48 timestamp,
        uint256 amount,
        bytes[] memory slashHints
    )
        internal
        view
        returns (uint256 totalStake, uint256[] memory slashAmounts)
    {
        if (vaults.length == 0) revert NoVaultsToSlash();

        totalStake = 0;
        uint256[] memory stakes = new uint256[](vaults.length);
        slashAmounts = new uint256[](vaults.length);

        // Calculate total stake across all vaults
        for (uint256 i = 0; i < vaults.length; i++) {
            stakes[i] = IBaseDelegator(IVault(vaults[i]).delegator()).stakeAt(
                bytes32(uint256(subnetwork)), operator, timestamp, slashHints[i]
            );
            totalStake += stakes[i];
        }

        if (totalStake == 0) revert NoVaultsToSlash();

        uint256 remainingAmount = amount;

        // Calculate proportional amounts using safe math
        for (uint256 i = 0; i < vaults.length; i++) {
            slashAmounts[i] = Math.mulDiv(amount, stakes[i], totalStake);
            remainingAmount -= slashAmounts[i];
        }

        // Distribute remaining amount due to rounding errors
        if (remainingAmount > 0) {
            slashAmounts[vaults.length - 1] += remainingAmount;
        }

        return (totalStake, slashAmounts);
    }

    /// @notice Gets all subnetworks that have allocated stake to a specific operator
    /// @param operator The operator address
    /// @param registryCoordinator The registry coordinator
    /// @return allocatedSubnetworks Array of subnetwork IDs that have stake allocated to the operator
    function getOperatorAllocatedSubnetworks(
        address operator,
        ITaiyiRegistryCoordinator registryCoordinator
    )
        internal
        view
        returns (uint96[] memory allocatedSubnetworks)
    {
        uint96[] memory subnetworks = new uint96[](2);
        subnetworks[0] = OperatorSubsetLib.SYMBIOTIC_VALIDATOR_SUBSET_ID;
        subnetworks[1] = OperatorSubsetLib.SYMBIOTIC_UNDERWRITER_SUBSET_ID;

        // First allocate a temporary array to hold all potential subnetworks
        uint96[] memory tempAllocated = new uint96[](subnetworks.length);
        uint256 allocatedCount = 0;

        // First pass: Add all allocated subnetworks to the temporary array
        for (uint256 i = 0; i < subnetworks.length; i++) {
            uint32 subnetworkId = uint32(subnetworks[i]);
            if (registryCoordinator.isOperatorInLinglongSubset(subnetworkId, operator)) {
                // Check if this subnetworkId is already in the array
                bool isDuplicate = false;
                for (uint256 j = 0; j < allocatedCount; j++) {
                    if (tempAllocated[j] == SafeCast.toUint96(subnetworkId)) {
                        isDuplicate = true;
                        break;
                    }
                }

                // Only add if not a duplicate
                if (!isDuplicate) {
                    tempAllocated[allocatedCount] = SafeCast.toUint96(subnetworkId);
                    allocatedCount++;
                }
            }
        }

        // Create the final array with the correct size
        allocatedSubnetworks = new uint96[](allocatedCount);
        for (uint256 i = 0; i < allocatedCount; i++) {
            allocatedSubnetworks[i] = tempAllocated[i];
        }

        return allocatedSubnetworks;
    }
}

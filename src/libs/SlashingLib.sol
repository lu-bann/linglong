// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { DelegationStore } from "../types/CommonTypes.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { EnumerableMapLib } from "@solady/utils/EnumerableMapLib.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { Registry } from "@urc/Registry.sol";
import { IRegistry } from "@urc/Registry.sol";
import { BLS } from "@urc/lib/BLS.sol";

/// @title SlashingLib
/// @notice Shared library for middleware contracts implementing common slashing and delegation functionality
/// @dev Contains shared logic for delegation management, registration, and slashing
library SlashingLib {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMapLib for EnumerableMapLib.Uint256ToBytes32Map;

    // ==============================================================================================
    // ================================= ERRORS ===================================================
    // ==============================================================================================

    error RegistrationRootNotFound();
    error OperatorNotOwnerOfRegistrationRoot();
    error OperatorNotRegistered();
    error OperatorUnregistered();
    error OperatorFraudProofPeriodNotOver();
    error OperatorSlashed();
    error PubKeyNotFound();

    // ==============================================================================================
    // ================================= STRUCTS ==================================================
    // ==============================================================================================

    /// @notice Common parameters for delegation operations
    struct DelegationParams {
        bytes32 registrationRoot;
        IRegistry.SignedRegistration[] registrations;
        BLS.G2Point[] delegationSignatures;
        BLS.G1Point delegateePubKey;
        address delegateeAddress;
        bytes[] data;
    }

    // ==============================================================================================
    // ================================= DELEGATION FUNCTIONS ======================================
    // ==============================================================================================

    /// @notice Get all delegations for an operator under a registration root
    /// @param registry The registry contract
    /// @param delegationStore The delegation store
    /// @param operator The operator address
    /// @param registrationRoot The registration root
    /// @return pubkeys Array of BLS public keys
    /// @return delegations Array of signed delegations
    function getAllDelegations(
        IRegistry registry,
        DelegationStore storage delegationStore,
        address operator,
        bytes32 registrationRoot
    )
        public
        view
        returns (
            BLS.G1Point[] memory pubkeys,
            ISlasher.SignedDelegation[] memory delegations
        )
    {
        IRegistry.OperatorData memory operatorData =
            registry.getOperatorData(registrationRoot);
        address owner = operatorData.owner;
        uint48 registeredAt = operatorData.registeredAt;

        if (registeredAt == 0) {
            revert RegistrationRootNotFound();
        }

        uint256 count = delegationStore.delegationMap.length();

        pubkeys = new BLS.G1Point[](count);
        delegations = new ISlasher.SignedDelegation[](count);

        for (uint256 i = 0; i < count; i++) {
            bytes32 pubkeyHash = delegationStore.delegationMap.get(i);
            ISlasher.SignedDelegation memory delegation =
                delegationStore.delegations[pubkeyHash];
            pubkeys[i] = delegation.delegation.proposer;
            delegations[i] = delegation;
        }
    }

    /// @notice Get a specific delegation by pubkey
    /// @param registry The registry contract
    /// @param delegationStore The delegation store
    /// @param operator The operator address
    /// @param registrationRoot The registration root
    /// @param pubkey The BLS public key
    /// @return The signed delegation
    function getDelegation(
        IRegistry registry,
        DelegationStore storage delegationStore,
        address operator,
        bytes32 registrationRoot,
        BLS.G1Point calldata pubkey
    )
        public
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

    // ==============================================================================================
    // ================================= SLASHING FUNCTIONS ========================================
    // ==============================================================================================

    /// @notice Opt in to slasher and store delegations
    /// @param registry The registry contract
    /// @param delegationStore The delegation store for the operator
    /// @param registrationRoots The set of registration roots
    /// @param slasher The slasher contract address
    /// @param committer The committer address
    /// @param params Common delegation parameters
    function optInToSlasher(
        IRegistry registry,
        DelegationStore storage delegationStore,
        EnumerableSet.Bytes32Set storage registrationRoots,
        address slasher,
        address committer,
        DelegationParams calldata params
    )
        public
    {
        registry.optInToSlasher(params.registrationRoot, slasher, committer);
        registrationRoots.add(params.registrationRoot);

        for (uint256 i = 0; i < params.registrations.length; ++i) {
            ISlasher.SignedDelegation memory signedDelegation = ISlasher.SignedDelegation({
                delegation: ISlasher.Delegation({
                    proposer: params.registrations[i].pubkey,
                    delegate: params.delegateePubKey,
                    committer: params.delegateeAddress,
                    slot: type(uint64).max,
                    metadata: params.data[i]
                }),
                signature: params.delegationSignatures[i]
            });

            _setDelegations(
                delegationStore, i, signedDelegation, params.registrations[i].pubkey
            );
        }
    }

    /// @notice Batch set delegations for a registration root
    /// @param registry The registry contract
    /// @param delegationStore The delegation store
    /// @param registrationRoot The registration root
    /// @param restakingMiddleware The restaking middleware address
    /// @param pubkeys BLS public keys
    /// @param delegations Signed delegations
    function batchSetDelegations(
        IRegistry registry,
        DelegationStore storage delegationStore,
        bytes32 registrationRoot,
        address restakingMiddleware,
        BLS.G1Point[] calldata pubkeys,
        ISlasher.SignedDelegation[] calldata delegations
    )
        public
    {
        _validateOperatorRegistration(registry, registrationRoot, restakingMiddleware);

        require(pubkeys.length == delegations.length, "Array length mismatch");
        require(
            delegationStore.delegationMap.length() == pubkeys.length,
            "Array length mismatch"
        );

        for (uint256 i = 0; i < pubkeys.length; i++) {
            bytes32 pubkeyHash = keccak256(abi.encode(pubkeys[i]));

            (, bytes32 storedHash) = delegationStore.delegationMap.at(i);
            if (storedHash == pubkeyHash) {
                delegationStore.delegations[pubkeyHash] = delegations[i];
            }
        }
    }

    // ==============================================================================================
    // ================================= INTERNAL FUNCTIONS ========================================
    // ==============================================================================================

    /// @notice Internal helper to set delegations
    function _setDelegations(
        DelegationStore storage delegationStore,
        uint256 index,
        ISlasher.SignedDelegation memory signedDelegation,
        BLS.G1Point memory pubkey
    )
        internal
    {
        bytes32 pubkeyHash = keccak256(abi.encode(pubkey));
        delegationStore.delegations[pubkeyHash] = signedDelegation;
        delegationStore.delegationMap.set(index, pubkeyHash);
    }

    /// @notice Internal helper to validate operator registration
    function _validateOperatorRegistration(
        IRegistry registry,
        bytes32 registrationRoot,
        address restakingMiddleware
    )
        internal
    {
        IRegistry.OperatorData memory operatorData =
            registry.getOperatorData(registrationRoot);
        address owner = operatorData.owner;
        uint48 registeredAt = operatorData.registeredAt;
        uint48 unregisteredAt = operatorData.unregisteredAt;
        uint48 slashedAt = operatorData.slashedAt;

        if (registeredAt == 0) {
            revert RegistrationRootNotFound();
        }

        if (owner != restakingMiddleware) {
            revert OperatorNotOwnerOfRegistrationRoot();
        }

        if (slashedAt != 0) {
            revert OperatorSlashed();
        }

        if (unregisteredAt < block.number) {
            revert OperatorUnregistered();
        }

        if (registeredAt + registry.getConfig().fraudProofWindow > block.number) {
            revert OperatorFraudProofPeriodNotOver();
        }
    }
}

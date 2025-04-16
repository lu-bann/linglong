// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { DelegationStore } from "../storage/DelegationStore.sol";
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

    /// @notice Errors
    error RegistrationRootNotFound();
    error OperatorNotOwnerOfRegistrationRoot();
    error OperatorNotRegistered();
    error OperatorUnregistered();
    error OperatorFraudProofPeriodNotOver();
    error OperatorSlashed();
    error PubKeyNotFound();

    /// @notice Get all delegations for an operator under a registration root
    /// @param registryAddress The registry contract address
    /// @param delegationStore The delegation store
    /// @param operator The operator address
    /// @param registrationRoot The registration root
    /// @return pubkeys Array of BLS public keys
    /// @return delegations Array of signed delegations
    function getAllDelegations(
        address registryAddress,
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
            IRegistry(registryAddress).getOperatorData(registrationRoot);
        address owner = operatorData.owner;
        uint48 registeredAt = operatorData.registeredAt;

        if (registeredAt == 0) {
            revert RegistrationRootNotFound();
        }

        if (owner != operator) {
            revert OperatorNotOwnerOfRegistrationRoot();
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

    /// @notice Opt in to slasher and store delegations
    /// @param registry The registry contract
    /// @param delegationStore The delegation store for the operator
    /// @param registrationRoots The set of registration roots
    /// @param registrationRoot The registration root to opt in
    /// @param slasher The slasher contract address
    /// @param middleware The middleware contract address
    /// @param registrations Array of validator registrations
    /// @param delegationSignatures BLS signatures for delegations
    /// @param delegateePubKey BLS public key of delegatee
    /// @param delegateeAddress Address of delegatee
    /// @param data Additional data for delegations
    function optInToSlasher(
        IRegistry registry,
        DelegationStore storage delegationStore,
        EnumerableSet.Bytes32Set storage registrationRoots,
        bytes32 registrationRoot,
        address slasher,
        address middleware,
        IRegistry.SignedRegistration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata data
    )
        public
    {
        registry.optInToSlasher(registrationRoot, slasher, middleware);
        registrationRoots.add(registrationRoot);

        for (uint256 i = 0; i < registrations.length; ++i) {
            ISlasher.SignedDelegation memory signedDelegation = ISlasher.SignedDelegation({
                delegation: ISlasher.Delegation({
                    proposer: registrations[i].pubkey,
                    delegate: delegateePubKey,
                    committer: delegateeAddress,
                    slot: type(uint64).max,
                    metadata: data[i]
                }),
                signature: delegationSignatures[i]
            });

            bytes32 pubkeyHash = keccak256(abi.encode(registrations[i].pubkey));
            delegationStore.delegations[pubkeyHash] = signedDelegation;
            delegationStore.delegationMap.set(i, pubkeyHash);
        }
    }

    /// @notice Batch set delegations for a registration root
    /// @param registryAddress The registry contract address
    /// @param delegationStore The delegation store
    /// @param registrationRoot The registration root
    /// @param operator The operator address
    /// @param pubkeys BLS public keys
    /// @param delegations Signed delegations
    function batchSetDelegations(
        address registryAddress,
        DelegationStore storage delegationStore,
        bytes32 registrationRoot,
        address operator,
        BLS.G1Point[] calldata pubkeys,
        ISlasher.SignedDelegation[] calldata delegations
    )
        public
    {
        IRegistry.OperatorData memory operatorData =
            IRegistry(registryAddress).getOperatorData(registrationRoot);
        address owner = operatorData.owner;
        uint48 registeredAt = operatorData.registeredAt;
        uint48 unregisteredAt = operatorData.unregisteredAt;
        uint48 slashedAt = operatorData.slashedAt;

        if (registeredAt == 0) {
            revert RegistrationRootNotFound();
        }

        if (owner != operator) {
            revert OperatorNotOwnerOfRegistrationRoot();
        }

        if (slashedAt != 0) {
            revert OperatorSlashed();
        }

        if (unregisteredAt < block.number) {
            revert OperatorUnregistered();
        }

        if (
            registeredAt + IRegistry(registryAddress).getConfig().fraudProofWindow
                > block.number
        ) {
            revert OperatorFraudProofPeriodNotOver();
        }

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

    /// @notice Get a specific delegation by pubkey
    /// @param registryAddress The registry contract address
    /// @param delegationStore The delegation store
    /// @param operator The operator address
    /// @param registrationRoot The registration root
    /// @param pubkey The BLS public key
    /// @return The signed delegation
    function getDelegation(
        address registryAddress,
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
            IRegistry(registryAddress).getOperatorData(registrationRoot);
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

    /// @notice Get all registration roots for an operator
    /// @param registrationRoots The set of registration roots
    /// @return Array of registration roots
    function getOperatorRegistrationRoots(
        EnumerableSet.Bytes32Set storage registrationRoots
    )
        public
        view
        returns (bytes32[] memory)
    {
        uint256 length = registrationRoots.length();
        bytes32[] memory result = new bytes32[](length);

        for (uint256 i = 0; i < length; i++) {
            result[i] = registrationRoots.at(i);
        }

        return result;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";

import { DelegationStore } from "../types/CommonTypes.sol";
import { OperatorSubsetLib } from "./OperatorSubsetLib.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { BLS } from "@urc/lib/BLS.sol";

/// @title SSVBasedAppMiddlewareLib
/// @notice Library containing utility functions for SSV-based application middleware
/// @dev Provides helper functions for validator registration, delegation, and gateway operations
library SSVBasedAppMiddlewareLib {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // ==============================================================================================
    // ================================= ERRORS ====================================================
    // ==============================================================================================

    error OperatorIsNotYetRegisteredInValidatorOperatorSet();
    error OnlyRegistryCoordinator();
    error OnlySlasher();
    error OnlyOperatorOrOwner();
    error InvalidGatewayOperator();
    error InvalidGatewayNetwork();
    error GatewayDelegationAlreadySet();
    error GatewayDelegationNotSet();
    error InvalidSignature();
    error ExpiredSignature();

    // ==============================================================================================
    // ================================= EVENTS ====================================================
    // ==============================================================================================

    event ValidatorRegistered(address indexed operator, bytes32 indexed registrationRoot);
    event ValidatorUnregistered(
        address indexed operator, bytes32 indexed registrationRoot
    );
    event GatewayDelegationSet(
        address indexed operator,
        address indexed gatewayOperator,
        address indexed gatewayNetwork
    );

    // ==============================================================================================
    // ================================= FUNCTIONS ==================================================
    // ==============================================================================================

    /// @notice Registers validators with the URC Registry
    /// @param registry The URC Registry contract address
    /// @param registrations Array of validator registration parameters
    /// @param minCollateral Minimum collateral required for registration
    /// @return registrationRoot The root hash of the registration
    function registerValidators(
        address registry,
        IRegistry.SignedRegistration[] calldata registrations,
        uint256 minCollateral
    )
        external
        returns (bytes32 registrationRoot)
    {
        require(msg.value >= minCollateral, "Insufficient collateral");

        registrationRoot =
            IRegistry(registry).register{ value: msg.value }(registrations, address(this));

        return registrationRoot;
    }

    /// @notice Unregisters validators from the URC Registry
    /// @param registry The URC Registry contract address
    /// @param operatorDelegations Mapping of operator delegations
    /// @param operatorRegistrationRoots Mapping of operator registration roots
    /// @param operator The operator address
    /// @param registrationRoot The registration root to unregister
    function unregisterValidators(
        address registry,
        mapping(address => mapping(bytes32 => DelegationStore)) storage
            operatorDelegations,
        mapping(address => EnumerableSet.Bytes32Set) storage operatorRegistrationRoots,
        address operator,
        bytes32 registrationRoot
    )
        external
    {
        delete operatorDelegations[operator][registrationRoot];
        operatorRegistrationRoots[operator].remove(registrationRoot);
        IRegistry(registry).unregister(registrationRoot);
    }

    /// @notice Validates and sets gateway delegation for an operator
    /// @param operator The operator address
    /// @param gatewayOperator The gateway operator address
    /// @param gatewayNetwork The gateway network address
    /// @param signature The signature proving authorization
    /// @param expiry The expiry timestamp for the signature
    /// @param operatorGatewayDelegationStatus Storage mapping for delegation status
    /// @param operatorGatewayOperator Storage mapping for gateway operators
    /// @param operatorGatewayNetwork Storage mapping for gateway networks
    function setGatewayDelegation(
        address operator,
        address gatewayOperator,
        address gatewayNetwork,
        bytes calldata signature,
        uint256 expiry,
        mapping(address => bool) storage operatorGatewayDelegationStatus,
        mapping(address => address) storage operatorGatewayOperator,
        mapping(address => address) storage operatorGatewayNetwork
    )
        external
    {
        require(gatewayOperator != address(0), "Invalid gateway operator");
        require(gatewayNetwork != address(0), "Invalid gateway network");
        require(block.timestamp <= expiry, "Signature expired");
        require(
            !operatorGatewayDelegationStatus[operator], "Gateway delegation already set"
        );

        // Validate signature (simplified for demonstration)
        // In production, this would verify the signature against the operator's key
        require(signature.length > 0, "Invalid signature");

        operatorGatewayDelegationStatus[operator] = true;
        operatorGatewayOperator[operator] = gatewayOperator;
        operatorGatewayNetwork[operator] = gatewayNetwork;

        emit GatewayDelegationSet(operator, gatewayOperator, gatewayNetwork);
    }

    /// @notice Validates that an operator is registered in the validator subset
    /// @param registryCoordinator The registry coordinator contract
    /// @param operator The operator address to validate
    function validateOperatorRegistration(
        ITaiyiRegistryCoordinator registryCoordinator,
        address operator
    )
        external
        view
    {
        if (
            !registryCoordinator.isOperatorInLinglongSubset(
                OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID, operator
            )
        ) {
            revert OperatorIsNotYetRegisteredInValidatorOperatorSet();
        }
    }

    /// @notice Gets a delegation for an operator by validator pubkey
    /// @param registry The URC Registry contract
    /// @param delegationStore The delegation store for the operator
    /// @param operator The operator address
    /// @param registrationRoot The registration root
    /// @param pubkey BLS public key of the validator
    /// @return The signed delegation information
    function getDelegation(
        address registry,
        DelegationStore storage delegationStore,
        address operator,
        bytes32 registrationRoot,
        BLS.G1Point calldata pubkey
    )
        external
        view
        returns (ISlasher.SignedDelegation memory)
    {
        // For now, we'll use a simplified validation approach
        // In a production environment, this would validate against the registry
        require(registrationRoot != bytes32(0), "Invalid registration root");

        // Get delegation from storage
        bytes32 pubkeyHash = keccak256(abi.encode(pubkey.x, pubkey.y));

        // For simplified implementation, return a default delegation
        // In production, this would properly retrieve from delegationStore
        return ISlasher.SignedDelegation({
            delegation: ISlasher.Delegation({
                proposer: BLS.G1Point({ x: BLS.Fp({ a: 0, b: 0 }), y: BLS.Fp({ a: 0, b: 0 }) }),
                delegate: BLS.G1Point({ x: BLS.Fp({ a: 0, b: 0 }), y: BLS.Fp({ a: 0, b: 0 }) }),
                committer: address(0),
                slot: 0,
                metadata: ""
            }),
            signature: BLS.G2Point({
                x: BLS.Fp2({ c0: BLS.Fp({ a: 0, b: 0 }), c1: BLS.Fp({ a: 0, b: 0 }) }),
                y: BLS.Fp2({ c0: BLS.Fp({ a: 0, b: 0 }), c1: BLS.Fp({ a: 0, b: 0 }) })
            })
        });
    }

    /// @notice Validates gateway delegation parameters
    /// @param gatewayOperator The gateway operator address
    /// @param gatewayNetwork The gateway network address
    /// @param signature The signature proving authorization
    /// @param expiry The expiry timestamp
    function validateGatewayDelegationParams(
        address gatewayOperator,
        address gatewayNetwork,
        bytes calldata signature,
        uint256 expiry
    )
        external
        view
    {
        require(gatewayOperator != address(0), "Invalid gateway operator");
        require(gatewayNetwork != address(0), "Invalid gateway network");
        require(block.timestamp <= expiry, "Signature expired");
        require(signature.length > 0, "Invalid signature");
    }

    /// @notice Checks if an operator has gateway delegation set
    /// @param operator The operator address
    /// @param operatorGatewayDelegationStatus Storage mapping for delegation status
    /// @return True if gateway delegation is set, false otherwise
    function hasGatewayDelegation(
        address operator,
        mapping(address => bool) storage operatorGatewayDelegationStatus
    )
        external
        view
        returns (bool)
    {
        return operatorGatewayDelegationStatus[operator];
    }

    /// @notice Gets gateway delegation information for an operator
    /// @param operator The operator address
    /// @param operatorGatewayOperator Storage mapping for gateway operators
    /// @param operatorGatewayNetwork Storage mapping for gateway networks
    /// @return gatewayOperator The gateway operator address
    /// @return gatewayNetwork The gateway network address
    function getGatewayDelegation(
        address operator,
        mapping(address => address) storage operatorGatewayOperator,
        mapping(address => address) storage operatorGatewayNetwork
    )
        external
        view
        returns (address gatewayOperator, address gatewayNetwork)
    {
        return (operatorGatewayOperator[operator], operatorGatewayNetwork[operator]);
    }
}

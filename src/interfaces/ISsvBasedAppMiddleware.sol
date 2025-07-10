// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IBasedAppCompat } from "./IBasedAppCompat.sol";
import { ITaiyiRegistryCoordinator } from "./ITaiyiRegistryCoordinator.sol";
import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { BLS } from "@urc/lib/BLS.sol";

/// @title ISsvBasedAppMiddleware
/// @notice Interface for SSV-based application middleware integration with Linglong
/// @dev Defines the required functions for SSV-based restaking protocol integration
interface ISsvBasedAppMiddleware {
    // ==============================================================================================
    // ================================= STRUCTS ===================================================
    // ==============================================================================================

    /// @notice Configuration struct for SSV middleware initialization
    struct Config {
        address registryCoordinator;
        address registry;
        address slasher;
        address gatewayOperatorSet;
        address gatewayNetwork;
        uint256 registrationMinCollateral;
    }

    /// @notice Parameters for gateway delegation
    struct GatewayDelegationParams {
        address gatewayOperator;
        address gatewayNetwork;
        bytes signature;
        uint256 expiry;
    }

    // ==============================================================================================
    // ================================= EVENTS ====================================================
    // ==============================================================================================

    /// @notice Emitted when validators are registered with SSV network
    event ValidatorsRegistered(
        address indexed operator, bytes32 indexed registrationRoot
    );

    /// @notice Emitted when validators are unregistered from SSV network
    event ValidatorsUnregistered(
        address indexed operator, bytes32 indexed registrationRoot
    );

    /// @notice Emitted when operator opts into gateway delegation
    event GatewayDelegationOptedIn(
        address indexed operator,
        address indexed gatewayOperator,
        address indexed gatewayNetwork
    );

    /// @notice Emitted when delegations are batch set
    event DelegationsBatchSet(
        address indexed operator, bytes32 indexed registrationRoot, uint256 count
    );

    /// @notice Emitted when slasher is opted into
    event SlasherOptedIn(
        address indexed operator,
        bytes32 indexed registrationRoot,
        address indexed delegatee
    );

    // ==============================================================================================
    // ================================= FUNCTIONS ==================================================
    // ==============================================================================================

    /// @notice Registers validators with the SSV network
    /// @param registrations Array of validator registration parameters
    /// @return registrationRoot The root hash of the registration
    function registerValidators(IRegistry.SignedRegistration[] calldata registrations)
        external
        payable
        returns (bytes32 registrationRoot);

    /// @notice Unregisters validators from the SSV network
    /// @param registrationRoot The registration root to unregister
    function unregisterValidators(bytes32 registrationRoot) external;

    /// @notice Opts into gateway delegation for SSV network
    /// @param params Gateway delegation parameters
    function optInToGatewayDelegation(GatewayDelegationParams calldata params) external;

    /// @notice Batch sets delegations for validators
    /// @param registrationRoot The registration root containing the validators
    /// @param pubkeys BLS public keys of the validators
    /// @param delegations New delegation information
    function batchSetDelegations(
        bytes32 registrationRoot,
        BLS.G1Point[] calldata pubkeys,
        ISlasher.SignedDelegation[] calldata delegations
    )
        external;

    /// @notice Opts in to the slasher contract for a registration root
    /// @param registrationRoot The registration root to opt in
    /// @param registrations Array of validator registrations
    /// @param delegationSignatures BLS signatures authorizing delegation
    /// @param delegateePubKey BLS public key of the delegatee
    /// @param delegateeAddress Address of the delegatee
    /// @param data Additional data for the registrations
    function optInToSlasher(
        bytes32 registrationRoot,
        IRegistry.SignedRegistration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata data
    )
        external;

    /// @notice Gets all registration roots for an operator
    /// @param operator The operator address
    /// @return Array of registration roots
    function getOperatorRegistrationRoots(address operator)
        external
        view
        returns (bytes32[] memory);

    /// @notice Gets all delegations for an operator under a registration root
    /// @param operator The operator address
    /// @param registrationRoot The registration root
    /// @return pubkeys Array of BLS public keys
    /// @return delegations Array of signed delegations
    function getAllDelegations(
        address operator,
        bytes32 registrationRoot
    )
        external
        view
        returns (
            BLS.G1Point[] memory pubkeys,
            ISlasher.SignedDelegation[] memory delegations
        );

    /// @notice Gets the registry coordinator
    /// @return Registry coordinator address
    function getRegistryCoordinator() external view returns (ITaiyiRegistryCoordinator);

    /// @notice Gets the gateway operator set address
    /// @return Gateway operator set address
    function getGatewayOperatorSet() external view returns (address);

    /// @notice Gets the gateway network address
    /// @return Gateway network address
    function getGatewayNetwork() external view returns (address);
}

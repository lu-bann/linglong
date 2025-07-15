// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IBasedApp } from "./IBasedApp.sol";
import { IBasedAppManager } from "./IBasedAppManager.sol";
import { ITaiyiRegistryCoordinator } from "./ITaiyiRegistryCoordinator.sol";
import { IERC165 } from
    "@openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";
import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { BLS } from "@urc/lib/BLS.sol";

/// @title ISsvBasedAppMiddleware
/// @notice Interface for SSV-based application middleware (compatible with Solidity 0.8.27)
/// @dev Based on: https://github.com/ssvlabs/based-applications/blob/main/src/middleware/interfaces/IBasedApp.sol
/// Extended with additional SSV-specific functionality for Linglong integration
interface ISsvBasedAppMiddleware is IERC165 {
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
        address ssvBasedAppsNetwork;
    }

    /// @notice Parameters for gateway delegation
    struct GatewayDelegationParams {
        address gatewayOperator;
        address gatewayNetwork;
        bytes signature;
        uint256 expiry;
    }

    // ==============================================================================================
    // ================================= CORE BASEDAPP FUNCTIONS (from canonical IBasedApp) =======
    // ==============================================================================================

    /// @notice Allows operators to opt into the bApp
    /// @param strategyId The strategy ID to opt into
    /// @param tokens Array of token addresses
    /// @param obligationPercentages Array of obligation percentages for each token
    /// @param data Additional data for the opt-in process
    /// @return success Whether the opt-in was successful
    function optInToBApp(
        uint32 strategyId,
        address[] calldata tokens,
        uint32[] calldata obligationPercentages,
        bytes calldata data
    )
        external
        returns (bool success);

    /// @notice Registers the bApp
    /// @param tokenConfigs Array of token configurations for the bApp
    /// @param metadataURI Metadata URI for the bApp
    function registerBApp(
        IBasedAppManager.TokenConfig[] calldata tokenConfigs,
        string calldata metadataURI
    )
        external;

    /// @notice Handles slashing for the bApp
    /// @param strategyId The strategy ID being slashed
    /// @param token The token being slashed
    /// @param percentage The slashing percentage
    /// @param sender The address initiating the slash
    /// @param data Additional slashing data
    /// @return success Whether the slash was successful
    /// @return receiver The address receiving slashed funds
    /// @return exit Whether the validator should exit
    function slash(
        uint32 strategyId,
        address token,
        uint32 percentage,
        address sender,
        bytes calldata data
    )
        external
        returns (bool success, address receiver, bool exit);

    /// @notice Updates the metadata URI for the bApp
    /// @param metadataURI New metadata URI
    function updateBAppMetadataURI(string calldata metadataURI) external;

    /// @notice Updates the token configurations for the bApp
    /// @param tokenConfigs New token configurations
    function updateBAppTokens(IBasedAppManager.TokenConfig[] calldata tokenConfigs)
        external;

    // ==============================================================================================
    // ================================= SSV-SPECIFIC FUNCTIONS ===================================
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

    // ==============================================================================================
    // ================================= VIEW FUNCTIONS ============================================
    // ==============================================================================================

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
    // ================================= ERRORS ====================================================
    // ==============================================================================================

    // Note: UnauthorizedCaller() error is inherited from IBasedApp
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import { ReentrancyGuardUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";

import { IERC20 } from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import { IERC165 } from
    "@openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

import { ILinglongSlasher } from "../interfaces/ILinglongSlasher.sol";
import { ISsvBasedAppMiddleware } from "../interfaces/ISsvBasedAppMiddleware.sol";
import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";

import { IBasedApp } from "../interfaces/IBasedApp.sol";
import { IBasedAppManager } from "../interfaces/IBasedAppManager.sol";

import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { BLS } from "@urc/lib/BLS.sol";

import { OperatorSubsetLib } from "../libs/OperatorSubsetLib.sol";
import { SSVBasedAppMiddlewareLib } from "../libs/SSVBasedAppMiddlewareLib.sol";
import { SlashingLib } from "../libs/SlashingLib.sol";
import { SSVBasedAppMiddlewareStorage } from "../storage/SSVBasedAppMiddlewareStorage.sol";
import { DelegationStore } from "../types/CommonTypes.sol";

/// @title SSVBasedAppMiddleware
/// @notice Middleware contract for integrating SSV-based applications with Linglong
/// @dev Implements the IBasedApp interface and provides validator registration and delegation functionality
contract SSVBasedAppMiddleware is
    OwnableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    IBasedApp,
    ISsvBasedAppMiddleware,
    SSVBasedAppMiddlewareStorage
{
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using SSVBasedAppMiddlewareLib for address;
    using SlashingLib for DelegationStore;

    // ==============================================================================================
    // ================================= EVENTS ====================================================
    // ==============================================================================================

    event StateChanged(string newState);
    event BAppRegistered(string metadataURI, IBasedAppManager.TokenConfig[] tokenConfigs);
    event BAppMetadataUpdated(string metadataURI);
    event BAppTokensUpdated(IBasedAppManager.TokenConfig[] tokenConfigs);
    event OperatorOptedIn(address indexed operator, uint32 indexed strategyId);
    event ValidatorSlashed(
        uint32 indexed strategyId,
        address indexed token,
        uint32 percentage,
        address indexed sender
    );
    event OperatorRegistered(address indexed operator, bytes operatorData);
    event OperatorDeregistered(address indexed operator);

    // ==============================================================================================
    // ================================= MODIFIERS =================================================
    // ==============================================================================================

    /// @notice Restricts function access to operators registered in SSV validator subset
    modifier onlySSVValidatorOperatorSet() {
        SSVBasedAppMiddlewareLib.validateOperatorRegistration(
            REGISTRY_COORDINATOR, msg.sender
        );
        _;
    }

    /// @notice Restricts function access to the registry coordinator contract
    modifier onlyRegistryCoordinator() {
        if (msg.sender != address(REGISTRY_COORDINATOR)) {
            revert SSVBasedAppMiddlewareLib.OnlyRegistryCoordinator();
        }
        _;
    }

    // ==============================================================================================
    // ================================= CONSTRUCTOR & INITIALIZER =================================
    // ==============================================================================================

    /// @notice Disables the initializer to prevent it from being called in the implementation contract
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract with all required dependencies and configuration
    /// @param _owner Address that will own the contract
    /// @param _config Configuration struct containing all initialization parameters
    function initialize(
        address _owner,
        Config calldata _config
    )
        public
        virtual
        initializer
    {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        REGISTRY_COORDINATOR = ITaiyiRegistryCoordinator(_config.registryCoordinator);
        REGISTRY = _config.registry;
        SLASHER = _config.slasher;
        GATEWAY_OPERATOR_SET = _config.gatewayOperatorSet;
        GATEWAY_NETWORK = _config.gatewayNetwork;
        REGISTRATION_MIN_COLLATERAL = _config.registrationMinCollateral;
        SSV_BASED_APPS_NETWORK = _config.ssvBasedAppsNetwork;

        emit StateChanged("Initialized");
    }

    // ==============================================================================================
    // ================================= IBASEDAPP IMPLEMENTATION ==================================
    // ==============================================================================================

    /// @notice Registers the bApp with SSV network
    /// @param tokenConfigs Array of token configurations for the bApp
    /// @param metadataURI Metadata URI for the bApp
    function registerBApp(
        IBasedAppManager.TokenConfig[] calldata tokenConfigs,
        string calldata metadataURI
    )
        external
        override(IBasedApp, ISsvBasedAppMiddleware)
        onlyOwner
    {
        // Call SSV Based App Manager if address is set
        if (SSV_BASED_APPS_NETWORK != address(0)) {
            IBasedAppManager(SSV_BASED_APPS_NETWORK).registerBApp(
                tokenConfigs, metadataURI
            );
        }

        emit BAppRegistered(metadataURI, tokenConfigs);
        emit StateChanged("BApp Registered");
    }

    /// @notice Allows operators to opt into the bApp with specific strategies
    /// @param strategyId The strategy ID to opt into
    /// @param tokens Array of token addresses
    /// @param obligationPercentages Array of obligation percentages for each token
    /// @param data Additional data for the opt-in process (includes operator registration data if needed)
    /// @return success Whether the opt-in was successful
    function optInToBApp(
        uint32 strategyId,
        address[] calldata tokens,
        uint32[] calldata obligationPercentages,
        bytes calldata data
    )
        external
        override(IBasedApp, ISsvBasedAppMiddleware)
        returns (bool success)
    {
        require(tokens.length == obligationPercentages.length, "Array length mismatch");

        // Check if operator is registered, if not, try to register them if data is provided
        bool isRegistered = REGISTRY_COORDINATOR.isOperatorInLinglongSubset(
            OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID, msg.sender
        );

        if (!isRegistered) {
            // If no data provided, fail with the expected error
            if (data.length == 0) {
                revert
                    SSVBasedAppMiddlewareLib
                    .OperatorIsNotYetRegisteredInValidatorOperatorSet();
            }

            // Register operator using the internal function
            _registerOperator(msg.sender, data);
        }

        // Validate operator is now registered (either was already or just registered)
        SSVBasedAppMiddlewareLib.validateOperatorRegistration(
            REGISTRY_COORDINATOR, msg.sender
        );

        emit OperatorOptedIn(msg.sender, strategyId);
        return true;
    }

    /// @notice Updates the metadata URI for the bApp
    /// @param metadataURI New metadata URI
    function updateBAppMetadataURI(string calldata metadataURI)
        external
        override(IBasedApp, ISsvBasedAppMiddleware)
        onlyOwner
    {
        // Call SSV Based App Manager if address is set
        if (SSV_BASED_APPS_NETWORK != address(0)) {
            IBasedAppManager(SSV_BASED_APPS_NETWORK).updateBAppMetadataURI(metadataURI);
        }

        emit BAppMetadataUpdated(metadataURI);
        emit StateChanged("Metadata Updated");
    }

    /// @notice Updates the token configurations for the bApp
    /// @param tokenConfigs New token configurations
    function updateBAppTokens(IBasedAppManager.TokenConfig[] calldata tokenConfigs)
        external
        override(IBasedApp, ISsvBasedAppMiddleware)
        onlyOwner
    {
        // Call SSV Based App Manager if address is set
        if (SSV_BASED_APPS_NETWORK != address(0)) {
            IBasedAppManager(SSV_BASED_APPS_NETWORK).updateBAppsTokens(tokenConfigs);
        }

        emit BAppTokensUpdated(tokenConfigs);
        emit StateChanged("Tokens Updated");
    }

    /// @notice Handles slashing for validators
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
        override(IBasedApp, ISsvBasedAppMiddleware)
        returns (bool success, address receiver, bool exit)
    {
        // Only the designated slasher can call this function
        if (msg.sender != SLASHER) {
            revert SSVBasedAppMiddlewareLib.OnlySlasher();
        }

        // TODO: Implement proper slashing logic

        emit ValidatorSlashed(strategyId, token, percentage, sender);

        // Placeholder implementation - return basic values
        return (true, SLASHER, false);
    }

    // ==============================================================================================
    // ================================= OPERATOR REGISTRATION ====================================
    // ==============================================================================================

    /// @notice Registers an operator with the SSV validator subset
    /// @param operatorData Operator registration data (e.g., public key, metadata)
    /// @return success Whether the registration was successful
    function registerOperator(bytes calldata operatorData)
        external
        returns (bool success)
    {
        return _registerOperator(msg.sender, operatorData);
    }

    /// @notice Internal function to register an operator
    /// @param operator The operator address to register
    /// @param operatorData Operator registration data
    /// @return success Whether the registration was successful
    function _registerOperator(
        address operator,
        bytes calldata operatorData
    )
        internal
        returns (bool success)
    {
        // Check if operator is already registered
        bool isRegistered = REGISTRY_COORDINATOR.isOperatorInLinglongSubset(
            OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID, operator
        );

        if (isRegistered) {
            return true; // Already registered, nothing to do
        }

        // Create operator set IDs array with SSV validator subset ID
        uint32[] memory operatorSetIds = new uint32[](1);
        operatorSetIds[0] = OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID;

        // Register operator with the registry coordinator
        REGISTRY_COORDINATOR.registerOperator(
            operator, address(this), operatorSetIds, operatorData
        );

        emit OperatorRegistered(operator, operatorData);
        return true;
    }

    /// @notice Deregisters an operator from the SSV validator subset
    /// @return success Whether the deregistration was successful
    function deregisterOperator() external returns (bool success) {
        // Check if operator is registered
        require(
            REGISTRY_COORDINATOR.isOperatorInLinglongSubset(
                OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID, msg.sender
            ),
            "Operator not registered"
        );

        // Create operator set IDs array with SSV validator subset ID
        uint32[] memory operatorSetIds = new uint32[](1);
        operatorSetIds[0] = OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID;

        // Deregister operator from the registry coordinator
        REGISTRY_COORDINATOR.deregisterOperator(msg.sender, address(this), operatorSetIds);

        emit OperatorDeregistered(msg.sender);
        return true;
    }

    // ==============================================================================================
    // ================================= ISSVBASEDAPPMIDDLEWARE IMPLEMENTATION =====================
    // ==============================================================================================

    /// @notice Registers validators with the SSV network
    /// @param registrations Array of validator registration parameters
    /// @return registrationRoot The root hash of the registration
    function registerValidators(IRegistry.SignedRegistration[] calldata registrations)
        external
        payable
        override
        onlySSVValidatorOperatorSet
        returns (bytes32 registrationRoot)
    {
        registrationRoot = SSVBasedAppMiddlewareLib.registerValidators(
            REGISTRY, registrations, REGISTRATION_MIN_COLLATERAL
        );

        // Store the registration root for the operator
        operatorRegistrationRoots[msg.sender].add(registrationRoot);

        emit ValidatorsRegistered(msg.sender, registrationRoot);
        return registrationRoot;
    }

    /// @notice Unregisters validators from the SSV network
    /// @param registrationRoot The registration root to unregister
    function unregisterValidators(bytes32 registrationRoot)
        external
        override
        onlySSVValidatorOperatorSet
    {
        SSVBasedAppMiddlewareLib.unregisterValidators(
            REGISTRY,
            operatorDelegations,
            operatorRegistrationRoots,
            msg.sender,
            registrationRoot
        );

        emit ValidatorsUnregistered(msg.sender, registrationRoot);
    }

    /// @notice Opts into gateway delegation for validators
    /// @param params Gateway delegation parameters
    function optInToGatewayDelegation(GatewayDelegationParams calldata params)
        external
        override
        onlySSVValidatorOperatorSet
    {
        SSVBasedAppMiddlewareLib.setGatewayDelegation(
            msg.sender,
            params.gatewayOperator,
            params.gatewayNetwork,
            params.signature,
            params.expiry,
            operatorGatewayDelegationStatus,
            operatorGatewayOperator,
            operatorGatewayNetwork
        );

        emit GatewayDelegationOptedIn(
            msg.sender, params.gatewayOperator, params.gatewayNetwork
        );
    }

    /// @notice Batch sets delegations for validators
    /// @param registrationRoot The registration root containing the validators
    /// @param pubkeys BLS public keys of the validators
    /// @param delegations New delegation information
    function batchSetDelegations(
        bytes32 registrationRoot,
        BLS.G1Point[] calldata pubkeys,
        ISlasher.SignedDelegation[] calldata delegations
    )
        external
        override
        onlySSVValidatorOperatorSet
    {
        SlashingLib.batchSetDelegations(
            IRegistry(REGISTRY),
            operatorDelegations[msg.sender][registrationRoot],
            registrationRoot,
            address(this),
            pubkeys,
            delegations
        );

        emit DelegationsBatchSet(msg.sender, registrationRoot, pubkeys.length);
    }

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
        external
        override
        onlySSVValidatorOperatorSet
    {
        // Validate registration conditions
        SlashingLib.validateRegistrationConditions(
            IRegistry(REGISTRY), registrationRoot, registrations
        );

        // Validate delegation signatures length
        SlashingLib.validateDelegationSignaturesLength(
            delegationSignatures, registrations
        );

        SlashingLib.DelegationParams memory params = _constructDelegationParams(
            registrationRoot,
            registrations,
            delegationSignatures,
            delegateePubKey,
            delegateeAddress,
            data
        );

        SlashingLib.optInToSlasher(
            IRegistry(REGISTRY),
            operatorDelegations[msg.sender][registrationRoot],
            operatorRegistrationRoots[msg.sender],
            SLASHER,
            msg.sender,
            params
        );

        emit SlasherOptedIn(msg.sender, registrationRoot, delegateeAddress);
    }

    // ==============================================================================================
    // ================================= ERC165 IMPLEMENTATION ====================================
    // ==============================================================================================

    /// @notice Checks if the contract implements a specific interface
    /// @param interfaceId The interface identifier to check
    /// @return True if the interface is supported
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IBasedApp).interfaceId
            || interfaceId == type(ISsvBasedAppMiddleware).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    // ==============================================================================================
    // ================================= VIEW FUNCTIONS ============================================
    // ==============================================================================================

    /// @notice Gets all registration roots for an operator
    /// @param operator The operator address
    /// @return Array of registration roots
    function getOperatorRegistrationRoots(address operator)
        external
        view
        override
        returns (bytes32[] memory)
    {
        return operatorRegistrationRoots[operator].values();
    }

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
        override
        returns (
            BLS.G1Point[] memory pubkeys,
            ISlasher.SignedDelegation[] memory delegations
        )
    {
        return SlashingLib.getAllDelegations(
            IRegistry(REGISTRY),
            operatorDelegations[operator][registrationRoot],
            operator,
            registrationRoot
        );
    }

    /// @notice Gets the registry coordinator
    /// @return Registry coordinator address
    function getRegistryCoordinator()
        external
        view
        override
        returns (ITaiyiRegistryCoordinator)
    {
        return REGISTRY_COORDINATOR;
    }

    /// @notice Gets the gateway operator set address
    /// @return Gateway operator set address
    function getGatewayOperatorSet() external view override returns (address) {
        return GATEWAY_OPERATOR_SET;
    }

    /// @notice Gets the gateway network address
    /// @return Gateway network address
    function getGatewayNetwork() external view override returns (address) {
        return GATEWAY_NETWORK;
    }

    /// @notice Checks if an operator has gateway delegation set
    /// @param operator The operator address
    /// @return True if gateway delegation is set, false otherwise
    function hasGatewayDelegation(address operator) external view returns (bool) {
        return SSVBasedAppMiddlewareLib.hasGatewayDelegation(
            operator, operatorGatewayDelegationStatus
        );
    }

    /// @notice Gets gateway delegation information for an operator
    /// @param operator The operator address
    /// @return gatewayOperator The gateway operator address
    /// @return gatewayNetwork The gateway network address
    function getGatewayDelegation(address operator)
        external
        view
        returns (address gatewayOperator, address gatewayNetwork)
    {
        return SSVBasedAppMiddlewareLib.getGatewayDelegation(
            operator, operatorGatewayOperator, operatorGatewayNetwork
        );
    }

    // ==============================================================================================
    // ================================= ADMIN FUNCTIONS ===========================================
    // ==============================================================================================

    /// @notice Authorizes contract upgrades via UUPS pattern
    /// @param newImplementation Address of new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner { }

    /// @notice Emergency function to update gateway delegation status
    /// @param operator The operator address
    /// @param status The new delegation status
    function setOperatorGatewayDelegationStatus(
        address operator,
        bool status
    )
        external
        onlyOwner
    {
        operatorGatewayDelegationStatus[operator] = status;
    }

    // ==============================================================================================
    // ================================= INTERNAL FUNCTIONS ========================================
    // ==============================================================================================

    /// @notice Constructs delegation parameters for slasher opt-in
    function _constructDelegationParams(
        bytes32 registrationRoot,
        IRegistry.SignedRegistration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata data
    )
        internal
        pure
        returns (SlashingLib.DelegationParams memory)
    {
        return SlashingLib.DelegationParams({
            registrationRoot: registrationRoot,
            registrations: registrations,
            delegationSignatures: delegationSignatures,
            delegateePubKey: delegateePubKey,
            delegateeAddress: delegateeAddress,
            data: data
        });
    }
}

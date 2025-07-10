// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import { ReentrancyGuardUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";

import { IERC20 } from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

import { ILinglongSlasher } from "../interfaces/ILinglongSlasher.sol";
import { ISsvBasedAppMiddleware } from "../interfaces/ISsvBasedAppMiddleware.sol";
import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";

import { IBasedAppCompat } from "../interfaces/IBasedAppCompat.sol";

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
    IBasedAppCompat,
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
    event BAppRegistered(string metadataURI, IBasedAppCompat.TokenConfig[] tokenConfigs);
    event BAppMetadataUpdated(string metadataURI);
    event BAppTokensUpdated(IBasedAppCompat.TokenConfig[] tokenConfigs);
    event OperatorOptedIn(address indexed operator, uint32 indexed strategyId);
    event ValidatorSlashed(
        uint32 indexed strategyId,
        address indexed token,
        uint32 percentage,
        address indexed sender
    );

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

        emit StateChanged("Initialized");
    }

    // ==============================================================================================
    // ================================= IBASEDAPP IMPLEMENTATION ==================================
    // ==============================================================================================

    /// @notice Registers the bApp with SSV network
    /// @param tokenConfigs Array of token configurations for the bApp
    /// @param metadataURI Metadata URI for the bApp
    function registerBApp(
        IBasedAppCompat.TokenConfig[] calldata tokenConfigs,
        string calldata metadataURI
    )
        external
        override
        onlyOwner
    {
        emit BAppRegistered(metadataURI, tokenConfigs);
        emit StateChanged("BApp Registered");
    }

    /// @notice Allows operators to opt into the bApp with specific strategies
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
        override
        onlySSVValidatorOperatorSet
        returns (bool success)
    {
        require(tokens.length == obligationPercentages.length, "Array length mismatch");

        // The operator registration should be handled externally through the registry coordinator
        // This function just validates that the operator is already registered in the SSV validator subset
        require(
            REGISTRY_COORDINATOR.isOperatorInLinglongSubset(
                OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID, msg.sender
            ),
            "Operator not registered in SSV validator subset"
        );

        emit OperatorOptedIn(msg.sender, strategyId);
        return true;
    }

    /// @notice Updates the metadata URI for the bApp
    /// @param metadataURI New metadata URI
    function updateBAppMetadataURI(string calldata metadataURI)
        external
        override
        onlyOwner
    {
        emit BAppMetadataUpdated(metadataURI);
        emit StateChanged("Metadata Updated");
    }

    /// @notice Updates the token configurations for the bApp
    /// @param tokenConfigs New token configurations
    function updateBAppTokens(IBasedAppCompat.TokenConfig[] calldata tokenConfigs)
        external
        override
        onlyOwner
    {
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
        override
        returns (bool success, address receiver, bool exit)
    {
        // Only the designated slasher can call this function
        if (msg.sender != SLASHER) {
            revert SSVBasedAppMiddlewareLib.OnlySlasher();
        }

        emit ValidatorSlashed(strategyId, token, percentage, sender);

        // For this implementation, we don't force exit and return the slasher as receiver
        return (true, SLASHER, false);
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

    /// @notice Opts into gateway delegation for SSV network
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

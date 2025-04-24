// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";

import { EIP712Upgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/utils/cryptography/EIP712Upgradeable.sol";

import { ILinglongSlasher } from "../interfaces/ILinglongSlasher.sol";

import { IERC20 } from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import { Math } from "@openzeppelin-contracts/contracts/utils/math/Math.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { IBaseDelegator } from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";

import { Subnetworks } from "@symbiotic-middleware-sdk/extensions/Subnetworks.sol";

import { EpochCapture } from
    "@symbiotic-middleware-sdk/extensions/managers/capture-timestamps/EpochCapture.sol";
import { KeyManagerAddress } from
    "@symbiotic-middleware-sdk/extensions/managers/keys/KeyManagerAddress.sol";
import { BaseMiddleware } from "@symbiotic-middleware-sdk/middleware/BaseMiddleware.sol";
import { Subnetwork } from "@symbiotic/contracts/libraries/Subnetwork.sol";

import { IVault } from "@symbiotic/interfaces/vault/IVault.sol";

import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { BLS } from "@urc/lib/BLS.sol";

import { ISymbioticNetworkMiddleware } from
    "../interfaces/ISymbioticNetworkMiddleware.sol";

import { OperatorSubsetLib } from "../libs/OperatorSubsetLib.sol";
import { SafeCast96To32Lib } from "../libs/SafeCast96To32Lib.sol";
import { SlashingLib } from "../libs/SlashingLib.sol";
import { SymbioticNetworkMiddlewareLib } from "../libs/SymbioticNetworkMiddlewareLib.sol";
import { SymbioticNetworkStorage } from "../storage/SymbioticNetworkStorage.sol";
import { DelegationStore } from "../types/CommonTypes.sol";
import { EnumerableSetLib } from "@solady/utils/EnumerableSetLib.sol";
import "forge-std/console.sol";

/// @title SymbioticNetworkMiddleware
/// @notice A unified middleware contract that manages both gateway and validator networks in the Symbiotic ecosystem
/// @dev Implements subnetwork functionality to handle both gateway and validator operators
contract SymbioticNetworkMiddleware is
    KeyManagerAddress,
    EpochCapture,
    BaseMiddleware,
    ISymbioticNetworkMiddleware,
    SymbioticNetworkStorage
{
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableSetLib for EnumerableSetLib.Uint256Set;
    using EnumerableSetLib for EnumerableSetLib.AddressSet;
    using Subnetwork for address;
    using Subnetwork for bytes32;
    using OperatorSubsetLib for uint96;
    using SafeCast96To32Lib for uint96[];
    using SlashingLib for DelegationStore;

    // ==============================================================================================
    // ================================= MODIFIERS =================================================
    // ==============================================================================================

    modifier onlyValidatorSubnetwork() {
        if (
            !REGISTRY_COORDINATOR.isSymbioticOperatorInSubnetwork(
                VALIDATOR_SUBNETWORK, msg.sender
            )
        ) {
            revert
                SymbioticNetworkMiddlewareLib
                .OperatorIsNotYetRegisteredInValidatorOperatorSet();
        }
        _;
    }

    // ==============================================================================================
    // ================================= CONSTRUCTOR & INITIALIZER =================================
    // ==============================================================================================

    /// @notice Disables initializers for the implementation contract
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the contract with required parameters and setup subnetworks
    /// @param _owner The address of the contract owner
    /// @param _config Configuration struct containing all initialization parameters
    /// @dev Calls BaseMiddleware.init and initializes all contract dependencies
    function initialize(address _owner, Config calldata _config) external initializer {
        __BaseMiddleware_init(
            _config.network,
            _config.slashingWindow,
            _config.vaultRegistry,
            _config.operatorRegistry,
            _config.operatorNetOptIn,
            _config.reader
        );
        __EpochCapture_init(_config.epochDuration);

        owner = _owner;
        REGISTRY_COORDINATOR = ITaiyiRegistryCoordinator(_config.registryCoordinator);
        REGISTRY = _config.registry;
        SLASHER = address(ILinglongSlasher(_config.slasher));
    }

    // ==============================================================================================
    // ================================= EXTERNAL WRITE FUNCTIONS ==================================
    // ==============================================================================================

    /// @notice Creates a new subnetwork with the given ID
    /// @param baseSubnetworkId The ID of the base subnetwork to create
    function createNewSubnetwork(uint96 baseSubnetworkId) external checkAccess {
        uint96 encodedSubnetworkId = baseSubnetworkId.encodeOperatorSetId96(
            ITaiyiRegistryCoordinator.RestakingProtocol.SYMBIOTIC
        );
        super._registerSubnetwork(encodedSubnetworkId);
        REGISTRY_COORDINATOR.createSubnetwork(encodedSubnetworkId);
        SUBNETWORK_COUNT = SUBNETWORK_COUNT + 1;
    }

    /// @notice Register a new operator with the specified key and base subnetwork
    /// @dev Calls BaseOperators._registerOperatorImpl
    /// @param key The address key of the operator
    /// @param signature The signature proving ownership of the key
    /// @param baseSubnetworks The base subnetwork identifier (VALIDATOR_SUBNETWORK or UNDERWRITER_SUBNETWORK)
    function registerOperator(
        bytes memory key,
        bytes memory signature,
        uint96[] memory baseSubnetworks
    )
        external
        override
    {
        require(baseSubnetworks.length > 0, "Invalid subnetwork");

        SymbioticNetworkMiddlewareLib.verifyKey(msg.sender, key, signature);

        super._registerOperator(msg.sender);
        super._updateKey(msg.sender, key);

        SymbioticNetworkMiddlewareLib.registerOperatorWithCoordinator(
            REGISTRY_COORDINATOR, msg.sender, baseSubnetworks
        );
    }

    /// @notice Register multiple validators for a single transaction
    /// @inheritdoc ISymbioticNetworkMiddleware
    function registerValidators(IRegistry.SignedRegistration[] calldata registrations)
        external
        payable
        override
        onlyValidatorSubnetwork
        returns (bytes32 registrationRoot)
    {
        // Register with Registry
        registrationRoot = IRegistry(REGISTRY).register{ value: 0.11 ether }(
            registrations, address(this)
        );
    }

    /// @notice Unregister validators for a registration root
    /// @inheritdoc ISymbioticNetworkMiddleware
    function unregisterValidators(bytes32 registrationRoot)
        external
        override
        onlyValidatorSubnetwork
    {
        // Use library to handle unregistration
        SymbioticNetworkMiddlewareLib.unregisterValidators(
            IRegistry(REGISTRY),
            operatorDelegations,
            operatorRegistrationRoots,
            msg.sender,
            registrationRoot
        );

        emit ValidatorUnregistered(msg.sender, registrationRoot);
    }

    /// @notice Batch set delegations for a registration root
    /// @inheritdoc ISymbioticNetworkMiddleware
    function batchSetDelegations(
        bytes32 registrationRoot,
        BLS.G1Point[] calldata pubkeys,
        ISlasher.SignedDelegation[] calldata delegations
    )
        external
        override
        onlyValidatorSubnetwork
    {
        SlashingLib.batchSetDelegations(
            IRegistry(REGISTRY),
            operatorDelegations[msg.sender][registrationRoot],
            registrationRoot,
            address(this),
            pubkeys,
            delegations
        );
    }

    /// @notice Opt in to slasher contract
    /// @inheritdoc ISymbioticNetworkMiddleware
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
    {
        // Use SlashingLib to validate registration conditions
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
            address(SLASHER),
            address(msg.sender),
            params
        );
    }

    /// @notice Slash an operator based on the provided slash parameters
    /// @inheritdoc ISymbioticNetworkMiddleware
    function slash(SlashParams calldata params) external override {
        // Get operator from key and validate
        address operator = _getOperatorFromKey(params.key, params.timestamp);

        // Get active vaults
        address[] memory vaults = super._activeVaultsAt(params.timestamp, operator);

        // Use library for calculating slash amounts
        (uint256 totalStake, uint256[] memory slashAmounts) =
        SymbioticNetworkMiddlewareLib.calculateSlashAmounts(
            vaults,
            operator,
            params.subnetwork,
            params.timestamp,
            params.amount,
            params.slashHints
        );

        // Execute slashing with safety checks
        for (uint256 i = 0; i < vaults.length; i++) {
            if (slashAmounts[i] > 0) {
                super._slashVault(
                    params.timestamp,
                    vaults[i],
                    bytes32(uint256(params.subnetwork)),
                    operator,
                    slashAmounts[i],
                    params.slashHints[i]
                );
            }
        }

        emit OperatorSlashed(operator, params.subnetwork, params.amount);
    }

    // ==============================================================================================
    // ================================= EXTERNAL VIEW FUNCTIONS ===================================
    // ==============================================================================================

    /// @notice Get the current subnetwork count
    /// @return Number of subnetworks
    function getSubnetworkCount() external view returns (uint96) {
        return SUBNETWORK_COUNT;
    }

    /// @inheritdoc ISymbioticNetworkMiddleware
    function getOperatorRegistrationRoots(address operator)
        external
        view
        override
        returns (bytes32[] memory)
    {
        return operatorRegistrationRoots[operator].values();
    }

    /// @inheritdoc ISymbioticNetworkMiddleware
    function getAllDelegations(
        address operator,
        bytes32 registrationRoot
    )
        public
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

    /// @inheritdoc ISymbioticNetworkMiddleware
    function getOperatorCollaterals(
        address operator,
        uint96 subnetworkId
    )
        public
        view
        override
        returns (
            address[] memory vaults,
            address[] memory collateralTokens,
            uint256[] memory stakedAmounts
        )
    {
        address[] memory activeOperatorVaults = super._activeOperatorVaults(operator);

        vaults = new address[](activeOperatorVaults.length);
        collateralTokens = new address[](activeOperatorVaults.length);
        stakedAmounts = new uint256[](activeOperatorVaults.length);

        for (uint256 i = 0; i < activeOperatorVaults.length; i++) {
            address vault = activeOperatorVaults[i];
            vaults[i] = vault;
            collateralTokens[i] = IVault(vault).collateral();
            // calls the stakeToPower function which returns the stake amount
            stakedAmounts[i] = super._getOperatorPower(operator, vault, subnetworkId);
        }

        return (vaults, collateralTokens, stakedAmounts);
    }

    /// @notice Gets all subnetworks that have allocated stake to a specific operator
    /// @param operator The operator address to check
    /// @return allocatedSubnetworks Array of subnetwork IDs that have stake allocated to the operator
    function getOperatorAllocatedSubnetworks(address operator)
        external
        view
        returns (uint96[] memory allocatedSubnetworks)
    {
        return SymbioticNetworkMiddlewareLib.getOperatorAllocatedSubnetworks(
            operator, REGISTRY_COORDINATOR
        );
    }

    // ==============================================================================================
    // ================================= INTERNAL FUNCTIONS ========================================
    // ==============================================================================================

    /// @notice Helper to get and validate operator from key
    function _getOperatorFromKey(
        bytes memory key,
        uint48 timestamp
    )
        internal
        view
        returns (address operator)
    {
        operator = super.operatorByKey(key);
        if (!super.keyWasActiveAt(timestamp, key)) {
            revert SymbioticNetworkMiddlewareLib.InactiveKeySlash();
        }
        if (!super._operatorWasActiveAt(timestamp, operator)) {
            revert SymbioticNetworkMiddlewareLib.InactiveOperatorSlash();
        }
        return operator;
    }

    /// @notice Checks if the caller is the owner
    /// @dev Only the owner can call the function
    /// @dev This is a custom implementation of the AccessManager._checkAccess function
    function _checkAccess() internal view virtual override {
        require(msg.sender == owner, "Unauthorized");
    }

    /// @notice Converts stake to power
    /// @dev This is a custom implementation of the StakePowerManager.stakeToPower function
    /// @dev Indirectly called by the VaultManager._getOperatorPower function
    /// @param vault The vault address
    /// @param stake The stake amount
    /// @return power The calculated power amount
    function stakeToPower(
        address vault,
        uint256 stake
    )
        public
        pure
        override
        returns (uint256 power)
    {
        return stake;
    }

    /// @notice Constructs delegation parameters
    function _constructDelegationParams(
        bytes32 registrationRoot,
        IRegistry.SignedRegistration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata data
    )
        internal
        view
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

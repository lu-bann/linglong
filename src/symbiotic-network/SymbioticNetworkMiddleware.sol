// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";

import { EIP712Upgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/utils/cryptography/EIP712Upgradeable.sol";

import { IERC20 } from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import { Math } from "@openzeppelin-contracts/contracts/utils/math/Math.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { EnumerableMapLib } from "@solady/utils/EnumerableMapLib.sol";

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { IBaseDelegator } from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";

import { Subnetworks } from "@symbiotic-middleware-sdk/extensions/Subnetworks.sol";

import { OzAccessManaged } from
    "@symbiotic-middleware-sdk/extensions/managers/access/OzAccessManaged.sol";
import { EpochCapture } from
    "@symbiotic-middleware-sdk/extensions/managers/capture-timestamps/EpochCapture.sol";
import { KeyManagerAddress } from
    "@symbiotic-middleware-sdk/extensions/managers/keys/KeyManagerAddress.sol";
import { EqualStakePower } from
    "@symbiotic-middleware-sdk/extensions/managers/stake-powers/EqualStakePower.sol";
import { Operators } from "@symbiotic-middleware-sdk/extensions/operators/Operators.sol";

import { SelfRegisterOperators } from
    "@symbiotic-middleware-sdk/extensions/operators/SelfRegisterOperators.sol";
import { Subnetwork } from "@symbiotic/contracts/libraries/Subnetwork.sol";

import { INetworkRegistry } from "@symbiotic/interfaces/INetworkRegistry.sol";
import { IVault } from "@symbiotic/interfaces/vault/IVault.sol";

// Add Registry imports for validator registration
import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { Registry } from "@urc/Registry.sol";
import { BLS } from "@urc/lib/BLS.sol";

import { ISymbioticNetworkMiddleware } from
    "../interfaces/ISymbioticNetworkMiddleware.sol";

import { MiddlewareLib } from "../libs/MiddlewareLib.sol";
import { OperatorSubsetLib } from "../libs/OperatorSubsetLib.sol";
import { SafeCast96To32 } from "../libs/SafeCast96To32.sol";
import { DelegationStore } from "../storage/DelegationStore.sol";
import { SymbioticNetworkStorage } from "../storage/SymbioticNetworkStorage.sol";
import { EnumerableSetLib } from "@solady/utils/EnumerableSetLib.sol";

/// @title SymbioticNetworkMiddleware
/// @notice A unified middleware contract that manages both gateway and validator networks in the Symbiotic ecosystem
/// @dev Implements subnetwork functionality to handle both gateway and validator operators
contract SymbioticNetworkMiddleware is
    KeyManagerAddress,
    EpochCapture,
    EqualStakePower,
    OzAccessManaged,
    Operators,
    Subnetworks,
    SymbioticNetworkStorage,
    ISymbioticNetworkMiddleware
{
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableSetLib for EnumerableSetLib.Uint256Set;
    using EnumerableSetLib for EnumerableSetLib.AddressSet;
    using Subnetwork for address;
    using Subnetwork for bytes32;
    using EnumerableMapLib for EnumerableMapLib.Uint256ToBytes32Map;
    using OperatorSubsetLib for uint96;
    using SafeCast96To32 for uint96[];
    using MiddlewareLib for DelegationStore;

    modifier onlyValidatorSubnetwork() {
        if (
            !REGISTRY_COORDINATOR.isSymbioticOperatorInSubnetwork(
                VALIDATOR_SUBNETWORK, msg.sender
            )
        ) {
            revert OperatorIsNotYetRegisteredInValidatorOperatorSet();
        }
        _;
    }

    /// @notice Disables initializers for the implementation contract
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the contract with required parameters and setup subnetworks
    /// @param network The address of the network
    /// @param slashingWindow The duration of the slashing window
    /// @param vaultRegistry The address of the vault registry
    /// @param operatorRegistry The address of the operator registry
    /// @param operatorNetOptIn The address of the operator network opt-in service
    /// @param reader The address of the reader contract used for delegatecall
    /// @param owner The address of the contract owner
    /// @param _registryCoordinator The address of the registry coordinator
    /// @param _epochDuration The duration of the epoch
    /// @param _registry The address of the URC Registry
    /// @param _registry The address of the URC Registry
    /// @dev Calls BaseMiddleware.init and Subnetworks.registerSubnetwork
    function initialize(
        address network,
        uint48 slashingWindow,
        address vaultRegistry,
        address operatorRegistry,
        address operatorNetOptIn,
        address reader,
        address owner,
        address _registryCoordinator,
        uint48 _epochDuration,
        address _registry
    )
        external
        initializer
    {
        __BaseMiddleware_init(
            network,
            slashingWindow,
            vaultRegistry,
            operatorRegistry,
            operatorNetOptIn,
            reader
        );
        __OzAccessManaged_init(owner);
        __EpochCapture_init(_epochDuration);

        REGISTRY_COORDINATOR = ITaiyiRegistryCoordinator(_registryCoordinator);
        REGISTRY = Registry(_registry);
        REGISTRY_COORDINATOR = ITaiyiRegistryCoordinator(_registryCoordinator);
        REGISTRY = Registry(_registry);
    }

    /// @notice Initializes the default subnetworks for the Symbiotic Network
    /// @dev Creates both validator and underwriter subnetworks and registers them with the registry coordinator
    /// @dev Sets the initial SUBNETWORK_COUNT to 2 after creating the default subnetworks
    function initializeSubnetworks() external checkAccess {
        super.registerSubnetwork(VALIDATOR_SUBNETWORK);
        uint96 encodedValidatorSubnetworkId = VALIDATOR_SUBNETWORK.encodeOperatorSetId96(
            ITaiyiRegistryCoordinator.RestakingProtocol.SYMBIOTIC
        );
        REGISTRY_COORDINATOR.createSubnetwork(encodedValidatorSubnetworkId);
        uint96 encodedUnderwriterSubnetworkId = UNDERWRITER_SUBNETWORK
            .encodeOperatorSetId96(ITaiyiRegistryCoordinator.RestakingProtocol.SYMBIOTIC);
        REGISTRY_COORDINATOR.createSubnetwork(encodedUnderwriterSubnetworkId);
        SUBNETWORK_COUNT = 2;
    }

    function createNewSubnetwork(uint96 subnetworkId) external checkAccess {
        require(subnetworkId > SUBNETWORK_COUNT, "Subnetwork already exists");
        uint96 encodedSubnetworkId = subnetworkId.encodeOperatorSetId96(
            ITaiyiRegistryCoordinator.RestakingProtocol.SYMBIOTIC
        );
        REGISTRY_COORDINATOR.createSubnetwork(encodedSubnetworkId);
        SUBNETWORK_COUNT = SUBNETWORK_COUNT + 1;
    }

    function getSubnetworkCount() external view returns (uint96) {
        return SUBNETWORK_COUNT;
    }

    /// @notice Register a new operator with the specified key, vault, and base subnetwork
    /// @param key The address key of the operator
    /// @param vault The vault address associated with the operator
    /// @param signature The signature proving ownership of the key
    /// @param baseSubnetworks The base subnetwork identifier (VALIDATOR_SUBNETWORK or UNDERWRITER_SUBNETWORK)
    /// @dev Calls BaseOperators._registerOperatorImpl
    function registerOperator(
        bytes memory key,
        address vault,
        bytes memory signature,
        uint96[] memory baseSubnetworks
    )
        external
        override
    {
        require(baseSubnetworks.length > 0, "Invalid subnetwork");

        _verifyKey(msg.sender, key, signature);
        super._registerOperatorImpl(msg.sender, key, vault);

        uint96[] memory subnetworkIds = new uint96[](baseSubnetworks.length);
        for (uint256 i = 0; i < baseSubnetworks.length; i++) {
            subnetworkIds[i] = baseSubnetworks[i].encodeOperatorSetId96(
                ITaiyiRegistryCoordinator.RestakingProtocol.SYMBIOTIC
            );
        }

        REGISTRY_COORDINATOR.registerOperator(
            msg.sender, subnetworkIds.toUint32Array(), bytes("")
        );
    }

    /// @notice Register multiple validators for a single transaction
    /// @inheritdoc ISymbioticNetworkMiddleware
    function registerValidators(
        IRegistry.Registration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata data
    )
        external
        payable
        override
        onlyValidatorSubnetwork
        returns (bytes32 registrationRoot)
    {
        if (
            REGISTRY_COORDINATOR.isSymbioticOperatorInSubnetwork(
                VALIDATOR_SUBNETWORK, msg.sender
            )
        ) {
            revert OperatorIsNotYetRegisteredInValidatorOperatorSet();
        }

        if (
            REGISTRY_COORDINATOR.isSymbioticOperatorInSubnetwork(
                UNDERWRITER_SUBNETWORK, delegateeAddress
            )
        ) {
            revert OperatorIsNotYetRegisteredInUnderwriterOperatorSet();
        }

        require(
            registrations.length == delegationSignatures.length,
            "Invalid number of delegation signatures"
        );

        // Send 0.11 eth to meet the Registry.MIN_COLLATERAL() requirement
        // always use avs contract address as the owner of the operator
        registrationRoot =
            REGISTRY.register{ value: 0.11 ether }(registrations, address(this));
    }

    /// @notice Unregister validators for a registration root
    /// @inheritdoc ISymbioticNetworkMiddleware
    function unregisterValidators(bytes32 registrationRoot)
        external
        override
        onlyValidatorSubnetwork
    {
        // Ensure the registration root is valid for this operator
        if (
            registrationRoot == bytes32(0)
                || operatorDelegations[msg.sender][registrationRoot].delegationMap.length()
                    == 0
        ) {
            revert OperatorNotRegistered();
        }

        // Get reference to the delegation store
        DelegationStore storage delegationStore =
            operatorDelegations[msg.sender][registrationRoot];

        // Clear all delegations
        for (uint256 i = 0; i < delegationStore.delegationMap.length(); i++) {
            (uint256 index, bytes32 pubkeyHash) = delegationStore.delegationMap.at(i);
            delete delegationStore.delegations[pubkeyHash];
            delegationStore.delegationMap.remove(index);
        }

        // Delete the pubkey hashes array
        delete operatorDelegations[msg.sender][registrationRoot];
        EnumerableSet.Bytes32Set storage roots = operatorRegistrationRoots[msg.sender];
        roots.remove(registrationRoot);

        // Unregister from the registry
        REGISTRY.unregister(registrationRoot);

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
        MiddlewareLib.batchSetDelegations(
            REGISTRY,
            operatorDelegations[msg.sender][registrationRoot],
            registrationRoot,
            msg.sender,
            pubkeys,
            delegations
        );
    }

    /// @notice Opt in to slasher contract
    /// @inheritdoc ISymbioticNetworkMiddleware
    function optInToSlasher(
        bytes32 registrationRoot,
        IRegistry.Registration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata data
    )
        external
        override
    {
        MiddlewareLib.optInToSlasher(
            REGISTRY,
            operatorDelegations[msg.sender][registrationRoot],
            operatorRegistrationRoots[msg.sender],
            registrationRoot,
            address(this),
            address(this),
            registrations,
            delegationSignatures,
            delegateePubKey,
            delegateeAddress,
            data
        );
    }

    /// @notice Slash an operator based on the provided slash parameters
    /// @inheritdoc ISymbioticNetworkMiddleware
    function slash(SlashParams calldata params) external override {
        address operator = _getOperatorAndCheckCanSlash(params.key, params.timestamp);
        address[] memory vaults = super._activeVaultsAt(params.timestamp, operator);

        if (vaults.length == 0) revert NoVaultsToSlash();

        uint256 totalStake;
        uint256[] memory stakes = new uint256[](vaults.length);

        // Calculate total stake across all vaults
        for (uint256 i = 0; i < vaults.length; i++) {
            stakes[i] = IBaseDelegator(IVault(vaults[i]).delegator()).stakeAt(
                params.subnetwork, operator, params.timestamp, params.slashHints[i]
            );
            totalStake += stakes[i];
        }

        if (totalStake == 0) revert NoVaultsToSlash();

        uint256 remainingAmount = params.amount;
        uint256[] memory slashAmounts = new uint256[](vaults.length);

        // Calculate proportional amounts using safe math
        for (uint256 i = 0; i < vaults.length; i++) {
            slashAmounts[i] = Math.mulDiv(params.amount, stakes[i], totalStake);
            remainingAmount -= slashAmounts[i];
        }

        // Distribute remaining amount due to rounding errors
        if (remainingAmount > 0) {
            slashAmounts[vaults.length - 1] += remainingAmount;
        }

        // Execute slashing with safety checks
        for (uint256 i = 0; i < vaults.length; i++) {
            if (slashAmounts[i] > 0) {
                super._slashVault(
                    params.timestamp,
                    vaults[i],
                    params.subnetwork,
                    operator,
                    slashAmounts[i],
                    params.slashHints[i]
                );
            }
        }

        emit OperatorSlashed(operator, uint96(uint256(params.subnetwork)), params.amount);
    }

    /// @inheritdoc ISymbioticNetworkMiddleware
    function getOperatorRegistrationRoots(address operator)
        external
        view
        override
        returns (bytes32[] memory)
    {
        return MiddlewareLib.getOperatorRegistrationRoots(
            operatorRegistrationRoots[operator]
        );
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
        return MiddlewareLib.getAllDelegations(
            REGISTRY,
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

    /// @notice Gets the operator's address for a given key and verifies they can be slashed
    /// @param key The address key to look up
    /// @param timestamp The timestamp to check activity at
    /// @return operator The operator address associated with the key
    /// @dev Verifies both the key and operator were active at the given timestamp
    function _getOperatorAndCheckCanSlash(
        bytes memory key,
        uint48 timestamp
    )
        internal
        view
        returns (address operator)
    {
        operator = super.operatorByKey(key);
        if (!super.keyWasActiveAt(timestamp, key)) revert InactiveKeySlash();
        if (!super._operatorWasActiveAt(timestamp, operator)) {
            revert InactiveOperatorSlash();
        }
        return operator;
    }

    /// @notice Internal function to verify operator's address key signature
    /// @param operator The operator address
    /// @param key The address key
    /// @param signature The signature to verify
    function _verifyKey(
        address operator,
        bytes memory key,
        bytes memory signature
    )
        internal
        pure
    {
        address keyAddress = abi.decode(key, (address));
        if (keyAddress != operator) {
            revert InvalidSignature();
        }
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
        address[] memory activeVaultAddresses = super._activeOperatorVaults(operator);
        uint256 length = activeVaultAddresses.length;

        vaults = new address[](length);
        collateralTokens = new address[](length);
        stakedAmounts = new uint256[](length);

        for (uint256 i = 0; i < length; i++) {
            address vault = activeVaultAddresses[i];
            vaults[i] = vault;
            collateralTokens[i] = IVault(vault).collateral();

            uint256 power = super._getOperatorPower(operator, vault, subnetworkId);
            stakedAmounts[i] = power;
        }

        return (vaults, collateralTokens, stakedAmounts);
    }

    /// @inheritdoc ISymbioticNetworkMiddleware
    function totalPower(address[] memory operators)
        external
        view
        override
        returns (uint256)
    {
        return super._totalPower(operators);
    }

    /// @notice Gets all subnetworks that have allocated stake to a specific operator
    /// @param operator The operator address to check
    /// @return allocatedSubnetworks Array of subnetwork IDs that have stake allocated to the operator
    function getOperatorAllocatedSubnetworks(address operator)
        external
        view
        returns (uint96[] memory allocatedSubnetworks)
    {
        uint96[] memory subnetworks = REGISTRY_COORDINATOR.getSymbioticSubnetworks();
        for (uint256 i = 0; i < subnetworks.length; i++) {
            if (
                REGISTRY_COORDINATOR.isSymbioticOperatorInSubnetwork(
                    subnetworks[i], operator
                )
            ) {
                allocatedSubnetworks[i] = subnetworks[i];
            }
        }
    }
}

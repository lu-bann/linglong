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

import { ServiceTypeLib } from "../libs/ServiceTypeLib.sol";

// Add Registry imports for validator registration
import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { Registry } from "@urc/Registry.sol";
import { BLS } from "@urc/lib/BLS.sol";

import { ISymbioticNetworkMiddleware } from "../interfaces/ISymbioticNetworkMiddleware.sol";

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
    ISymbioticNetworkMiddleware
{
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using Subnetwork for address;
    using ServiceTypeLib for ITaiyiRegistryCoordinator.RestakingServiceTypes;

    // ======= REGISTRY INTEGRATION =========

    /// @notice Registry contract reference
    Registry public REGISTRY;
    
    /// @notice Store validation registrations by operator
    mapping(address => mapping(bytes32 => DelegationStore)) public operatorDelegations;
    
    /// @notice Keep track of registration roots for each operator
    mapping(address => EnumerableSet.Bytes32Set) private operatorRegistrationRoots;
    
    /// @notice Similar to EigenLayerMiddleware but for Symbiotic's delegations
    struct DelegationStore {
        mapping(bytes32 => ISlasher.SignedDelegation) delegations;
        EnumerableMapLib.Uint256ToBytes32Map delegationMap;
    }

    /// @notice Reference to the rewards handler contract for Symbiotic
    address public rewardsHandler;

    /// @notice Emit when rewards handler is set
    event RewardsHandlerSet(address rewardsHandler);

    /// @notice Error when rewards handler is not set
    error RewardsHandlerNotSet();

    /// @notice Error for registration failures
    error RegistrationRootNotFound();
    error OperatorNotOwnerOfRegistrationRoot();
    error PubKeyNotFound();
    error OperatorUnregistered();
    error OperatorSlashed();
    error OperatorFraudProofPeriodNotOver();

    error InvalidSignature();
    error NoVaultsToSlash();
    error InactiveSubnetworkSlash();
    error InactiveKeySlash();
    error InactiveOperatorSlash();

    ITaiyiRegistryCoordinator public registryCoordinator;

    uint96 public constant VALIDATOR_SUBNETWORK = 1;
    uint96 public constant UNDERWRITER_SUBNETWORK = 2;

    struct SlashParams {
        uint48 timestamp;
        bytes key;
        uint256 amount;
        bytes32 subnetwork;
        bytes[] slashHints;
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

        registryCoordinator = ITaiyiRegistryCoordinator(_registryCoordinator);
        REGISTRY = Registry(_registry);
    }

    function setupSubnetworks() external {
        super.registerSubnetwork(VALIDATOR_SUBNETWORK);
        super.registerSubnetwork(UNDERWRITER_SUBNETWORK);
    }

    /// @notice Set the rewards handler contract
    /// @param _rewardsHandler Address of the rewards handler contract
    function setRewardsHandler(address _rewardsHandler) external onlyOwner {
        rewardsHandler = _rewardsHandler;
        emit RewardsHandlerSet(_rewardsHandler);
    }

    /// @notice Register a new operator with the specified key, vault, and subnetwork
    /// @param key The address key of the operator
    /// @param vault The vault address associated with the operator
    /// @param signature The signature proving ownership of the key
    /// @param subnetwork The subnetwork identifier (VALIDATOR_SUBNETWORK or UNDERWRITER_SUBNETWORK)
    /// @dev Calls BaseOperators._registerOperatorImpl
    function registerOperator(
        bytes memory key,
        address vault,
        bytes memory signature,
        uint96 subnetwork
    )
        external
        override
    {
        require(
            subnetwork == VALIDATOR_SUBNETWORK || subnetwork == UNDERWRITER_SUBNETWORK,
            "Invalid subnetwork"
        );

        _verifyKey(msg.sender, key, signature);
        super._registerOperatorImpl(msg.sender, key, vault);

        ITaiyiRegistryCoordinator.RestakingServiceTypes serviceType = subnetwork
            == VALIDATOR_SUBNETWORK
            ? ITaiyiRegistryCoordinator.RestakingServiceTypes.SYMBIOTIC_VALIDATOR
            : ITaiyiRegistryCoordinator.RestakingServiceTypes.SYMBIOTIC_UNDERWRITER;
        uint32 serviceTypeId = serviceType.toId();

        registryCoordinator.registerOperatorWithServiceType(
            msg.sender, serviceTypeId, bytes("")
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
        returns (bytes32 registrationRoot)
    {
        // Verify the operator is registered in the validator subnetwork
        address operator = msg.sender;
        if (
            registryCoordinator.getOperatorFromOperatorSet(uint32(VALIDATOR_SUBNETWORK), operator)
                == address(0)
        ) {
            revert OperatorIsNotYetRegisteredInValidatorOperatorSet();
        }
        
        // Verify the delegatee address is registered in the underwriter subnetwork
        if (
            registryCoordinator.getOperatorFromOperatorSet(
                uint32(UNDERWRITER_SUBNETWORK), delegateeAddress) == address(0)
        ) {
            revert OperatorIsNotYetRegisteredInUnderwriterOperatorSet();
        }

        require(
            registrations.length == delegationSignatures.length,
            "Invalid number of delegation signatures"
        );

        // Send 0.11 eth to meet the Registry.MIN_COLLATERAL() requirement
        // always use avs contract address as the owner of the operator
        registrationRoot = REGISTRY.register{ value: 0.11 ether }(registrations, address(this));

        // Store the registration info for this operator
        DelegationStore storage delegationStore = operatorDelegations[operator][registrationRoot];
        EnumerableSet.Bytes32Set storage roots = operatorRegistrationRoots[operator];
        roots.add(registrationRoot);

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
            delegationStore.delegationMap.set(i, pubkeyHash); // Use index as value for enumeration
        }

        emit ValidatorRegistered(operator, registrationRoot);
        return registrationRoot;
    }

    /// @notice Unregister validators for a registration root
    /// @inheritdoc ISymbioticNetworkMiddleware
    function unregisterValidators(bytes32 registrationRoot) external override {
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
    {
        address operator = msg.sender;
        (address owner,,, uint32 registeredAt, uint32 unregisteredAt, uint32 slashedAt) =
            REGISTRY.registrations(registrationRoot);
        
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

        if (registeredAt + REGISTRY.FRAUD_PROOF_WINDOW() > block.number) {
            revert OperatorFraudProofPeriodNotOver();
        }

        DelegationStore storage delegationStore =
            operatorDelegations[operator][registrationRoot];
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
        REGISTRY.optInToSlasher(registrationRoot, address(this), address(this));

        DelegationStore storage delegationStore =
            operatorDelegations[msg.sender][registrationRoot];

        EnumerableSet.Bytes32Set storage roots = operatorRegistrationRoots[msg.sender];
        roots.add(registrationRoot);

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
            delegationStore.delegationMap.set(i, pubkeyHash); // Use index as value for enumeration
        }
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
                _slashVault(
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

    /// @notice Distribute rewards to operators in a subnetwork
    /// @param token The token address for rewards
    /// @param amount The total amount to distribute
    /// @param subnetworkId The subnetwork ID (validator or underwriter)
    /// @return success Whether distribution was successful
    function distributeRewards(
        address token,
        uint256 amount,
        uint96 subnetworkId
    )
        external
        onlyOwner
        returns (bool success)
    {
        if (address(rewardsHandler) == address(0)) {
            revert RewardsHandlerNotSet();
        }

        // Ensure token approval for the rewards handler
        if (!IERC20(token).approve(rewardsHandler, amount)) {
            revert("Token approval failed");
        }

        // Call the rewards handler to distribute rewards
        return SymbioticRewardsHandler(rewardsHandler).distributeRewards(
            token, amount, subnetworkId
        );
    }

    /// @inheritdoc ISymbioticNetworkMiddleware
    function getOperatorRegistrationRoots(address operator)
        external
        view
        override
        returns (bytes32[] memory)
    {
        EnumerableSet.Bytes32Set storage roots = operatorRegistrationRoots[operator];
        uint256 length = roots.length();
        bytes32[] memory result = new bytes32[](length);

        for (uint256 i = 0; i < length; i++) {
            result[i] = roots.at(i);
        }

        return result;
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
        (address owner,,, uint32 registeredAt,,) =
            REGISTRY.registrations(registrationRoot);

        if (registeredAt == 0) {
            revert RegistrationRootNotFound();
        }

        if (owner != operator) {
            revert OperatorNotOwnerOfRegistrationRoot();
        }

        DelegationStore storage delegationStore =
            operatorDelegations[operator][registrationRoot];
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

    /// @notice Gets the registry coordinator
    /// @return Registry coordinator address
    function getRegistryCoordinator() external view override returns (ITaiyiRegistryCoordinator) {
        return registryCoordinator;
    }

    /// @notice Get the address validator constant
    function VALIDATOR_SUBNETWORK() external pure override returns (uint96) {
        return 1;
    }

    /// @notice Get the underwriter constant
    function UNDERWRITER_SUBNETWORK() external pure override returns (uint96) {
        return 2;
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
        // For address-based verification, we expect the key to be an encoded address
        // and the signature to be empty or a valid ECDSA signature
        address keyAddress = abi.decode(key, (address));

        // Simple verification: Check that the key address matches the operator or that the key
        // is a valid signer for the operator
        if (keyAddress != operator) {
            // Additional verification could be added here if needed
            // For now, we'll just check if the key address matches the operator
            revert InvalidSignature();
        }
    }

    /// @inheritdoc ISymbioticNetworkMiddleware
    function getOperatorCollaterals(address operator)
        external
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

            uint256 validatorPower =
                super._getOperatorPower(operator, vault, VALIDATOR_SUBNETWORK);
            uint256 underwriterPower =
                super._getOperatorPower(operator, vault, UNDERWRITER_SUBNETWORK);
            stakedAmounts[i] = validatorPower + underwriterPower;
        }

        return (vaults, collateralTokens, stakedAmounts);
    }

    /// @inheritdoc ISymbioticNetworkMiddleware
    function totalPower(address[] memory operators) external view override returns (uint256) {
        return _totalPower(operators);
    }
}

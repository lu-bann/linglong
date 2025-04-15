// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IERC20 } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts-v4.9.0/contracts/token/ERC20/IERC20.sol";
import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";

import { Math } from "@openzeppelin-contracts/contracts/utils/math/Math.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { EnumerableMapLib } from "@solady/utils/EnumerableMapLib.sol";

import { ILinglongSlasher } from "../interfaces/ILinglongSlasher.sol";
import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";

import { DelegationManager } from
    "@eigenlayer-contracts/src/contracts/core/DelegationManager.sol";
import { IAVSDirectory } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAVSDirectory.sol";

import { IAllocationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IAllocationManagerTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";

import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IRewardsCoordinatorTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";

import { RestakingProtocolMap } from "../libs/RestakingProtocolMap.sol";
import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { Registry } from "@urc/Registry.sol";
import { BLS } from "@urc/lib/BLS.sol";

import { EigenLayerMiddlewareLib } from "../libs/EigenLayerMiddlewareLib.sol";

import { OperatorSubsetLib } from "../libs/OperatorSubsetLib.sol";
import { EigenLayerMiddlewareStorage } from "../storage/EigenLayerMiddlewareStorage.sol";
import { EigenLayerRewardsHandler } from "./EigenLayerRewardsHandler.sol";

import { SafeCast96To32 } from "../libs/SafeCast96To32.sol";

/// @title EigenLayer Middleware Contract
/// @notice Manages operator registration, delegation, and restaking in EigenLayer ecosystem
/// @dev This contract serves as the interface between validators and EigenLayer infrastructure
///      and provides functionality for registering validators, managing operator sets,
///      handling rewards, and integrating with external registries
///
/// The middleware facilitates:
/// - Validator registration and management
/// - Stake delegation and allocation
/// - Rewards distribution between validators and underwriters
/// - Integration with BLS registries for validator pubkeys
contract EigenLayerMiddleware is
    OwnableUpgradeable,
    UUPSUpgradeable,
    EigenLayerMiddlewareStorage
{
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMapLib for EnumerableMapLib.Uint256ToBytes32Map;
    using OperatorSubsetLib for uint96;
    using OperatorSubsetLib for uint32;
    using SafeCast96To32 for uint96;
    using SafeCast96To32 for uint32;

    // ==============================================================================================
    // ================================= STATE VARIABLES ============================================
    // ==============================================================================================

    /// @notice Reference to the rewards handler contract that processes reward distributions
    /// @dev Handles both validator and underwriter reward calculations and allocations
    EigenLayerRewardsHandler public rewardsHandler;

    // ==============================================================================================
    // ================================= EVENTS ====================================================
    // ==============================================================================================

    /// @notice Emitted when the rewards handler address is updated
    /// @param rewardsHandler The new rewards handler address
    event RewardsHandlerSet(address rewardsHandler);

    /// @notice Thrown when a function requiring the rewards handler is called but it's not set
    error RewardsHandlerNotSet();

    // ==============================================================================================
    // ================================= MODIFIERS =================================================
    // ==============================================================================================

    /// @notice Restricts function access to operators registered in validator operator set
    /// @dev Validates that msg.sender is registered in the validator operatorSet with ID 0
    modifier onlyValidatorOperatorSet() {
        if (
            REGISTRY_COORDINATOR.isEigenLayerOperatorInSet(uint32(0), msg.sender) == false
        ) {
            revert OperatorIsNotYetRegisteredInValidatorOperatorSet();
        }
        _;
    }

    /// @notice Restricts function access to the registry coordinator contract
    /// @dev Ensures only the trusted registry coordinator can call the function
    modifier onlyRegistryCoordinator() {
        if (msg.sender != address(REGISTRY_COORDINATOR)) {
            revert OnlyRegistryCoordinator();
        }
        _;
    }

    /// @notice Restricts function access to the designated rewards initiator
    /// @dev Used for controlling who can trigger reward distributions
    modifier onlyRewardsInitiator() {
        if (msg.sender != REWARD_INITIATOR) {
            revert OnlyRewardsInitiator();
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
    /// @param _avsDirectory Address of the AVS directory contract
    /// @param _delegationManager Address of EigenLayer's delegation manager
    /// @param _rewardCoordinator Address of EigenLayer's reward coordinator
    /// @param _rewardInitiator Address authorized to initiate rewards
    /// @param _registryCoordinator Address of the registry coordinator
    /// @param _underwriterShareBips Percentage of rewards for underwriters in basis points
    /// @param _registry Address of the validator registry contract
    /// @param _slasher Address of the slasher contract
    /// @param _allocationManager Address of the allocation manager contract
    /// @dev Sets up all contract dependencies and configures initial parameters
    function initialize(
        address _owner,
        address _avsDirectory,
        address _delegationManager,
        address _rewardCoordinator,
        address _rewardInitiator,
        address _registryCoordinator,
        uint256 _underwriterShareBips,
        address _registry,
        address _slasher,
        address _allocationManager
    )
        public
        virtual
        initializer
    {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();

        AVS_DIRECTORY = IAVSDirectory(_avsDirectory);
        DELEGATION_MANAGER = DelegationManager(_delegationManager);
        REWARDS_COORDINATOR = IRewardsCoordinator(_rewardCoordinator);
        _setRewardsInitiator(_rewardInitiator);
        UNDERWRITER_SHARE_BIPS = _underwriterShareBips;
        REGISTRY_COORDINATOR = ITaiyiRegistryCoordinator(_registryCoordinator);
        REGISTRY = Registry(_registry);
        SLASHER = address(ILinglongSlasher(_slasher));
        ALLOCATION_MANAGER = _allocationManager;
    }

    // ==============================================================================================
    // ================================= EXTERNAL WRITE FUNCTIONS ==================================
    // ==============================================================================================

    /// @notice Registers multiple validators in a single transaction
    /// @param registrations Array of validator registration parameters
    /// @param delegationSignatures BLS signatures authorizing delegation
    /// @param delegateePubKey BLS public key of the delegatee
    /// @param delegateeAddress Address of the delegatee
    /// @param data Additional data for the registrations
    /// @return registrationRoot Root hash of the registered validators
    /// @dev Registers validators with the Registry contract and sends required collateral
    function registerValidators(
        IRegistry.Registration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata data
    )
        external
        payable
        returns (bytes32 registrationRoot)
    {
        registrationRoot = _registerValidators(
            registrations, delegationSignatures, delegateePubKey, delegateeAddress, data
        );
    }

    /// @notice Updates delegations for validators under a registration root
    /// @param registrationRoot The registration root containing the validators
    /// @param pubkeys BLS public keys of the validators
    /// @param delegations New delegation information
    /// @dev Can only be called by a registered validator operator after fraud proof window
    function batchSetDelegations(
        bytes32 registrationRoot,
        BLS.G1Point[] calldata pubkeys,
        ISlasher.SignedDelegation[] calldata delegations
    )
        external
    {
        _batchSetDelegations(registrationRoot, pubkeys, delegations);
    }

    /// @notice Unregisters validators associated with a registration root
    /// @param registrationRoot The registration root to unregister
    /// @dev Removes all delegations and unregisters from the Registry contract
    function unregisterValidators(bytes32 registrationRoot) external {
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
    }

    /// @notice Creates an operator set with the given strategies
    /// @param strategies Array of strategies for the operator set
    /// @return operatorSetId The ID of the created operator set
    function createOperatorSet(IStrategy[] memory strategies)
        external
        onlyOwner
        returns (uint32 operatorSetId)
    {
        return _createOperatorSet(strategies);
    }

    /// @notice Opts in to the slasher contract for a registration root
    /// @param registrationRoot The registration root to opt in
    /// @param registrations Array of validator registrations
    /// @param delegationSignatures BLS signatures authorizing delegation
    /// @param delegateePubKey BLS public key of the delegatee
    /// @param delegateeAddress Address of the delegatee
    /// @param data Additional data for the registrations
    /// @dev Registers the slasher contract with the Registry and stores delegation information
    function optInToSlasher(
        bytes32 registrationRoot,
        IRegistry.Registration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata data
    )
        external
    {
        REGISTRY.optInToSlasher(registrationRoot, SLASHER, address(this));

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

    /// @notice Processes a reward claim from the rewards merkle tree
    /// @param claim The merkle claim information
    /// @param recipient Address to receive the claimed rewards
    /// @dev Forwards the claim to the rewards coordinator
    function processClaim(
        IRewardsCoordinator.RewardsMerkleClaim calldata claim,
        address recipient
    )
        external
    {
        _processClaim(claim, recipient);
    }

    /// @notice Deprecated function for creating AVS rewards submissions
    /// @dev Always reverts with instruction to use createOperatorDirectedAVSRewardsSubmission
    function createAVSRewardsSubmission(IRewardsCoordinator.RewardsSubmission[] calldata)
        external
        pure
    {
        revert UseCreateOperatorDirectedAVSRewardsSubmission();
    }

    /// @notice Creates operator-directed rewards for validator and underwriter distribution
    /// @param operatorDirectedRewardsSubmissions Array containing underwriter and validator reward submissions
    /// @dev Strictly enforces submission format and validation rules for reward distribution
    function createOperatorDirectedAVSRewardsSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata
            operatorDirectedRewardsSubmissions
    )
        external
        onlyRewardsInitiator
    {
        if (address(rewardsHandler) == address(0)) {
            revert RewardsHandlerNotSet();
        }

        require(
            keccak256(bytes(operatorDirectedRewardsSubmissions[0].description))
                == keccak256(bytes("underwriter")),
            "EigenLayerMiddleware: First submission must be the Underwriter portion"
        );

        require(
            keccak256(bytes(operatorDirectedRewardsSubmissions[1].description))
                == keccak256(bytes("validator")),
            "EigenLayerMiddleware: Second submission must be the Validator portion"
        );

        require(
            operatorDirectedRewardsSubmissions[0].startTimestamp == block.timestamp
                && operatorDirectedRewardsSubmissions[1].startTimestamp == block.timestamp,
            "EigenLayerMiddleware: Underwriter and Validator submissions must have start timestamp of current block"
        );

        require(
            operatorDirectedRewardsSubmissions[0].duration == REWARD_DURATION
                && operatorDirectedRewardsSubmissions[1].duration == REWARD_DURATION,
            "EigenLayerMiddleware: Underwriter and Validator submissions must have the same duration"
        );

        // Enforce that the second submission's operator rewards are always zero.
        // The validator portion is determined by _handleUnderwriterSubmission, which
        // calculates how many tokens go to the validator side.
        IRewardsCoordinator.OperatorReward[] memory validatorRewards =
            operatorDirectedRewardsSubmissions[1].operatorRewards;
        for (uint256 i = 0; i < validatorRewards.length; i++) {
            require(
                validatorRewards[i].amount == 0,
                "EigenLayerMiddleware: Validator submission reward must be zero"
            );
        }

        // 1) Handle Underwriter portion using the rewards handler
        uint256 validatorAmount = rewardsHandler.handleUnderwriterSubmission(
            operatorDirectedRewardsSubmissions[0]
        );

        // 2) Handle Validator portion using the rewards handler
        rewardsHandler.handleValidatorRewards(
            operatorDirectedRewardsSubmissions[1], validatorAmount
        );
    }

    // ==============================================================================================
    // ================================= OWNER/ADMIN FUNCTIONS =====================================
    // ==============================================================================================

    /// @notice Sets the rewards initiator address
    /// @param newRewardsInitiator The new rewards initiator address
    /// @dev Only callable by the contract owner
    function setRewardsInitiator(address newRewardsInitiator) external onlyOwner {
        _setRewardsInitiator(newRewardsInitiator);
    }

    /// @notice Sets the rewards handler contract
    /// @param _rewardsHandler Address of the rewards handler contract
    /// @dev Only callable by the contract owner, emits RewardsHandlerSet event
    function setRewardsHandler(address _rewardsHandler) external onlyOwner {
        rewardsHandler = EigenLayerRewardsHandler(_rewardsHandler);
        emit RewardsHandlerSet(_rewardsHandler);
    }

    /// @dev EigenLayer only method
    /// @notice Adds strategies to an existing operator set
    /// @param operatorSetId The ID of the operator set
    /// @param strategies Array of strategies to add
    function addStrategiesToOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external
        onlyOwner
    {
        _addStrategiesToOperatorSet(operatorSetId, strategies);
    }

    /// @dev EigenLayer only method
    /// @notice Removes strategies from an existing operator set
    /// @param operatorSetId The ID of the operator set
    /// @param strategies Array of strategies to remove
    function removeStrategiesFromOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external
        onlyOwner
    {
        _removeStrategiesFromOperatorSet(operatorSetId, strategies);
    }

    /// @notice Updates the metadata URI for the AVS in the AVS directory
    /// @param metadataURI New metadata URI
    /// @dev Only callable by the contract owner
    function updateAVSMetadataURI(string calldata metadataURI) external onlyOwner {
        _updateAVSMetadataURI(metadataURI);
    }

    /// @notice Sets the address authorized to process reward claims
    /// @param claimer Address of the claimer
    /// @dev Only callable by the contract owner
    function setClaimerFor(address claimer) external onlyOwner {
        _setClaimerFor(claimer);
    }

    /// @notice Authorizes contract upgrades via UUPS pattern
    /// @param newImplementation Address of new implementation contract
    /// @dev Only callable by the contract owner
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner { }

    // ==============================================================================================
    // ================================= EXTERNAL VIEW FUNCTIONS ===================================
    // ==============================================================================================

    /// @notice Gets the number of delegations for an operator under a registration root
    /// @param operator The operator address
    /// @param registrationRoot The registration root
    /// @return count Number of delegations
    function getOperatorDelegationsCount(
        address operator,
        bytes32 registrationRoot
    )
        external
        view
        returns (uint256 count)
    {
        return operatorDelegations[operator][registrationRoot].delegationMap.length();
    }

    /// @notice Gets all registration roots for an operator
    /// @param operator The operator address
    /// @return Array of registration roots
    function getOperatorRegistrationRoots(address operator)
        external
        view
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

    /// @notice Gets an operator's restaked strategies and their stake amounts
    /// @param operator The operator address
    /// @return strategies Array of strategy contracts the operator has staked in
    /// @return stakeAmounts Array of stake amounts corresponding to each strategy
    function getStrategiesAndStakes(address operator)
        external
        view
        returns (IStrategy[] memory strategies, uint256[] memory stakeAmounts)
    {
        strategies = getOperatorRestakedStrategies(operator);
        stakeAmounts = DELEGATION_MANAGER.getOperatorShares(operator, strategies);
    }

    /// @notice Verifies an operator's registration status in EigenLayer and this AVS
    /// @param operator The operator address to check
    /// @return Array of operator sets the operator is registered in
    /// @dev Reverts if operator is not registered in EigenLayer or this AVS
    function verifyEigenLayerOperatorRegistration(address operator)
        public
        view
        returns (OperatorSet[] memory)
    {
        // First check if operator is registered in delegation manager
        bool isDelegated = DELEGATION_MANAGER.isOperator(operator);
        if (!isDelegated) {
            revert OperatorNotRegisteredInEigenLayer();
        }

        ITaiyiRegistryCoordinator.AllocatedOperatorSets memory operatorSetsIds =
            REGISTRY_COORDINATOR.getOperatorAllocatedOperatorSets(operator);

        OperatorSet[] memory operatorSets =
            new OperatorSet[](operatorSetsIds.eigenLayerSets.length);
        for (uint256 i = 0; i < operatorSetsIds.eigenLayerSets.length; i++) {
            operatorSets[i] =
                OperatorSet({ avs: address(this), id: operatorSetsIds.eigenLayerSets[i] });
        }

        // Check operator's registration status in this AVS
        if (operatorSets.length == 0) {
            revert OperatorNotRegisteredInAVS();
        }

        return operatorSets;
    }

    /// @notice Gets all strategies an operator has restaked in
    /// @param operator The operator address
    /// @return strategies Array of strategy contracts
    /// @dev Verifies registration and deduplicates strategies across operator sets
    function getOperatorRestakedStrategies(address operator)
        public
        view
        returns (IStrategy[] memory strategies)
    {
        OperatorSet[] memory operatorSets = verifyEigenLayerOperatorRegistration(operator);
        return EigenLayerMiddlewareLib.deduplicateStrategies(
            operatorSets, REGISTRY_COORDINATOR, operator
        );
    }

    /// @notice Gets a delegation for an operator by validator pubkey
    /// @param operator The operator address
    /// @param registrationRoot The registration root
    /// @param pubkey BLS public key of the validator
    /// @return The signed delegation information
    /// @dev Reverts if registration or pubkey not found
    function getDelegation(
        address operator,
        bytes32 registrationRoot,
        BLS.G1Point calldata pubkey
    )
        public
        view
        returns (ISlasher.SignedDelegation memory)
    {
        (address owner,,, uint32 registeredAt,,) =
            REGISTRY.registrations(registrationRoot);

        if (registeredAt == 0) {
            revert RegistrationRootNotFound();
        }

        if (owner != operator) {
            revert OperatorNotOwnerOfRegistrationRoot();
        }

        bytes32 pubkeyHash = keccak256(abi.encode(pubkey));
        DelegationStore storage delegationStore =
            operatorDelegations[operator][registrationRoot];

        if (delegationStore.delegations[pubkeyHash].delegation.committer != address(0)) {
            return delegationStore.delegations[pubkeyHash];
        } else {
            revert PubKeyNotFound();
        }
    }

    /// @notice Gets all delegations for an operator under a registration root
    /// @param operator The operator address
    /// @param registrationRoot The registration root
    /// @return pubkeys Array of BLS public keys
    /// @return delegations Array of signed delegations
    /// @dev Reverts if registration not found or operator doesn't own it
    function getAllDelegations(
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

    /// @notice Gets the total number of operator sets
    /// @return Number of operator sets
    function getOperatorSetCount() public view returns (uint32) {
        return REGISTRY_COORDINATOR.getOperatorSetCount();
    }

    /// @notice Gets the rewards initiator address
    /// @return Address of the rewards initiator
    function getRewardInitiator() external view returns (address) {
        return REWARD_INITIATOR;
    }

    /// @notice Gets the underwriter share in basis points
    /// @return Underwriter share in basis points
    function getUnderwriterShareBips() external view returns (uint256) {
        return UNDERWRITER_SHARE_BIPS;
    }

    /// @notice Gets the registry coordinator contract
    /// @return Registry coordinator address
    function getRegistryCoordinator() external view returns (ITaiyiRegistryCoordinator) {
        return REGISTRY_COORDINATOR;
    }

    /// @notice Gets the rewards coordinator contract
    /// @return Rewards coordinator address
    function getRewardsCoordinator() external view returns (IRewardsCoordinator) {
        return REWARDS_COORDINATOR;
    }

    // ==============================================================================================
    // ================================= INTERNAL FUNCTIONS ========================================
    // ==============================================================================================

    /// @notice Deprecated internal function for registering operators
    /// @dev Always reverts with instruction to use allocation manager
    function _registerOperatorToAvs(
        address,
        bytes memory,
        bytes memory
    )
        internal
        pure
        returns (uint32)
    {
        revert UseAllocationManagerForOperatorRegistration();
    }

    /// @notice Internal implementation for batch setting delegations
    /// @param registrationRoot The registration root
    /// @param pubkeys BLS public keys of validators
    /// @param delegations Signed delegations to set
    /// @dev Performs various validations before updating delegations
    function _batchSetDelegations(
        bytes32 registrationRoot,
        BLS.G1Point[] calldata pubkeys,
        ISlasher.SignedDelegation[] calldata delegations
    )
        internal
        onlyValidatorOperatorSet
    {
        (address owner,,, uint32 registeredAt, uint32 unregisteredAt, uint32 slashedAt) =
            REGISTRY.registrations(registrationRoot);
        if (registeredAt == 0) {
            revert RegistrationRootNotFound();
        }

        if (owner != msg.sender) {
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
            operatorDelegations[msg.sender][registrationRoot];
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

    /// @notice Internal implementation for registering validators
    /// @param registrations Array of validator registration parameters
    /// @param delegationSignatures BLS signatures authorizing delegation
    /// @param delegateePubKey BLS public key of the delegatee
    /// @param delegateeAddress Address of the delegatee
    /// @return registrationRoot Root hash of the registered validators
    /// @dev Verifies delegatee is registered and handles registration with the Registry
    function _registerValidators(
        IRegistry.Registration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata
    )
        internal
        onlyValidatorOperatorSet
        returns (bytes32 registrationRoot)
    {
        if (
            REGISTRY_COORDINATOR.getEigenLayerOperatorFromOperatorSet(0, delegateeAddress)
                == address(0)
        ) {
            revert OperatorIsNotYetRegisteredInUnderwriterOperatorSet();
        }

        require(
            registrations.length == delegationSignatures.length,
            "Invalid number of delegation signatures"
        );

        // send 0.11 eth to meet the Registry.MIN_COLLATERAL() requirement
        // always use avs contract address as the owner of the operator
        registrationRoot =
            REGISTRY.register{ value: 0.11 ether }(registrations, address(this));
    }

    /// @notice Internal function to create an operator set
    /// @param strategies Array of strategies for the operator set
    /// @dev Calls registry coordinator to create the operator set
    function _createOperatorSet(IStrategy[] memory strategies)
        internal
        returns (uint32 operatorSetId)
    {
        // Get the current operator set count from allocationManager
        uint256 currentSetCount =
            IAllocationManager(ALLOCATION_MANAGER).getOperatorSetCount(address(this));

        operatorSetId = uint32(currentSetCount).encodeOperatorSetId32(
            ITaiyiRegistryCoordinator.RestakingProtocol.EIGENLAYER
        );

        IAllocationManagerTypes.CreateSetParams[] memory createSetParams =
            new IAllocationManagerTypes.CreateSetParams[](1);

        createSetParams[0] = IAllocationManagerTypes.CreateSetParams({
            operatorSetId: operatorSetId,
            strategies: strategies
        });

        // AllocationManager still expects uint32 for its internal ID
        IAllocationManager(ALLOCATION_MANAGER).createOperatorSets(
            address(this), createSetParams
        );

        REGISTRY_COORDINATOR.createOperatorSet(operatorSetId);

        return operatorSetId;
    }

    /// @notice Internal function to add strategies to an operator set
    /// @param operatorSetId ID of the operator set (encoded uint96)
    /// @param strategies Array of strategies to add
    /// @dev Calls registry coordinator to add the strategies
    function _addStrategiesToOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        internal
    {
        IAllocationManager(ALLOCATION_MANAGER).addStrategiesToOperatorSet(
            address(this), operatorSetId, strategies
        );

        // Registry coordinator might need the encoded ID if it performs its own actions (check its implementation)
        // REGISTRY_COORDINATOR.addStrategiesToOperatorSet(operatorSetId, strategies); // Assuming Taiyi doesn't need this directly
    }

    /// @notice Internal function to remove strategies from an operator set
    /// @param operatorSetId ID of the operator set (encoded uint96)
    /// @param strategies Array of strategies to remove
    /// @dev Calls registry coordinator to remove the strategies
    function _removeStrategiesFromOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        internal
    {
        IAllocationManager(ALLOCATION_MANAGER).removeStrategiesFromOperatorSet(
            address(this), operatorSetId, strategies
        );

        // Registry coordinator might need the encoded ID if it performs its own actions (check its implementation)
        // REGISTRY_COORDINATOR.removeStrategiesFromOperatorSet(operatorSetId, strategies); // Assuming Taiyi doesn't need this directly
    }

    /// @notice Deprecated internal function for creating AVS rewards submission
    /// @dev Always reverts with instruction to use operator directed rewards
    function _createAVSRewardsSubmission(
        uint32,
        address[] memory,
        uint256[] memory
    )
        internal
        pure
        returns (bytes memory)
    {
        revert UseCreateOperatorDirectedAVSRewardsSubmission();
    }

    /// @notice Internal function to set the claimer for rewards
    /// @param claimer Address of the claimer
    /// @dev Calls rewards coordinator to set the claimer
    function _setClaimerFor(address claimer) internal {
        REWARDS_COORDINATOR.setClaimerFor(claimer);
    }

    /// @notice Internal function to set the rewards initiator
    /// @param newRewardsInitiator Address of the new rewards initiator
    function _setRewardsInitiator(address newRewardsInitiator) internal {
        REWARD_INITIATOR = newRewardsInitiator;
    }

    /// @notice Internal function to process a rewards claim
    /// @param claim The merkle claim information
    /// @param recipient Address to receive the claimed rewards
    /// @dev Calls rewards coordinator to process the claim
    function _processClaim(
        IRewardsCoordinator.RewardsMerkleClaim calldata claim,
        address recipient
    )
        internal
    {
        IRewardsCoordinator(REWARDS_COORDINATOR).processClaim(claim, recipient);
    }

    /// @notice Internal function to update AVS metadata URI
    /// @param metadataURI New metadata URI
    /// @dev Calls AVS directory to update the metadata URI
    function _updateAVSMetadataURI(string calldata metadataURI) internal {
        AVS_DIRECTORY.updateAVSMetadataURI(metadataURI);
    }
}

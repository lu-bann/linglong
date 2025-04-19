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

import { EigenLayerMiddlewareLib } from "../libs/EigenLayerMiddlewareLib.sol";
import { OperatorSubsetLib } from "../libs/OperatorSubsetLib.sol";
import { RestakingProtocolMapLib } from "../libs/RestakingProtocolMapLib.sol";

import { SafeCast96To32Lib } from "../libs/SafeCast96To32Lib.sol";
import { SlashingLib } from "../libs/SlashingLib.sol";
import { EigenLayerMiddlewareStorage } from "../storage/EigenLayerMiddlewareStorage.sol";
import { DelegationStore } from "../types/CommonTypes.sol";
import { EigenLayerRewardsHandler } from "./EigenLayerRewardsHandler.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IRewardsCoordinatorTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { Registry } from "@urc/Registry.sol";
import { BLS } from "@urc/lib/BLS.sol";

import { console } from "forge-std/console.sol";

/// @title EigenLayer Middleware Contract
/// @notice Manages operator registration, delegation, and restaking in EigenLayer ecosystem
/// @dev This contract serves as the interface between validators and EigenLayer infrastructure
///      and provides functionality for registering validators, managing operator sets,
///      handling rewards, and integrating with external registries
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
    using SafeCast96To32Lib for uint96;
    using SafeCast96To32Lib for uint32;
    using SlashingLib for DelegationStore;
    using EigenLayerMiddlewareLib for ITaiyiRegistryCoordinator;

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
            revert
                EigenLayerMiddlewareLib
                .OperatorIsNotYetRegisteredInValidatorOperatorSet();
        }
        _;
    }

    /// @notice Restricts function access to the registry coordinator contract
    /// @dev Ensures only the trusted registry coordinator can call the function
    modifier onlyRegistryCoordinator() {
        if (msg.sender != address(REGISTRY_COORDINATOR)) {
            revert EigenLayerMiddlewareLib.OnlyRegistryCoordinator();
        }
        _;
    }

    /// @notice Restricts function access to the designated rewards initiator
    /// @dev Used for controlling who can trigger reward distributions
    modifier onlyRewardsInitiator() {
        if (msg.sender != REWARD_INITIATOR) {
            revert EigenLayerMiddlewareLib.OnlyRewardsInitiator();
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
    /// @dev Sets up all contract dependencies and configures initial parameters
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

        AVS_DIRECTORY = IAVSDirectory(_config.avsDirectory);
        DELEGATION_MANAGER = DelegationManager(_config.delegationManager);
        REWARDS_COORDINATOR = IRewardsCoordinator(_config.rewardCoordinator);
        _setRewardsInitiator(_config.rewardInitiator);
        UNDERWRITER_SHARE_BIPS = _config.underwriterShareBips;
        REGISTRY_COORDINATOR = ITaiyiRegistryCoordinator(_config.registryCoordinator);
        REGISTRY = IRegistry(_config.registry);
        SLASHER = address(ILinglongSlasher(_config.slasher));
        ALLOCATION_MANAGER = _config.allocationManager;
        REGISTRATION_MIN_COLLATERAL = _config.registrationMinCollateral;
    }

    // ==============================================================================================
    // ================================= EXTERNAL WRITE FUNCTIONS ==================================
    // ==============================================================================================

    /// @notice Registers multiple validators in a single transaction
    /// @param registrations Array of validator registration parameters
    /// @dev Registers validators with the Registry contract and sends required collateral
    function registerValidators(IRegistry.SignedRegistration[] calldata registrations)
        external
        payable
        returns (bytes32)
    {
        if (!REGISTRY_COORDINATOR.getEigenLayerOperatorFromOperatorSet(0, msg.sender)) {
            revert
                EigenLayerMiddlewareLib
                .OperatorIsNotYetRegisteredInValidatorOperatorSet();
        }
        return EigenLayerMiddlewareLib.registerValidators(
            REGISTRY, registrations, REGISTRATION_MIN_COLLATERAL
        );
    }

    /// @notice Executes slashing for an operator through the EigenLayer allocation manager
    /// @param params The slashing parameters
    /// @return success Whether the slashing was successful
    function executeSlashing(IAllocationManagerTypes.SlashingParams memory params)
        external
        returns (bool success)
    {
        // Ensure only the LinglongSlasher can call this function
        if (msg.sender != SLASHER) {
            revert EigenLayerMiddlewareLib.OnlySlasher();
        }

        return _executeEigenLayerSlashing(address(this), params);
    }

    /// @notice Unregisters validators associated with a registration root
    /// @param registrationRoot The registration root to unregister
    /// @dev Removes all delegations and unregisters from the Registry contract
    function unregisterValidators(bytes32 registrationRoot) external {
        if (!REGISTRY_COORDINATOR.getEigenLayerOperatorFromOperatorSet(0, msg.sender)) {
            revert
                EigenLayerMiddlewareLib
                .OperatorIsNotYetRegisteredInValidatorOperatorSet();
        }
        delete operatorDelegations[msg.sender][registrationRoot];
        operatorRegistrationRoots[msg.sender].remove(registrationRoot);
        EigenLayerMiddlewareLib.unregisterValidators(REGISTRY, registrationRoot);
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
        onlyValidatorOperatorSet
    {
        SlashingLib.batchSetDelegations(
            REGISTRY,
            operatorDelegations[msg.sender][registrationRoot],
            registrationRoot,
            address(this),
            pubkeys,
            delegations
        );
    }

    /// @notice Creates an operator set with the given strategies
    /// @param strategies Array of strategies for the operator set
    /// @return operatorSetId The ID of the created operator set
    function createOperatorSet(IStrategy[] memory strategies)
        external
        onlyOwner
        returns (uint32 operatorSetId)
    {
        return EigenLayerMiddlewareLib.createOperatorSet(
            ALLOCATION_MANAGER, address(this), REGISTRY_COORDINATOR, strategies
        );
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
        IRegistry.SignedRegistration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata data
    )
        external
    {
        if (!REGISTRY_COORDINATOR.getEigenLayerOperatorFromOperatorSet(0, msg.sender)) {
            revert
                EigenLayerMiddlewareLib
                .OperatorIsNotYetRegisteredInValidatorOperatorSet();
        }

        if (
            !REGISTRY_COORDINATOR.getEigenLayerOperatorFromOperatorSet(1, delegateeAddress)
        ) {
            revert
                EigenLayerMiddlewareLib
                .OperatorIsNotYetRegisteredInUnderwriterOperatorSet();
        }

        if (registrations.length != REGISTRY.getOperatorData(registrationRoot).numKeys) {
            revert EigenLayerMiddlewareLib.InvalidRegistrationsLength();
        }

        if (delegationSignatures.length != registrations.length) {
            revert EigenLayerMiddlewareLib.InvalidDelegationSignaturesLength();
        }

        if (REGISTRY.getOperatorData(registrationRoot).registeredAt == 0) {
            revert EigenLayerMiddlewareLib.OperatorNotRegistered();
        }

        if (REGISTRY.isSlashed(registrationRoot)) {
            revert EigenLayerMiddlewareLib.OperatorIsSlashed();
        }

        SlashingLib.DelegationParams memory params = _constructDelegationParams(
            registrationRoot,
            registrations,
            delegationSignatures,
            delegateePubKey,
            delegateeAddress,
            data
        );

        SlashingLib.optInToSlasher(
            REGISTRY,
            operatorDelegations[msg.sender][registrationRoot],
            operatorRegistrationRoots[msg.sender],
            SLASHER,
            address(msg.sender),
            params
        );
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
        EigenLayerMiddlewareLib.processClaim(REWARDS_COORDINATOR, claim, recipient);
    }

    /// @notice Deprecated function for creating AVS rewards submissions
    /// @dev Always reverts with instruction to use createOperatorDirectedAVSRewardsSubmission
    function createAVSRewardsSubmission(IRewardsCoordinator.RewardsSubmission[] calldata)
        external
        pure
    {
        revert EigenLayerMiddlewareLib.UseCreateOperatorDirectedAVSRewardsSubmission();
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

        // Validate the rewards submissions format
        bool isValid = EigenLayerMiddlewareLib.validateRewardsSubmissions(
            operatorDirectedRewardsSubmissions
        );
        require(isValid, "EigenLayerMiddleware: Invalid rewards submissions format");

        // Check reward duration
        require(
            operatorDirectedRewardsSubmissions[0].duration == REWARD_DURATION
                && operatorDirectedRewardsSubmissions[1].duration == REWARD_DURATION,
            "EigenLayerMiddleware: Underwriter and Validator submissions must have the same duration"
        );

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
        EigenLayerMiddlewareLib.addStrategiesToOperatorSet(
            ALLOCATION_MANAGER, address(this), operatorSetId, strategies
        );
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
        EigenLayerMiddlewareLib.removeStrategiesFromOperatorSet(
            ALLOCATION_MANAGER, address(this), operatorSetId, strategies
        );
    }

    /// @notice Updates the metadata URI for the AVS in the AVS directory
    /// @param metadataURI New metadata URI
    /// @dev Only callable by the contract owner
    function updateAVSMetadataURI(string calldata metadataURI) external onlyOwner {
        EigenLayerMiddlewareLib.updateAVSMetadataURI(AVS_DIRECTORY, metadataURI);
    }

    /// @notice Sets the address authorized to process reward claims
    /// @param claimer Address of the claimer
    /// @dev Only callable by the contract owner
    function setClaimerFor(address claimer) external onlyOwner {
        EigenLayerMiddlewareLib.setClaimerFor(REWARDS_COORDINATOR, claimer);
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
        return operatorRegistrationRoots[operator].values();
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
        return EigenLayerMiddlewareLib.verifyEigenLayerOperatorRegistration(
            operator, address(this), DELEGATION_MANAGER, REGISTRY_COORDINATOR
        );
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
        return EigenLayerMiddlewareLib.getDelegation(
            REGISTRY,
            operatorDelegations[operator][registrationRoot],
            operator,
            registrationRoot,
            pubkey
        );
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
        external
        view
        returns (
            BLS.G1Point[] memory pubkeys,
            ISlasher.SignedDelegation[] memory delegations
        )
    {
        return SlashingLib.getAllDelegations(
            REGISTRY,
            operatorDelegations[operator][registrationRoot],
            operator,
            registrationRoot
        );
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

    /// @notice Internal function to set the rewards initiator
    /// @param newRewardsInitiator Address of the new rewards initiator
    function _setRewardsInitiator(address newRewardsInitiator) internal {
        REWARD_INITIATOR = newRewardsInitiator;
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

    /// @dev Execute slashing through the allocation manager for EigenLayer
    /// @param avs The address of the AVS initiating the slash
    /// @param params The slashing parameters
    /// @return success Whether the slashing was successful
    function _executeEigenLayerSlashing(
        address avs,
        IAllocationManagerTypes.SlashingParams memory params
    )
        internal
        returns (bool success)
    {
        try IAllocationManager(ALLOCATION_MANAGER).slashOperator(avs, params) {
            return true;
        } catch {
            return false;
        }
    }
}

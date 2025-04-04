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

import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { Registry } from "@urc/Registry.sol";
import { BLS } from "@urc/lib/BLS.sol";

import { EigenLayerMiddlewareLib } from "../libs/EigenLayerMiddlewareLib.sol";
import { EigenLayerMiddlewareStorage } from "../storage/EigenLayerMiddlewareStorage.sol";
import { EigenLayerRewardsHandler } from "./EigenLayerRewardsHandler.sol";

/// @title EigenLayer Middleware contract
/// @notice This contract is used to manage the registration of operators in EigenLayer core
contract EigenLayerMiddleware is
    OwnableUpgradeable,
    UUPSUpgradeable,
    EigenLayerMiddlewareStorage
{
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMapLib for EnumerableMapLib.Uint256ToBytes32Map;

    /// @notice Reference to the rewards handler contract
    EigenLayerRewardsHandler public rewardsHandler;

    // ========= EVENTS =========
    event RewardsHandlerSet(address rewardsHandler);

    // Custom error defined only in this contract (not in the interface)
    error RewardsHandlerNotSet();

    // ========= MODIFIERS =========

    /// @notice Modifier that restricts function access to operators registered
    /// in EigenLayer core
    /// @dev Reverts with CallerNotOperator if msg.sender is not an EigenLayer
    /// operator
    modifier onlyValidatorOperatorSet() {
        if (
            REGISTRY_COORDINATOR.getOperatorFromOperatorSet(uint32(0), msg.sender)
                == address(0)
        ) {
            revert OperatorIsNotYetRegisteredInValidatorOperatorSet();
        }
        _;
    }

    /// @notice when applied to a function, only allows the RegistryCoordinator to call it
    modifier onlyRegistryCoordinator() {
        if (msg.sender != address(REGISTRY_COORDINATOR)) {
            revert OnlyRegistryCoordinator();
        }
        _;
    }

    /// @notice only rewardsInitiator can call createAVSRewardsSubmission
    modifier onlyRewardsInitiator() {
        if (msg.sender != REWARD_INITIATOR) {
            revert OnlyRewardsInitiator();
        }
        _;
    }

    // Replace constructor with disable-initializers
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ========= EXTERNAL FUNCTIONS =========

    /// @notice Sets the rewards initiator address
    /// @param newRewardsInitiator The new rewards initiator address
    /// @dev only callable by the owner
    function setRewardsInitiator(address newRewardsInitiator) external onlyOwner {
        _setRewardsInitiator(newRewardsInitiator);
    }

    /// @notice Set the rewards handler contract
    /// @param _rewardsHandler Address of the rewards handler contract
    function setRewardsHandler(address _rewardsHandler) external onlyOwner {
        rewardsHandler = EigenLayerRewardsHandler(_rewardsHandler);
        emit RewardsHandlerSet(_rewardsHandler);
    }

    /// @notice Initialize the contract
    /// @param _owner Address of contract owner
    /// @param _avsDirectory Address of AVS directory contract
    /// @param _delegationManager Address of delegation manager contract
    /// @param _rewardCoordinator Address of reward coordinator contract
    /// @param _rewardInitiator Address of reward initiator
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

    /// @notice Register multiple validators for a single transaction
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

    /// @notice Batch set delegations for a registration root
    function batchSetDelegations(
        bytes32 registrationRoot,
        BLS.G1Point[] calldata pubkeys,
        ISlasher.SignedDelegation[] calldata delegations
    )
        external
    {
        _batchSetDelegations(registrationRoot, pubkeys, delegations);
    }

    /// @notice Unregister validators for a registration root
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

    /// @notice Create an operator set with the given strategies
    function createOperatorSet(IStrategy[] memory strategies)
        external
        onlyOwner
        returns (uint32 operatorSetId)
    {
        // Get the current operator set count from allocationManager
        uint256 currentSetCount =
            IAllocationManager(ALLOCATION_MANAGER).getOperatorSetCount(address(this));

        // Use the current count as the next ID
        operatorSetId = uint32(currentSetCount);

        IAllocationManagerTypes.CreateSetParams[] memory createSetParams =
            new IAllocationManagerTypes.CreateSetParams[](1);

        createSetParams[0] = IAllocationManagerTypes.CreateSetParams({
            operatorSetId: operatorSetId,
            strategies: strategies
        });

        IAllocationManager(ALLOCATION_MANAGER).createOperatorSets(
            address(this), createSetParams
        );

        return operatorSetId;
    }

    /// @notice Add strategies to an operator set
    function addStrategiesToOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external
        onlyOwner
    {
        _addStrategiesToOperatorSet(operatorSetId, strategies);
    }

    /// @notice Remove strategies from an operator set
    function removeStrategiesFromOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external
        onlyOwner
    {
        _removeStrategiesFromOperatorSet(operatorSetId, strategies);
    }

    /// @notice Updates the metadata URI for the AVS
    function updateAVSMetadataURI(string calldata metadataURI) external onlyOwner {
        _updateAVSMetadataURI(metadataURI);
    }

    /// @notice Creates operator-directed rewards
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

    /// @notice Set the address of the entity that can call `processClaim`
    function setClaimerFor(address claimer) external onlyOwner {
        _setClaimerFor(claimer);
    }

    /// @notice Create AVS rewards submission (deprecated)
    function createAVSRewardsSubmission(IRewardsCoordinator.RewardsSubmission[] calldata)
        external
        pure
    {
        revert UseCreateOperatorDirectedAVSRewardsSubmission();
    }

    /// @notice Process a rewards claim
    function processClaim(
        IRewardsCoordinator.RewardsMerkleClaim calldata claim,
        address recipient
    )
        external
    {
        _processClaim(claim, recipient);
    }

    /// @notice Opt in to slasher contract
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

    // ========= VIEW FUNCTIONS =========

    // Implementing view functions required by the interface
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

    /// @notice Get all registration roots for an operator
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

    /// @notice Query the stake amount for an operator across all strategies
    function getStrategiesAndStakes(address operator)
        external
        view
        returns (IStrategy[] memory strategies, uint256[] memory stakeAmounts)
    {
        strategies = getOperatorRestakedStrategies(operator);
        stakeAmounts = DELEGATION_MANAGER.getOperatorShares(operator, strategies);
    }

    /// @notice Query the registration status of an operator
    function verifyRegistration(address operator)
        public
        view
        returns (OperatorSet[] memory)
    {
        // First check if operator is registered in delegation manager
        bool isDelegated = DELEGATION_MANAGER.isOperator(operator);
        if (!isDelegated) {
            revert OperatorNotRegisteredInEigenLayer();
        }

        // Check operator's registration status in this AVS
        OperatorSet[] memory operatorSets =
            REGISTRY_COORDINATOR.getOperatorAllocatedOperatorSets(operator);
        if (operatorSets.length == 0) {
            revert OperatorNotRegisteredInAVS();
        }

        return operatorSets;
    }

    /// @notice Get the strategies an operator has restaked in
    function getOperatorRestakedStrategies(address operator)
        public
        view
        returns (IStrategy[] memory strategies)
    {
        OperatorSet[] memory operatorSets = verifyRegistration(operator);
        return EigenLayerMiddlewareLib.deduplicateStrategies(
            operatorSets, REGISTRY_COORDINATOR, operator
        );
    }

    /// @notice Get all strategies that can be restaked across all operator sets
    function getAllRestakeableStrategies() external view returns (address[] memory) {
        uint32 operatorSetCount = REGISTRY_COORDINATOR.getOperatorSetCount();

        // First count all strategies across all operator sets
        uint256 totalStrategiesCount = 0;
        for (uint32 i = 0; i < operatorSetCount; i++) {
            IStrategy[] memory operatorSet =
                REGISTRY_COORDINATOR.getOperatorSetStrategies(i);
            totalStrategiesCount += operatorSet.length;
        }

        // Create array to store all strategies (with potential duplicates)
        address[] memory allStrategies = new address[](totalStrategiesCount);
        uint256 allStrategiesLength = 0;

        // Fill array with all strategies
        for (uint32 i = 0; i < operatorSetCount; i++) {
            IStrategy[] memory operatorSet =
                REGISTRY_COORDINATOR.getOperatorSetStrategies(i);
            for (uint256 j = 0; j < operatorSet.length; j++) {
                allStrategies[allStrategiesLength] = address(operatorSet[j]);
                allStrategiesLength++;
            }
        }

        return EigenLayerMiddlewareLib.deduplicateStrategyAddresses(
            allStrategies, allStrategiesLength
        );
    }

    /// @notice Get all strategies for a given operator set
    function getRestakeableOperatorSetStrategies(uint32 operatorSetId)
        external
        view
        returns (IStrategy[] memory)
    {
        require(
            operatorSetId <= REGISTRY_COORDINATOR.getOperatorSetCount(),
            "Operator set not found"
        );
        return REGISTRY_COORDINATOR.getOperatorSetStrategies(operatorSetId);
    }

    /// @notice Gets a delegation for an operator by validator pubkey
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

    /// @notice Gets all delegations for an operator
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

    /// @notice Gets the registry coordinator
    /// @return Registry coordinator address
    function getRegistryCoordinator() external view returns (ITaiyiRegistryCoordinator) {
        return REGISTRY_COORDINATOR;
    }

    /// @notice Gets the rewards coordinator
    /// @return Rewards coordinator address
    function getRewardsCoordinator() external view returns (IRewardsCoordinator) {
        return REWARDS_COORDINATOR;
    }

    // ========= INTERNAL FUNCTIONS =========

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
            REGISTRY_COORDINATOR.getOperatorFromOperatorSet(0, delegateeAddress)
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

    function _createOperatorSet(IStrategy[] memory strategies) internal {
        REGISTRY_COORDINATOR.createOperatorSet(strategies);
    }

    function _addStrategiesToOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        internal
    {
        REGISTRY_COORDINATOR.addStrategiesToOperatorSet(operatorSetId, strategies);
    }

    function _removeStrategiesFromOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        internal
    {
        REGISTRY_COORDINATOR.removeStrategiesFromOperatorSet(operatorSetId, strategies);
    }

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

    function _setClaimerFor(address claimer) internal {
        REWARDS_COORDINATOR.setClaimerFor(claimer);
    }

    /// @notice Authorizes contract upgrades
    /// @param newImplementation Address of new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner { }

    function _setRewardsInitiator(address newRewardsInitiator) internal {
        REWARD_INITIATOR = newRewardsInitiator;
    }

    function _processClaim(
        IRewardsCoordinator.RewardsMerkleClaim calldata claim,
        address recipient
    )
        internal
    {
        IRewardsCoordinator(REWARDS_COORDINATOR).processClaim(claim, recipient);
    }

    function _updateAVSMetadataURI(string calldata metadataURI) internal {
        AVS_DIRECTORY.updateAVSMetadataURI(metadataURI);
    }
}

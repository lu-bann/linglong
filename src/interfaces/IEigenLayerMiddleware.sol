// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";

import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IAllocationManagerTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { BLS } from "@urc/lib/BLS.sol";

/// @title Interface for EigenLayer Middleware contract
/// @notice This interface defines the structure and functions of the EigenLayer Middleware
interface IEigenLayerMiddleware {
    // ========= EVENTS =========

    event AVSDirectorySet(address indexed avsDirectory);
    event RewardsInitiatorUpdated(
        address indexed previousRewardsInitiator, address indexed newRewardsInitiator
    );

    // ========= ERRORS =========

    error ValidatorNotActiveWithinEigenCore();
    error StrategyAlreadyRegistered();
    error StrategyNotRegistered();
    error OperatorNotRegistered();
    error OperatorNotRegisteredInEigenLayer();
    error CallerNotOperator();
    error OnlyRegistryCoordinator();
    error OnlyRewardsInitiator();
    error InvalidQueryParameters();
    error UnsupportedStrategy();
    error UseCreateOperatorDirectedAVSRewardsSubmission();
    error UseAllocationManagerForOperatorRegistration();
    error OperatorNotRegisteredInAVS();
    error OperatorIsNotYetRegisteredInValidatorOperatorSet();
    error OperatorIsNotYetRegisteredInUnderwriterOperatorSet();
    error OperatorNotOwnerOfRegistrationRoot();
    error RegistrationRootNotFound();
    error PubKeyNotFound();
    error OperatorSlashed();
    error OperatorUnregistered();
    error OperatorFraudProofPeriodNotOver();

    // ========= STRUCTS =========

    /// @notice Configuration struct for EigenLayer Middleware
    /// @dev Used during initialization to set up key parameters
    struct Config {
        /// @notice Address of the AVS directory contract
        address avsDirectory;
        /// @notice Address of EigenLayer's delegation manager
        address delegationManager;
        /// @notice Address of EigenLayer's reward coordinator
        address rewardCoordinator;
        /// @notice Address authorized to initiate rewards
        address rewardInitiator;
        /// @notice Address of the registry coordinator
        address registryCoordinator;
        /// @notice Percentage of rewards for underwriters in basis points
        uint256 underwriterShareBips;
        /// @notice Address of the validator registry contract
        address registry;
        /// @notice Address of the slasher contract
        address slasher;
        /// @notice Address of the allocation manager contract
        address allocationManager;
        /// @notice Minimum collateral required for registration
        uint256 registrationMinCollateral;
    }

    /// @notice Delegation info struct
    struct DelegationInfo {
        bytes32 registrationRoot;
        ISlasher.SignedDelegation delegation;
    }

    // ========= FUNCTIONS =========

    /// @notice Initialize the middleware contract with configuration
    /// @param owner Address that will own the contract
    /// @param config Configuration struct containing all initialization parameters
    function initialize(address owner, Config calldata config) external;

    /// @notice Register multiple validators in a single transaction
    /// @param registrations Array of signed registrations
    function registerValidators(IRegistry.SignedRegistration[] calldata registrations)
        external
        payable
        returns (bytes32 registrationRoot);

    /// @notice Unregister validators associated with a registration root
    /// @param registrationRoot The root hash of the registration to unregister
    function unregisterValidators(bytes32 registrationRoot) external;

    /// @notice Set multiple delegations for validators in a batch
    /// @param registrationRoot The root hash of the registration
    /// @param pubkeys Array of public keys for the validators
    /// @param delegations Array of signed delegations
    function batchSetDelegations(
        bytes32 registrationRoot,
        BLS.G1Point[] calldata pubkeys,
        ISlasher.SignedDelegation[] calldata delegations
    )
        external;

    /// @notice Create a new operator set with specified strategies
    /// @param strategies Array of strategy contracts
    /// @return The ID of the newly created operator set
    function createOperatorSet(IStrategy[] memory strategies) external returns (uint32);

    /// @notice Add strategies to an existing operator set
    /// @param operatorSetId The ID of the operator set
    /// @param strategies Array of strategy contracts to add
    function addStrategiesToOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external;

    /// @notice Remove strategies from an existing operator set
    /// @param operatorSetId The ID of the operator set
    /// @param strategies Array of strategy contracts to remove
    function removeStrategiesFromOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external;

    /// @notice Update the AVS metadata URI
    /// @param metadataURI The new metadata URI
    function updateAVSMetadataURI(string calldata metadataURI) external;

    /// @notice Set a new rewards initiator address
    /// @param newRewardsInitiator The address of the new rewards initiator
    function setRewardsInitiator(address newRewardsInitiator) external;

    /// @notice Create operator-directed AVS rewards submissions
    /// @param operatorDirectedRewardsSubmissions Array of operator-directed rewards submissions
    function createOperatorDirectedAVSRewardsSubmission(
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata
            operatorDirectedRewardsSubmissions
    )
        external;

    /// @notice Set a claimer address for the caller
    /// @param claimer The address that can claim rewards on behalf of the caller
    function setClaimerFor(address claimer) external;

    /// @notice Create AVS rewards submissions
    /// @param submissions Array of rewards submissions
    function createAVSRewardsSubmission(
        IRewardsCoordinator.RewardsSubmission[] calldata submissions
    )
        external;

    /// @notice Process a reward claim
    /// @param claim The Merkle claim for rewards
    /// @param recipient The address to receive the rewards
    function processClaim(
        IRewardsCoordinator.RewardsMerkleClaim calldata claim,
        address recipient
    )
        external;

    /// @notice Executes slashing for an operator through the EigenLayer allocation manager
    /// @param params The slashing parameters
    /// @return success Whether the slashing was successful
    function executeSlashing(IAllocationManagerTypes.SlashingParams memory params)
        external
        returns (bool success);

    // ========= VIEW FUNCTIONS =========

    /// @notice Get the strategies and stake amounts for an operator
    /// @param operator The operator address
    /// @return strategies Array of strategy contracts
    /// @return stakeAmounts Array of stake amounts corresponding to each strategy
    function getStrategiesAndStakes(address operator)
        external
        view
        returns (IStrategy[] memory strategies, uint256[] memory stakeAmounts);

    /// @notice Verify if an operator is registered in EigenLayer
    /// @param operator The operator address
    /// @return Array of operator sets the operator is registered in
    function verifyEigenLayerOperatorRegistration(address operator)
        external
        view
        returns (OperatorSet[] memory);

    /// @notice Get the restaked strategies for an operator
    /// @param operator The operator address
    /// @return strategies Array of strategy contracts the operator has restaked in
    function getOperatorRestakedStrategies(address operator)
        external
        view
        returns (IStrategy[] memory strategies);

    /// @notice Get a specific delegation for an operator and public key
    /// @param operator The operator address
    /// @param registrationRoot The root hash of the registration
    /// @param pubkey The public key of the validator
    /// @return The signed delegation for the specified validator
    function getDelegation(
        address operator,
        bytes32 registrationRoot,
        BLS.G1Point calldata pubkey
    )
        external
        view
        returns (ISlasher.SignedDelegation memory);

    /// @notice Get all delegations for an operator and registration root
    /// @param operator The operator address
    /// @param registrationRoot The root hash of the registration
    /// @return pubkeys Array of validator public keys
    /// @return delegations Array of signed delegations corresponding to each public key
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

    /// @notice Get the total number of operator sets
    /// @return The count of operator sets
    function getOperatorSetCount() external view returns (uint32);

    /// @notice Gets the rewards initiator address
    /// @return Address of the rewards initiator
    function getRewardInitiator() external view returns (address);

    /// @notice Gets the underwriter share in basis points
    /// @return Underwriter share in basis points
    function getUnderwriterShareBips() external view returns (uint256);

    /// @notice Gets the registry coordinator
    /// @return Registry coordinator address
    function getRegistryCoordinator() external view returns (ITaiyiRegistryCoordinator);

    /// @notice Gets the rewards coordinator
    /// @return Rewards coordinator address
    function getRewardsCoordinator() external view returns (IRewardsCoordinator);

    /// @notice Get all registration roots for an operator
    /// @param operator The operator address
    /// @return Array of registration roots
    function getOperatorRegistrationRoots(address operator)
        external
        view
        returns (bytes32[] memory);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IAllocationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { ISlasher } from "@urc/ISlasher.sol";

/// @title ILinglongSlasher Interface
/// @notice Interface for the Linglong Slasher contract which connects URC's ISlasher
/// with EigenLayer's slashing system through interactive and non-interactive
/// fraud proofs.
interface ILinglongSlasher is ISlasher {
    /// @notice Challenger implementation details
    struct ChallengerImpl {
        address addr; // Address of the challenger
        string name; // Name of the challenger implementation
        bool isActive; // Whether this challenger is active
        bytes32 violationType; // Violation type supported by this challenger
    }

    /// @notice Custom errors for better gas efficiency and clarity
    error NotInitialized();
    error InstantSlasherNotSet();
    error VetoSlasherNotSet();
    error InvalidSlashAmount();
    error InvalidInstantSlasher();
    error InvalidVetoSlasher();
    error InvalidAllocationManager();
    error InvalidChallengerAddress();
    error MethodNotSupported();
    error AlreadySlashed();
    error UnsupportedRestakingProtocol();
    error UnknownViolationType();
    error InvalidOperator();
    error ProofVerificationFailed();
    error SlasherCallFailed();
    error AllocationManagerCallFailed();
    error ChallengerAlreadyRegistered();
    error ChallengerNotRegistered();
    error InvalidChallengerImpl();
    error ViolationTypeNotSupported();
    error ViolationTypeAlreadyRegistered();
    error EmptyViolationTypeName();
    error InvalidSlasher();

    /// @notice Emitted when a slashing result is recorded
    /// @param operator The operator being slashed
    /// @param operatorSetId The ID of the operator set
    /// @param wasExecuted Whether the slashing was executed
    event SlashingResult(
        address indexed operator, uint32 indexed operatorSetId, bool wasExecuted
    );

    /// @notice Emitted when a violation type is configured for a specific operator set
    /// @param violationType The type of violation
    /// @param operatorSetId The ID of the operator set that handles this violation
    /// @param slashAmount The amount to slash for this violation (in WAD)
    /// @param isInstantSlashing Whether this violation uses instant slashing (or interactive)
    event ViolationTypeConfigured(
        bytes32 indexed violationType,
        uint32 indexed operatorSetId,
        uint256 slashAmount,
        bool isInstantSlashing
    );

    /// @notice Emitted when the EigenLayer slasher contracts are set
    /// @param instantSlasher The address of the instant slasher contract
    /// @param vetoSlasher The address of the veto slasher contract
    event SlashersSet(address indexed instantSlasher, address indexed vetoSlasher);

    /// @notice Events for challenger registration and management
    event ChallengerRegistered(address indexed challenger, string name);
    event ChallengerDeactivated(address indexed challenger);
    event ChallengerReactivated(address indexed challenger);
    event ViolationTypeRegistered(
        bytes32 indexed violationType, address indexed challenger
    );
    event NewViolationTypeDefined(
        bytes32 indexed violationType, string name, string description
    );

    /// @notice Sets the EigenLayer middleware address
    /// @param _eigenLayerMiddleware The address of the EigenLayer middleware
    function setEigenLayerMiddleware(address _eigenLayerMiddleware) external;

    /// @notice Sets URC commitment type to violation type mapping
    /// @param commitmentType The URC commitment type
    /// @param violationType The violation type
    function setURCCommitmentTypeToViolationType(
        uint64 commitmentType,
        bytes32 violationType
    )
        external;

    /// @notice Registers a challenger that implements ILinglongChallenger
    /// @param challenger The address of the challenger to register
    function registerChallenger(address challenger) external;

    /// @notice Deactivates a registered challenger
    /// @param challenger The address of the challenger to deactivate
    function deactivateChallenger(address challenger) external;

    /// @notice Reactivates a previously deactivated challenger
    /// @param challenger The address of the challenger to reactivate
    function reactivateChallenger(address challenger) external;

    /// @notice Get all registered challengers
    /// @return challengers Array of registered challenger addresses
    function getRegisteredChallengers() external view returns (address[] memory);

    /// @notice Get all active challengers for a violation type
    /// @param violationType The violation type to query
    /// @return challengers The active challenger address for the violation type
    function getViolationTypeChallengers(bytes32 violationType)
        external
        view
        returns (address);

    /// @notice Get all registered violation types
    /// @return violationTypes Array of registered violation types
    function getRegisteredViolationTypes() external view returns (bytes32[] memory);

    /// @notice Get all violation types supported by a challenger
    /// @param challenger The challenger address
    /// @return violationTypes The violation type supported by the challenger
    function getChallengerViolationTypes(address challenger)
        external
        view
        returns (bytes32);

    /// @notice Check if a slashing request is currently in progress for an operator
    /// @param operator The operator address to check
    /// @param operatorSetId The operator set ID
    /// @param challengeContract The challenger contract to check
    /// @return inProgress Whether a slashing is in progress
    /// @return slashingId The ID of the slashing request (if any)
    function isSlashingInProgress(
        address operator,
        uint32 operatorSetId,
        address challengeContract
    )
        external
        view
        returns (bool inProgress, uint256 slashingId);

    /// @notice Returns the address of the EigenLayer middleware
    function EIGENLAYER_MIDDLEWARE() external view returns (address);

    /// @notice Returns the address of the allocation manager
    function ALLOCATION_MANAGER() external view returns (address);

    /// @notice Returns a predefined violation type constant
    function VIOLATION_TYPE_NONE() external view returns (bytes32);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { VerificationStatus } from "../types/CommonTypes.sol";
import { IAllocationManagerTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { ISlasher } from "@urc/ISlasher.sol";

/// @title ILinglongChallenger
/// @notice Interface for the LinglongChallenger contract
interface ILinglongChallenger {
    /// @notice Event emitted when a new challenge is initiated
    /// @param challengeId Unique ID of the challenge
    /// @param registrationRoot Registration root of the challenged validator
    /// @param operator Address of the operator being challenged
    /// @param challenger Address of the entity initiating the challenge
    event ChallengeInitiated(
        bytes32 indexed challengeId,
        bytes32 indexed registrationRoot,
        address indexed operator,
        address challenger
    );

    /// @notice Event emitted when a challenge is resolved
    /// @param challengeId Unique ID of the challenge
    /// @param operator Address of the operator who was challenged
    /// @param resolver Address of the entity that resolved the challenge
    /// @param proven Whether the challenge was proven valid
    event ChallengeResolved(
        bytes32 indexed challengeId,
        address indexed operator,
        address indexed resolver,
        bool proven
    );

    /// @notice Get a descriptive name for this challenger implementation
    /// @return The name of the implementation
    function getImplementationName() external view returns (string memory);

    /// @notice Verify a proof of violation
    /// @param payload The proof payload
    /// @return status The status of the verification
    function verifyProof(bytes memory payload)
        external
        returns (VerificationStatus status);

    /// @notice Initiates a challenge against an operator for a specific commitment
    /// @param registrationRoot The registration root of the validator
    /// @param operator The address of the operator
    /// @param commitmentData The commitment data that's being challenged
    /// @param signature The signature that's being challenged
    /// @return The ID of the created challenge
    function initiateChallenge(
        bytes32 registrationRoot,
        address operator,
        bytes calldata commitmentData,
        bytes calldata signature
    )
        external
        payable
        returns (bytes32);

    /// @notice Resolves a challenge
    /// @param challengeId The ID of the challenge
    /// @param proven Whether the challenge was proven valid
    function resolveChallenge(bytes32 challengeId, bool proven) external;

    /// @notice Determines if the challenger should perform an instant slash
    /// @param registrationRoot The registration root of the validator
    /// @param signedCommitment The signed commitment under scrutiny
    /// @param evidence The evidence provided for the slash
    /// @return Whether an instant slash should be performed
    function shouldInstantSlash(
        bytes32 registrationRoot,
        ISlasher.SignedCommitment memory signedCommitment,
        bytes memory evidence
    )
        external
        view
        returns (bool);

    /// @notice Gets the amount to slash from an operator
    /// @param operator The address of the operator
    /// @param registrationRoot The registration root of the validator
    /// @return The amount to slash
    function getOperatorSlashingAmount(
        address operator,
        bytes32 registrationRoot
    )
        external
        view
        returns (uint256);

    /// @notice Get the violation type supported by this challenger
    /// @return violationType The supported violation type
    function getSupportedViolationType() external view returns (bytes32);

    /// @notice Check if this challenger supports a specific violation type
    /// @param violationType The violation type to check
    /// @return isSupported Whether the violation type is supported
    function supportedViolationType(bytes32 violationType)
        external
        view
        returns (bool isSupported);

    /// @notice Return whether the challenger uses instant slashing
    /// @return isInstant Whether instant slashing is used
    function isInstantSlashing() external view returns (bool isInstant);

    /// @notice Return the amount to slash
    /// @return slashAmount The amount to slash (in WAD)
    function getSlashAmount() external view returns (uint256 slashAmount);

    /// @notice Check if slashing is in progress for an operator
    /// @param operator The operator address
    /// @param operatorSetId The operator set ID
    /// @return inProgress Whether slashing is in progress
    /// @return slashingId The ID of the slashing
    function isSlashingInProgress(
        address operator,
        uint96 operatorSetId
    )
        external
        view
        returns (bool inProgress, uint256 slashingId);
}

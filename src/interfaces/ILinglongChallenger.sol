// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IAllocationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";

/// @title ILinglongChallenger
/// @notice Base interface for all Linglong challenger implementations
/// @dev Both interactive and non-interactive challengers should implement this interface
interface ILinglongChallenger {
    /// @notice Enum representing the status of a verification request
    enum VerificationStatus {
        Invalid, // Verification failed or not found
        Pending, // Verification is in progress
        Verified // Verification succeeded

    }

    /// @notice Verify a proof of violation
    /// @param payload The proof payload
    /// @return status The status of the verification
    function verifyProof(bytes memory payload)
        external
        view
        returns (VerificationStatus status);

    /// @notice Get a descriptive name for this challenger implementation
    /// @return name The name of the challenger implementation
    function getImplementationName() external view returns (string memory name);

    /// @notice Get the violation type supported by this challenger
    /// @return violationType The supported violation type
    function getSupportedViolationTypes() external view returns (bytes32);

    /// @notice Check if this challenger supports a specific violation type
    /// @param violationType The violation type to check
    /// @return isSupported Whether the violation type is supported
    function supportsViolationType(bytes32 violationType)
        external
        view
        returns (bool isSupported);

    /// @notice Return whether the challenger uses instant slashing
    /// @return isInstant Whether instant slashing is used
    function isInstantSlashing() external view returns (bool isInstant);

    /// @notice Return the operator set ID associated with this challenger
    /// @return operatorSetId The operator set ID
    function getOperatorSetId() external view returns (uint32 operatorSetId);

    /// @notice Return the amount to slash
    /// @return slashAmount The amount to slash (in WAD)
    function getSlashAmount() external view returns (uint256 slashAmount);

    /// @notice Initiate slashing for an operator
    /// @param params The slashing parameters
    /// @return success Whether the operation succeeded
    /// @return returnData Any return data from the operation
    function initiateSlashing(IAllocationManager.SlashingParams memory params)
        external
        returns (bool success, bytes memory returnData);

    /// @notice Check if slashing is in progress for an operator
    /// @param operator The operator address
    /// @param operatorSetId The operator set ID
    /// @return inProgress Whether slashing is in progress
    /// @return slashingId The ID of the slashing
    function isSlashingInProgress(
        address operator,
        uint32 operatorSetId
    )
        external
        view
        returns (bool inProgress, uint256 slashingId);
}

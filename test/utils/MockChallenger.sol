// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ILinglongChallenger } from "../../src/interfaces/ILinglongChallenger.sol";
import { IAllocationManagerTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";

/// @dev Mock implementation of ILinglongChallenger for testing
contract MockLinglongChallenger is ILinglongChallenger {
    bool private _isInstantSlashing;
    bool private _slashingInProgress;
    uint256 private _slashId;

    function setIsInstantSlashing(bool value) external {
        _isInstantSlashing = value;
    }

    function setSlashingInProgress(bool value) external {
        _slashingInProgress = value;
        _slashId = value ? 1 : 0;
    }

    function getImplementationName() external pure returns (string memory) {
        return "MockLinglongChallenger";
    }

    function getSupportedViolationTypes() external pure returns (bytes32) {
        return keccak256("URC_VIOLATION");
    }

    function isInstantSlashing() external view returns (bool) {
        return _isInstantSlashing;
    }

    function getOperatorSetId() external pure returns (uint32) {
        return 1;
    }

    function getSlashAmount() external pure returns (uint256) {
        return 1 ether;
    }

    function verifyProof(bytes memory) external pure returns (VerificationStatus) {
        return VerificationStatus.Verified;
    }

    function initiateSlashing(IAllocationManagerTypes.SlashingParams memory)
        external
        view
        returns (bool success, bytes memory returnData)
    {
        success = true;
        returnData = abi.encode(_isInstantSlashing);
    }

    function isSlashingInProgress(
        address,
        uint32
    )
        external
        view
        returns (bool inProgress, uint256 slashingId)
    {
        return (_slashingInProgress, _slashId);
    }

    function supportsViolationType(bytes32) external pure returns (bool) {
        return true;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ILinglongChallenger } from "../../src/interfaces/ILinglongChallenger.sol";

import { ChallengeStatus, VerificationStatus } from "../../src/types/CommonTypes.sol";
import { IAllocationManagerTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { ISlasher } from "@urc/ISlasher.sol";

/// @dev Mock implementation of ILinglongChallenger for testing
contract MockLinglongChallenger is ILinglongChallenger {
    bool private _isInstantSlashing;
    bool private _slashingInProgress;
    uint256 private _slashId;

    // Define the Challenge struct
    struct Challenge {
        bytes32 id;
        uint256 createdAt;
        address challenger;
        address commitmentSigner;
        ChallengeStatus status;
        uint8 preconfType;
        bytes commitmentData;
        bytes signature;
    }

    // Mapping to keep track of challenges
    mapping(bytes32 => Challenge) public challenges;

    // Challenge counter
    uint256 public challengeCount;

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

    function getSupportedViolationType() external pure returns (bytes32) {
        return keccak256("URC_VIOLATION");
    }

    function isInstantSlashing() external view returns (bool) {
        return _isInstantSlashing;
    }

    function getSlashAmount() external pure returns (uint256) {
        return 1e18; // 100 WAD percent
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
        uint96
    )
        external
        view
        returns (bool inProgress, uint256 slashingId)
    {
        return (_slashingInProgress, _slashId);
    }

    function supportedViolationType(bytes32) external pure returns (bool) {
        return true;
    }

    // Mock function for initiating a challenge
    function initiateChallenge(
        bytes32 registrationRoot,
        address operator,
        bytes calldata commitmentData,
        bytes calldata signature
    )
        external
        payable
        override
        returns (bytes32)
    {
        bytes32 challengeId =
            keccak256(abi.encode(registrationRoot, operator, challengeCount++));

        // Create a new challenge
        Challenge memory challenge = Challenge({
            id: challengeId,
            createdAt: block.timestamp,
            challenger: msg.sender,
            commitmentSigner: operator,
            status: ChallengeStatus.Open,
            preconfType: 0, // Default preconf type
            commitmentData: commitmentData,
            signature: signature
        });

        // Store the challenge
        challenges[challengeId] = challenge;

        // Emit the event
        emit ChallengeInitiated(challengeId, registrationRoot, operator, msg.sender);

        return challengeId;
    }

    // Mock function for resolving a challenge
    function resolveChallenge(bytes32 challengeId, bool proven) external override {
        Challenge storage challenge = challenges[challengeId];

        // Basic validation
        require(challenge.id != bytes32(0), "Challenge not found");
        require(challenge.status == ChallengeStatus.Open, "Challenge already resolved");

        // Update challenge status
        challenge.status = proven ? ChallengeStatus.Proven : ChallengeStatus.Disproven;

        // Emit the event
        emit ChallengeResolved(
            challengeId, challenge.commitmentSigner, msg.sender, proven
        );
    }

    // Function to check if the challenger should perform an instant slash
    function shouldInstantSlash(
        bytes32 registrationRoot,
        ISlasher.SignedCommitment memory signedCommitment,
        bytes memory evidence
    )
        external
        view
        override
        returns (bool)
    {
        // For testing, we'll use the isInstantSlashing flag to determine the outcome
        return _isInstantSlashing;
    }

    // Function to get the operator slashing amount
    function getOperatorSlashingAmount(
        address operator,
        bytes32 registrationRoot
    )
        external
        pure
        override
        returns (uint256)
    {
        // For mock purposes, return a fixed amount
        return 1 ether;
    }
}

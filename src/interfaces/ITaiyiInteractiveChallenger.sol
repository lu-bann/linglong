// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ChallengeStatus } from "../types/CommonTypes.sol";

import { VerificationStatus } from "../types/CommonTypes.sol";
import { PreconfRequestAType } from "../types/PreconfRequestATypes.sol";
import { PreconfRequestBType } from "../types/PreconfRequestBTypes.sol";

interface ITaiyiInteractiveChallenger {
    struct Challenge {
        bytes32 id;
        uint256 createdAt;
        address challenger;
        address commitmentSigner;
        ChallengeStatus status;
        uint8 preconfType; // 0 - TypeA | 1 - TypeB
        bytes commitmentData; // abi encoded commitment data (PreconfRequestAType | PreconfRequestBType)
        bytes signature; // signed digest of the commitment data
    }

    error TargetSlotNotInChallengeCreationWindow();
    error BlockNotFinalized();
    error SignerDoesNotMatchPreconfRequest();
    error ChallengeBondInvalid();
    error ChallengeAlreadyResolved();
    error ChallengeAlreadyExists();
    error ChallengeDoesNotExist();
    error ChallengeExpired();
    error ChallengeNotExpired();
    // Proof verification errors
    error TargetSlotDoesNotMatch();
    error GenesisTimestampDoesNotMatch();
    error TaiyiCoreAddressDoesNotMatch();
    error ChallengeIdDoesNotMatch();
    error CommitmentSignerDoesNotMatch();
    error BlockHashDoesNotMatch();

    /// @notice Get all challenges.
    /// @return challenges An array of challenges.
    function getChallenges() external view returns (Challenge[] memory);

    /// @notice Get all open challenges.
    /// @return challenges An array of open challenges.
    function getOpenChallenges() external view returns (Challenge[] memory);

    /// @notice Get a challenge by id.
    /// @param id The id of the challenge.
    /// @return challenge The challenge.
    function getChallenge(bytes32 id) external view returns (Challenge memory);

    /// @notice Resolve an expired challenge.
    /// @dev This function can be called by anyone to resolve an expired challenge.
    /// @param id The id of the expired challenge.
    function resolveExpiredChallenge(bytes32 id) external;

    /// @notice Set the address of the SP1 gateway contract.
    /// @param verifierGateway The address of the SP1 gateway contract.
    function setVerifierGateway(address verifierGateway) external;

    /// @notice Set the verification key for the interactive fraud proof program.
    /// @param _interactiveFraudProofVKey The verification key.
    function setInteractiveFraudProofVKey(bytes32 _interactiveFraudProofVKey) external;
}

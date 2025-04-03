// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {
    IAllocationManager,
    IAllocationManagerTypes
} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { ISlasher } from "@urc/ISlasher.sol";

import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { Initializable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { ILinglongChallenger } from "../interfaces/ILinglongChallenger.sol";
import { ILinglongSlasher } from "../interfaces/ILinglongSlasher.sol";
import { ITaiyiInteractiveChallenger } from
    "../interfaces/ITaiyiInteractiveChallenger.sol";
import { LinglongSlasherStorage } from "../storage/LinglongSlasherStorage.sol";

/// @title LinglongSlasher
/// @notice Implementation of the ILinglongSlasher interface that bridges between URC's slashing system
/// and EigenLayer's slashing mechanisms. This contract receives slashing requests from the URC
/// Registry, routes them to appropriate challenger contracts (interactive or non-interactive),
/// and upon successful challenge, calls EigenLayer's AllocationManager to slash operators.
contract LinglongSlasher is Initializable, OwnableUpgradeable, LinglongSlasherStorage {
    using ECDSA for bytes32;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @dev Modifier to check that the contract is properly initialized
    modifier onlyInitialized() {
        if (ALLOCATION_MANAGER == address(0)) revert NotInitialized();
        _;
    }

    /// @notice Constructor - disabled for upgradeable pattern
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract (replaces constructor for upgradeable pattern)
    /// @param _initialOwner The initial contract owner
    /// @param _allocationManager The address of the allocation manager
    function initialize(
        address _initialOwner,
        address _allocationManager
    )
        external
        initializer
    {
        __Ownable_init(_initialOwner);
        if (_allocationManager == address(0)) revert InvalidAllocationManager();
        ALLOCATION_MANAGER = _allocationManager;
    }

    /// @inheritdoc ILinglongSlasher
    function setEigenLayerMiddleware(address _eigenLayerMiddleware)
        external
        override
        onlyOwner
    {
        EIGENLAYER_MIDDLEWARE = _eigenLayerMiddleware;
    }

    /// @inheritdoc ILinglongSlasher
    function setURCCommitmentTypeToViolationType(
        uint64 commitmentType,
        bytes32 violationType
    )
        external
        override
        onlyOwner
    {
        URCCommitmentTypeToViolationType[commitmentType] = violationType;
    }

    /// @inheritdoc ILinglongSlasher
    function registerChallenger(address challenger) external onlyOwner {
        if (challenger == address(0)) revert InvalidChallengerAddress();
        if (registeredChallengers.contains(challenger)) {
            revert ChallengerAlreadyRegistered();
        }

        // Verify the challenger implements ILinglongChallenger
        string memory name;
        try ILinglongChallenger(challenger).getImplementationName() returns (
            string memory implName
        ) {
            name = implName;
        } catch {
            revert InvalidChallengerImpl();
        }

        // Get supported violation types
        bytes32 supportedType =
            ILinglongChallenger(challenger).getSupportedViolationTypes();

        registeredChallengers.add(challenger);

        challengerImpls[challenger].addr = challenger;
        challengerImpls[challenger].name = name;
        challengerImpls[challenger].isActive = true;
        challengerImpls[challenger].violationType = supportedType;

        registeredViolationTypes.add(supportedType);
        violationTypeChallengers[supportedType] = challenger;

        emit ChallengerRegistered(challenger, name);
        emit ViolationTypeRegistered(supportedType, challenger);
    }

    /// @inheritdoc ILinglongSlasher
    function deactivateChallenger(address challenger) external override onlyOwner {
        if (!registeredChallengers.contains(challenger)) revert ChallengerNotRegistered();
        challengerImpls[challenger].isActive = false;
        emit ChallengerDeactivated(challenger);
    }

    /// @inheritdoc ILinglongSlasher
    function reactivateChallenger(address challenger) external override onlyOwner {
        if (!registeredChallengers.contains(challenger)) revert ChallengerNotRegistered();
        challengerImpls[challenger].isActive = true;
        emit ChallengerReactivated(challenger);
    }

    /// @inheritdoc ILinglongSlasher
    function getRegisteredChallengers()
        external
        view
        override
        returns (address[] memory)
    {
        address[] memory challengers = new address[](registeredChallengers.length());
        for (uint256 i = 0; i < registeredChallengers.length(); i++) {
            challengers[i] = registeredChallengers.at(i);
        }
        return challengers;
    }

    /// @inheritdoc ILinglongSlasher
    function getViolationTypeChallengers(bytes32 violationType)
        external
        view
        override
        returns (address)
    {
        return violationTypeChallengers[violationType];
    }

    /// @inheritdoc ILinglongSlasher
    function getRegisteredViolationTypes()
        external
        view
        override
        returns (bytes32[] memory)
    {
        bytes32[] memory violationTypes = new bytes32[](registeredViolationTypes.length());
        for (uint256 i = 0; i < registeredViolationTypes.length(); i++) {
            violationTypes[i] = registeredViolationTypes.at(i);
        }
        return violationTypes;
    }

    /// @inheritdoc ILinglongSlasher
    function getChallengerViolationTypes(address challenger)
        external
        view
        override
        returns (bytes32)
    {
        if (!registeredChallengers.contains(challenger)) revert ChallengerNotRegistered();
        return challengerImpls[challenger].violationType;
    }

    /// @inheritdoc ISlasher
    function slash(
        ISlasher.Delegation calldata, /* delegation */
        ISlasher.Commitment calldata, /* commitment */
        bytes calldata, /* evidence */
        address /* challenger */
    )
        external
        pure
        override
        returns (uint256 /* slashAmountGwei */ )
    {
        // This method is required by ISlasher but not used
        revert MethodNotSupported();
    }

    /// @inheritdoc ISlasher
    /// @notice Slash an operator for a given commitment
    /// @dev The URC Registry will call this function to slash a registered operator if supplied with a valid commitment and evidence
    /// @param commitment The commitment message
    /// @param evidence Arbitrary evidence for the slashing
    /// @return slashAmountGwei The amount of Gwei slashed (always 0 for Taiyi, as EigenLayer handles actual slashing)
    function slashFromOptIn(
        ISlasher.Commitment calldata commitment,
        bytes calldata evidence,
        address /* challenger */
    )
        external
        override
        onlyInitialized
        returns (uint256 slashAmountGwei)
    {
        // Prevent double slashing by tracking the commitment hash
        bytes32 commitmentHash = keccak256(abi.encode(commitment, evidence));
        if (slashedCommitments[commitmentHash]) revert AlreadySlashed();
        if (commitment.slasher != address(this)) revert InvalidSlasher();

        // Get violation type and challenger contract
        bytes32 violationType =
            URCCommitmentTypeToViolationType[commitment.commitmentType];
        address challengerContract = violationTypeChallengers[violationType];

        // Extract operator from commitment
        address operator = _extractOperatorFromCommitment(commitment);

        // Verify proof and get slashing status
        bool shouldExecuteSlashing = _verifyProofAndInitiateSlashing(
            operator, challengerContract, commitment.payload, violationType
        );

        // If direct execution is requested, execute the slashing
        if (shouldExecuteSlashing) {
            slashedCommitments[commitmentHash] = true;
            emit SlashingResult(
                operator, ILinglongChallenger(challengerContract).getOperatorSetId(), true
            );
        }

        // Always return 0 for slashAmountGwei
        // This is because collateral management is handled by EigenLayer
        return 0;
    }

    /// @dev Extract the operator address from a commitment
    /// @param commitment The commitment to extract from
    /// @return operator The extracted operator address
    function _extractOperatorFromCommitment(ISlasher.Commitment calldata commitment)
        internal
        pure
        returns (address operator)
    {
        (bytes memory payload) = abi.decode(commitment.payload, (bytes));
        ITaiyiInteractiveChallenger.Challenge memory challenge =
            abi.decode(payload, (ITaiyiInteractiveChallenger.Challenge));
        return challenge.commitmentSigner;
    }

    /// @dev Verify the proof and initiate slashing if needed
    /// @param operator The operator to slash
    /// @param challengerContract The challenger contract address
    /// @param payload The commitment payload
    /// @return shouldExecuteDirectly Whether to execute slashing directly
    function _verifyProofAndInitiateSlashing(
        address operator,
        address challengerContract,
        bytes memory payload,
        bytes32 /* violationType */
    )
        internal
        returns (bool shouldExecuteDirectly)
    {
        // Decode the original payload for verification
        (bytes memory decodedPayload) = abi.decode(payload, (bytes));

        // Verify the proof
        ILinglongChallenger.VerificationStatus status =
            ILinglongChallenger(challengerContract).verifyProof(decodedPayload);

        if (status != ILinglongChallenger.VerificationStatus.Verified) {
            revert ProofVerificationFailed();
        }

        // Get slashing configuration
        bool isInstantSlashing =
            ILinglongChallenger(challengerContract).isInstantSlashing();
        uint32 operatorSetId = ILinglongChallenger(challengerContract).getOperatorSetId();

        // For veto slashing, check if slashing is already in progress
        if (!isInstantSlashing) {
            (bool inProgress,) =
                this.isSlashingInProgress(operator, operatorSetId, challengerContract);
            if (inProgress) {
                // Return without further action if slashing is already in progress
                return false;
            }
        }

        // Prepare slashing parameters
        IAllocationManagerTypes.SlashingParams memory params = _prepareSlashingParams(
            operator,
            operatorSetId,
            ILinglongChallenger(challengerContract).getSlashAmount(),
            string(
                abi.encodePacked("URC slash: ", challengerImpls[challengerContract].name)
            )
        );

        // Initiate slashing
        (bool success, bytes memory returnData) =
            ILinglongChallenger(challengerContract).initiateSlashing(params);

        if (!success) revert SlasherCallFailed();

        // Check if direct execution is requested
        shouldExecuteDirectly = abi.decode(returnData, (bool));
        if (shouldExecuteDirectly) {
            if (!_executeSlashing(address(this), params)) {
                revert AllocationManagerCallFailed();
            }
        }

        return shouldExecuteDirectly;
    }

    /// @inheritdoc ILinglongSlasher
    function isSlashingInProgress(
        address operator,
        uint32 operatorSetId,
        address challengeContract
    )
        external
        view
        override
        returns (bool inProgress, uint256 slashingId)
    {
        return ILinglongChallenger(challengeContract).isSlashingInProgress(
            operator, operatorSetId
        );
    }

    // ============== INTERNAL FUNCTIONS ===============

    /// @dev Execute slashing through the allocation manager
    /// @param avs The address of the AVS initiating the slash
    /// @param params The slashing parameters
    /// @return success Whether the slashing was successful
    function _executeSlashing(
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

    /// @dev Prepare slashing parameters for EigenLayer
    /// @param operator The operator to slash
    /// @param operatorSetId The operator set ID
    /// @param slashAmount The amount to slash
    /// @param description Description of the slashing
    /// @return params The slashing parameters
    function _prepareSlashingParams(
        address operator,
        uint32 operatorSetId,
        uint256 slashAmount,
        string memory description
    )
        internal
        view
        returns (IAllocationManagerTypes.SlashingParams memory)
    {
        // Create operator set structure using proper format for getAllocatedStrategies
        OperatorSet memory opSet =
            OperatorSet({ avs: EIGENLAYER_MIDDLEWARE, id: operatorSetId });

        IStrategy[] memory strategies =
            IAllocationManager(ALLOCATION_MANAGER).getAllocatedStrategies(operator, opSet);

        uint256[] memory wadsToSlash = new uint256[](strategies.length);
        for (uint256 i = 0; i < strategies.length; i++) {
            wadsToSlash[i] = slashAmount;
        }

        return IAllocationManagerTypes.SlashingParams({
            operator: operator,
            operatorSetId: operatorSetId,
            strategies: strategies,
            wadsToSlash: wadsToSlash,
            description: description
        });
    }
}

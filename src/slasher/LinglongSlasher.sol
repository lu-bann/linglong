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

import { IEigenLayerMiddleware } from "../interfaces/IEigenLayerMiddleware.sol";
import { ISymbioticNetworkMiddleware } from
    "../interfaces/ISymbioticNetworkMiddleware.sol";
import { ITaiyiInteractiveChallenger } from
    "../interfaces/ITaiyiInteractiveChallenger.sol";
import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";

import { OperatorSubsetLib } from "../libs/OperatorSubsetLib.sol";
import { LinglongSlasherStorage } from "../storage/LinglongSlasherStorage.sol";
import { VerificationStatus } from "../types/CommonTypes.sol";

/// @title LinglongSlasher
/// @notice Implementation of the ILinglongSlasher interface that bridges between URC's slashing system
/// and EigenLayer's slashing mechanisms. This contract receives slashing requests from the URC
/// Registry, routes them to appropriate challenger contracts (interactive or non-interactive),
/// and upon successful challenge, calls EigenLayer's AllocationManager to slash operators.
contract LinglongSlasher is Initializable, OwnableUpgradeable, LinglongSlasherStorage {
    using ECDSA for bytes32;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using OperatorSubsetLib for uint96;

    /// @dev Modifier to check that the contract is properly initialized
    modifier onlyInitialized() {
        if (ALLOCATION_MANAGER == address(0)) revert NotInitialized();
        _;
    }

    /// @dev Modifier to check that the contract is only URC
    modifier onlyURC() {
        if (msg.sender != REGISTRY_ADDRESS) revert NotURC();
        _;
    }

    error SlashingInProgress();
    error NotURC();

    /// @notice Constructor - disabled for upgradeable pattern
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract (replaces constructor for upgradeable pattern)
    /// @param _initialOwner The initial contract owner
    /// @param _allocationManager The address of the allocation manager
    /// @param _registryAddress The address of the URC Registry
    function initialize(
        address _initialOwner,
        address _allocationManager,
        address _registryAddress
    )
        external
        initializer
    {
        __Ownable_init(_initialOwner);
        ALLOCATION_MANAGER = _allocationManager;
        REGISTRY_ADDRESS = _registryAddress;
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
    function setSymbioticMiddleware(address _symbioticMiddleware)
        external
        override
        onlyOwner
    {
        SYMBIOTIC_MIDDLEWARE = _symbioticMiddleware;
    }

    /// @notice Sets the TaiyiRegistryCoordinator address
    /// @param _registryCoordinator The address of the TaiyiRegistryCoordinator
    function setTaiyiRegistryCoordinator(address _registryCoordinator)
        external
        onlyOwner
    {
        if (_registryCoordinator == address(0)) revert InvalidChallengerAddress();
        TAIYI_REGISTRY_COORDINATOR = _registryCoordinator;
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
        string memory name = ILinglongChallenger(challenger).getImplementationName();

        // Get supported violation types
        bytes32 supportedType =
            ILinglongChallenger(challenger).getSupportedViolationType();

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

    /// @dev Helper function to find middleware for an operator
    /// @param operator The operator address to look up
    /// @return middleware The middleware address if found. Returns 0 if not found
    function _findMiddleware(address operator)
        internal
        view
        returns (address middleware)
    {
        ITaiyiRegistryCoordinator.AllocatedOperatorSets memory operatorSets =
        ITaiyiRegistryCoordinator(TAIYI_REGISTRY_COORDINATOR)
            .getOperatorAllocatedOperatorSets(
            operator, ITaiyiRegistryCoordinator.RestakingProtocol.EIGENLAYER
        );

        if (operatorSets.eigenLayerSets.length > 0) {
            return EIGENLAYER_MIDDLEWARE;
        }

        operatorSets = ITaiyiRegistryCoordinator(TAIYI_REGISTRY_COORDINATOR)
            .getOperatorAllocatedOperatorSets(
            operator, ITaiyiRegistryCoordinator.RestakingProtocol.SYMBIOTIC
        );

        if (operatorSets.symbioticSets.length > 0) {
            return SYMBIOTIC_MIDDLEWARE;
        }

        return address(0);
    }

    /// @dev Helper function to execute slashing based on protocol
    /// @param operator The operator to slash
    /// @param middleware The middleware address
    /// @param challengerContract The challenger contract address
    /// @param payload The commitment payload
    /// @param protocol The protocol type
    /// @return executed Whether slashing was executed
    function _executeSlashingByProtocol(
        address operator,
        address middleware,
        address challengerContract,
        bytes memory payload,
        ITaiyiRegistryCoordinator.RestakingProtocol protocol
    )
        internal
        returns (bool executed)
    {
        if (protocol == ITaiyiRegistryCoordinator.RestakingProtocol.SYMBIOTIC) {
            executed = _verifyProofAndInitiateSymbioticSlashing(
                operator, middleware, challengerContract, payload
            );
        } else {
            executed = _verifyProofAndInitiateEigenLayerSlashing(
                operator, middleware, challengerContract, payload
            );
        }
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
        onlyURC
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

        // Find the middleware address for this operator
        address middleware = _findMiddleware(operator);
        if (middleware == address(0)) {
            revert OperatorNotInSet(operator, 0);
        }

        // Check which protocol the middleware belongs to
        ITaiyiRegistryCoordinator.RestakingProtocol protocol = ITaiyiRegistryCoordinator(
            TAIYI_REGISTRY_COORDINATOR
        ).getMiddlewareProtocol(middleware);

        // Execute slashing based on protocol
        bool executed = _executeSlashingByProtocol(
            operator, middleware, challengerContract, commitment.payload, protocol
        );

        // If direct execution is requested, execute the slashing
        if (executed) {
            slashedCommitments[commitmentHash] = true;
            emit SlashingResult(operator, true);
        }

        // Always return 0 for slashAmountGwei
        // This is because collateral management is handled by EigenLayer/Symbiotic
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

    /// @dev Verify the proof for a challenger contract
    /// @param challengerContract The challenger contract address
    /// @param payload The payload to verify
    /// @return status The verification status
    function _verifyChallenger(
        address challengerContract,
        bytes memory payload
    )
        internal
        returns (VerificationStatus)
    {
        // Decode the original payload for verification
        (bytes memory decodedPayload) = abi.decode(payload, (bytes));

        // Verify the proof
        return ILinglongChallenger(challengerContract).verifyProof(decodedPayload);
    }

    /// @dev Check if slashing is already in progress
    /// @param operator The operator address
    /// @param operatorSetId The operator set ID
    /// @param challengerContract The challenger contract address
    /// @return notInProgress True if slashing is not already in progress
    function _checkSlashingNotInProgress(
        address operator,
        uint96 operatorSetId,
        address challengerContract
    )
        internal
        view
        returns (bool notInProgress)
    {
        bool isInstantSlashing =
            ILinglongChallenger(challengerContract).isInstantSlashing();

        if (isInstantSlashing) {
            return true;
        }

        (bool inProgress,) =
            this.isSlashingInProgress(operator, operatorSetId, challengerContract);

        return !inProgress;
    }

    /// @dev Verify the proof and initiate EigenLayer slashing if needed
    /// @param operator The operator to slash
    /// @param middleware The middleware address (EigenLayer)
    /// @param challengerContract The challenger contract address
    /// @param payload The commitment payload
    /// @return executed Whether slashing was executed
    function _verifyProofAndInitiateEigenLayerSlashing(
        address operator,
        address middleware,
        address challengerContract,
        bytes memory payload
    )
        internal
        returns (bool)
    {
        // First verify the proof
        VerificationStatus status = _verifyChallenger(challengerContract, payload);

        if (status != VerificationStatus.Verified) {
            revert ProofVerificationFailed();
        }

        // Get operator set ID for preparing params
        uint32 operatorSetId;
        OperatorSet[] memory eigenLayerSets =
            IAllocationManager(ALLOCATION_MANAGER).getAllocatedSets(operator);
        for (uint256 i = 0; i < eigenLayerSets.length; i++) {
            if (eigenLayerSets[i].avs == middleware) {
                operatorSetId = eigenLayerSets[i].id;
                break;
            }
        }

        // Check if slashing is already in progress
        if (
            !_checkSlashingNotInProgress(
                operator, uint96(operatorSetId), challengerContract
            )
        ) {
            revert SlashingInProgress();
        }

        // Prepare slashing parameters for EigenLayer
        IAllocationManagerTypes.SlashingParams memory params =
        _prepareEigenLayerSlashingParams(
            operator,
            middleware,
            operatorSetId,
            ILinglongChallenger(challengerContract).getSlashAmount(),
            string(
                abi.encodePacked("URC slash: ", challengerImpls[challengerContract].name)
            )
        );

        // Call the middleware contract to execute the slashing
        if (!IEigenLayerMiddleware(middleware).executeSlashing(params)) {
            revert AllocationManagerCallFailed();
        }

        return true;
    }

    /// @dev Verify the proof and initiate Symbiotic slashing if needed
    /// @param operator The operator to slash
    /// @param middleware The middleware address (Symbiotic)
    /// @param challengerContract The challenger contract address
    /// @param payload The commitment payload
    /// @return executed Whether slashing was executed
    function _verifyProofAndInitiateSymbioticSlashing(
        address operator,
        address middleware,
        address challengerContract,
        bytes memory payload
    )
        internal
        returns (bool)
    {
        // First verify the proof
        VerificationStatus status = _verifyChallenger(challengerContract, payload);

        if (status != VerificationStatus.Verified) {
            revert ProofVerificationFailed();
        }

        uint96 subnetwork;
        uint96[] memory subnetworks = ISymbioticNetworkMiddleware(SYMBIOTIC_MIDDLEWARE)
            .getOperatorAllocatedSubnetworks(operator);

        for (uint256 i = 0; i < subnetworks.length; i++) {
            (, uint96 baseId) = subnetworks[i].decodeOperatorSetId96();
            if (
                ITaiyiRegistryCoordinator(TAIYI_REGISTRY_COORDINATOR)
                    .getSymbioticOperatorFromOperatorSet(baseId, operator)
            ) {
                subnetwork = subnetworks[i];
                break;
            }
        }

        // Check if slashing is already in progress
        if (!_checkSlashingNotInProgress(operator, subnetwork, challengerContract)) {
            revert SlashingInProgress();
        }

        // Prepare slashing parameters for Symbiotic
        uint256 slashAmount = ILinglongChallenger(challengerContract).getSlashAmount();

        // For Symbiotic, we call the slash function directly on the middleware
        (bool success,) = middleware.call(
            abi.encodeWithSignature(
                "slash((uint48,bytes,uint256,bytes32,bytes[]))",
                _prepareSymbioticSlashParams(
                    operator,
                    subnetwork,
                    slashAmount,
                    string(
                        abi.encodePacked(
                            "URC slash: ", challengerImpls[challengerContract].name
                        )
                    )
                )
            )
        );

        if (!success) revert SlasherCallFailed();

        // Always execute directly for Symbiotic
        return true;
    }

    /// @dev Get allocated strategies for an operator
    /// @param operator The operator address
    /// @param middleware The middleware address
    /// @param operatorSetId The operator set ID
    /// @return strategies Array of allocated strategies
    function _getAllocatedStrategies(
        address operator,
        address middleware,
        uint32 operatorSetId
    )
        internal
        view
        returns (IStrategy[] memory strategies)
    {
        OperatorSet memory opSet = OperatorSet({ avs: middleware, id: operatorSetId });
        return
            IAllocationManager(ALLOCATION_MANAGER).getAllocatedStrategies(operator, opSet);
    }

    /// @dev Create wads to slash based on strategies length and amount
    /// @param strategiesLength The length of the strategies array
    /// @param slashAmount The amount to slash
    /// @return wadsToSlash Array of amounts to slash
    function _createWadsToSlash(
        uint256 strategiesLength,
        uint256 slashAmount
    )
        internal
        pure
        returns (uint256[] memory wadsToSlash)
    {
        wadsToSlash = new uint256[](strategiesLength);
        for (uint256 i = 0; i < strategiesLength; i++) {
            wadsToSlash[i] = slashAmount;
        }
        return wadsToSlash;
    }

    /// @dev Prepare slashing parameters for EigenLayer
    /// @param operator The operator to slash
    /// @param middleware The middleware address
    /// @param operatorSetId The operator set ID
    /// @param slashAmount The amount to slash
    /// @param description Description of the slashing
    /// @return params The slashing parameters
    function _prepareEigenLayerSlashingParams(
        address operator,
        address middleware,
        uint32 operatorSetId,
        uint256 slashAmount,
        string memory description
    )
        internal
        view
        returns (IAllocationManagerTypes.SlashingParams memory)
    {
        // Get allocated strategies
        IStrategy[] memory strategies =
            _getAllocatedStrategies(operator, middleware, operatorSetId);

        // Create wads to slash array
        uint256[] memory wadsToSlash = _createWadsToSlash(strategies.length, slashAmount);

        // Construct and return the SlashingParams
        return IAllocationManagerTypes.SlashingParams({
            operator: operator,
            operatorSetId: operatorSetId,
            strategies: strategies,
            wadsToSlash: wadsToSlash,
            description: description
        });
    }

    /// @dev Prepare slashing parameters for Symbiotic
    /// @param operator The operator to slash
    /// @param subnetwork The subnetwork ID
    /// @param slashAmount The amount to slash
    /// @param description Description of the slashing
    /// @return params The slash parameters
    function _prepareSymbioticSlashParams(
        address operator,
        uint96 subnetwork,
        uint256 slashAmount,
        string memory description
    )
        internal
        view
        returns (ISymbioticNetworkMiddleware.SlashParams memory params)
    {
        // Create empty slash hints array
        bytes[] memory slashHints = new bytes[](0);

        // Return the constructed SlashParams
        return ISymbioticNetworkMiddleware.SlashParams({
            timestamp: uint48(block.timestamp),
            key: abi.encode(operator), // Using operator address as the key
            amount: slashAmount,
            subnetwork: subnetwork,
            slashHints: slashHints
        });
    }

    /// @inheritdoc ILinglongSlasher
    function isSlashingInProgress(
        address operator,
        uint96 operatorSetId,
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
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IERC20 } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts-v4.9.0/contracts/token/ERC20/IERC20.sol";
import { Math } from "@openzeppelin-contracts/contracts/utils/math/Math.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { EnumerableMapLib } from "@solady/utils/EnumerableMapLib.sol";

import { IEigenLayerMiddleware } from "../interfaces/IEigenLayerMiddleware.sol";
import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import {
    IRewardsCoordinator,
    IRewardsCoordinatorTypes
} from "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";

import { BLS } from "@urc/lib/BLS.sol";

/**
 * @title EigenLayerRewardsHandler
 * @author Taiyi team
 * @notice Helper contract for handling rewards distribution logic for EigenLayer AVS
 * @dev This contract manages the distribution of rewards to both underwriters and validators
 *      based on specific allocation strategies
 */
contract EigenLayerRewardsHandler {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMapLib for EnumerableMapLib.Uint256ToBytes32Map;

    // ========= EVENTS =========

    /**
     * @notice Emitted when underwriter rewards are processed
     * @param token The reward token address
     * @param totalAmount The total amount of rewards
     * @param underwriterAmount The amount allocated to underwriters
     * @param validatorAmount The amount allocated to validators
     */
    event UnderwriterRewardsProcessed(
        address indexed token,
        uint256 totalAmount,
        uint256 underwriterAmount,
        uint256 validatorAmount
    );

    /**
     * @notice Emitted when validator rewards are processed
     * @param token The reward token address
     * @param validatorAmount The total amount distributed to validators
     * @param validatorCount The total number of validators receiving rewards
     */
    event ValidatorRewardsProcessed(
        address indexed token, uint256 validatorAmount, uint256 validatorCount
    );

    // ========= ERRORS =========

    /**
     * @notice Error thrown when the token transfer fails
     */
    error TokenTransferFailed();

    /**
     * @notice Error thrown when no underwriter operators are found
     */
    error NoUnderwriterOperators();

    /**
     * @notice Error thrown when the reward per operator is zero
     */
    error ZeroRewardPerOperator();

    /**
     * @notice Error thrown when no validators are registered
     */
    error NoValidatorsRegistered();

    /**
     * @notice Error thrown when an operator has no validators
     */
    error OperatorHasNoValidators();

    /**
     * @notice Error thrown when an operator's reward share is zero
     */
    error ZeroOperatorShare();

    // ========= STATE VARIABLES =========

    /**
     * @notice EigenLayer middleware contract reference
     */
    IEigenLayerMiddleware public immutable middleware;

    // ========= CONSTRUCTOR =========

    /**
     * @notice Constructor sets the middleware contract
     * @param _middleware Address of the EigenLayerMiddleware contract
     */
    constructor(address _middleware) {
        middleware = IEigenLayerMiddleware(_middleware);
    }

    // ========= EXTERNAL FUNCTIONS =========

    /**
     * @notice Returns the reward initiator address from the middleware contract
     * @return Address of the reward initiator
     */
    function getRewardInitiator() external view returns (address) {
        return middleware.getRewardInitiator();
    }

    /**
     * @notice Handle the underwriter rewards submission
     * @param submission The rewards submission data
     * @return validatorAmount The amount allocated for validators
     */
    function handleUnderwriterSubmission(
        IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission calldata submission
    )
        external
        returns (uint256 validatorAmount)
    {
        // Calculate total underwriter amount
        uint256 totalAmount = _calculateTotalAmount(submission.operatorRewards);

        // Transfer tokens from reward initiator to this contract
        if (!submission.token.transferFrom(msg.sender, address(this), totalAmount)) {
            revert TokenTransferFailed();
        }

        // Split the reward into underwriter and validator portions
        uint256 underwriterAmount = _calculateUnderwriterAmount(totalAmount);
        validatorAmount = totalAmount - underwriterAmount;

        // Get underwriter operators and total staked amount
        address[] memory underwriterOperators =
            middleware.getRegistryCoordinator().getOperatorSetOperators(uint32(0));

        if (underwriterOperators.length == 0) {
            revert NoUnderwriterOperators();
        }

        // Distribute rewards evenly among underwriters
        IRewardsCoordinator.OperatorReward[] memory opRewards =
            _distributeUnderwriterRewards(underwriterOperators, underwriterAmount);

        // Create final submission for underwriters
        IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission[] memory
            underwriterSubmissions =
                _createUnderwriterSubmission(submission, opRewards);

        // Approve RewardsCoordinator to spend the underwriter portion
        submission.token.approve(
            address(middleware.getRewardsCoordinator()), underwriterAmount
        );

        // Create the rewards submission
        middleware.getRewardsCoordinator().createOperatorDirectedAVSRewardsSubmission(
            address(this), underwriterSubmissions
        );

        emit UnderwriterRewardsProcessed(
            address(submission.token), totalAmount, underwriterAmount, validatorAmount
        );

        return validatorAmount;
    }

    /**
     * @notice Handle the validator rewards submission
     * @param submission The rewards submission data
     * @param validatorAmount The amount to distribute to validators
     */
    function handleValidatorRewards(
        IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission calldata submission,
        uint256 validatorAmount
    )
        external
    {
        // Get validator operators for this AVS
        address[] memory operators =
            middleware.getRegistryCoordinator().getOperatorSetOperators(uint32(1));

        if (operators.length == 0) {
            revert NoUnderwriterOperators();
        }

        // Count validators per operator and total validators
        (uint256 totalValidatorCount, uint256[] memory validatorsPerOperator) =
            _countValidators(operators);

        if (totalValidatorCount == 0) {
            revert NoValidatorsRegistered();
        }

        // Build array of proportional operator rewards
        IRewardsCoordinatorTypes.OperatorReward[] memory opRewards =
        _calculateValidatorRewards(
            operators, validatorsPerOperator, totalValidatorCount, validatorAmount
        );

        // Create validator submission
        IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission[] memory
            validatorSubmissions = _createValidatorSubmission(submission, opRewards);

        // Approve RewardsCoordinator to spend the validator portion
        submission.token.approve(
            address(middleware.getRewardsCoordinator()), validatorAmount
        );

        // Submit validator rewards
        middleware.getRewardsCoordinator().createOperatorDirectedAVSRewardsSubmission(
            address(this), validatorSubmissions
        );

        emit ValidatorRewardsProcessed(
            address(submission.token), validatorAmount, totalValidatorCount
        );
    }

    // ========= INTERNAL FUNCTIONS =========

    /**
     * @notice Calculate the total amount from operator rewards
     * @param operatorRewards Array of operator rewards
     * @return totalAmount The sum of all operator rewards
     */
    function _calculateTotalAmount(
        IRewardsCoordinatorTypes.OperatorReward[] calldata operatorRewards
    )
        internal
        pure
        returns (uint256 totalAmount)
    {
        for (uint256 i = 0; i < operatorRewards.length; i++) {
            totalAmount += operatorRewards[i].amount;
        }
        return totalAmount;
    }

    /**
     * @notice Calculate the underwriter portion of rewards
     * @param totalAmount Total reward amount
     * @return underwriterAmount Amount allocated to underwriters
     */
    function _calculateUnderwriterAmount(uint256 totalAmount)
        internal
        view
        returns (uint256 underwriterAmount)
    {
        return Math.mulDiv(totalAmount, middleware.getUnderwriterShareBips(), 10_000);
    }

    /**
     * @notice Distribute rewards evenly among underwriters
     * @param underwriterOperators Array of underwriter addresses
     * @param underwriterAmount Total amount for underwriters
     * @return opRewards Array of operator rewards
     */
    function _distributeUnderwriterRewards(
        address[] memory underwriterOperators,
        uint256 underwriterAmount
    )
        internal
        pure
        returns (IRewardsCoordinatorTypes.OperatorReward[] memory opRewards)
    {
        uint256 numOperators = underwriterOperators.length;
        uint256 baseShare = underwriterAmount / numOperators;
        uint256 leftover = underwriterAmount % numOperators;

        if (baseShare == 0) {
            revert ZeroRewardPerOperator();
        }

        opRewards = new IRewardsCoordinatorTypes.OperatorReward[](numOperators);

        // Assign each operator a baseShare, plus one extra token until leftover is exhausted
        for (uint256 i = 0; i < numOperators; i++) {
            uint256 share = baseShare;
            if (i < leftover) {
                // Give one extra token to the first 'leftover' operators
                share += 1;
            }
            opRewards[i] = IRewardsCoordinatorTypes.OperatorReward({
                operator: underwriterOperators[i],
                amount: share
            });
        }

        return opRewards;
    }

    /**
     * @notice Create underwriter rewards submission
     * @param submission Original submission parameters
     * @param opRewards Operator rewards array
     * @return underwriterSubmissions Array with single submission entry
     */
    function _createUnderwriterSubmission(
        IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission calldata submission,
        IRewardsCoordinatorTypes.OperatorReward[] memory opRewards
    )
        internal
        pure
        returns (IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission[] memory)
    {
        IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission[] memory
            underwriterSubmissions =
                new IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission[](1);

        underwriterSubmissions[0] = IRewardsCoordinatorTypes
            .OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: submission.strategiesAndMultipliers,
            token: submission.token,
            operatorRewards: opRewards,
            startTimestamp: submission.startTimestamp,
            duration: submission.duration,
            description: string(
                abi.encodePacked(submission.description, " (Underwriter portion)")
            )
        });

        return underwriterSubmissions;
    }

    /**
     * @notice Count validators per operator and total validators
     * @param operators Array of operator addresses
     * @return totalValidatorCount Total number of validators
     * @return validatorsPerOperator Array of validator counts per operator
     */
    function _countValidators(address[] memory operators)
        internal
        view
        returns (uint256 totalValidatorCount, uint256[] memory validatorsPerOperator)
    {
        validatorsPerOperator = new uint256[](operators.length);

        for (uint256 i = 0; i < operators.length; i++) {
            bytes32 registrationRoot = getActiveRegistrationRoot(operators[i]);
            (BLS.G1Point[] memory pubkeys,) =
                middleware.getAllDelegations(operators[i], registrationRoot);

            uint256 opValidatorCount = pubkeys.length;
            validatorsPerOperator[i] = opValidatorCount;
            totalValidatorCount += opValidatorCount;
        }

        return (totalValidatorCount, validatorsPerOperator);
    }

    /**
     * @notice Calculate validator rewards based on validator count per operator
     * @param operators Array of operator addresses
     * @param validatorsPerOperator Array of validator counts per operator
     * @param totalValidatorCount Total number of validators
     * @param validatorAmount Total amount for validators
     * @return opRewards Array of operator rewards
     */
    function _calculateValidatorRewards(
        address[] memory operators,
        uint256[] memory validatorsPerOperator,
        uint256 totalValidatorCount,
        uint256 validatorAmount
    )
        internal
        pure
        returns (IRewardsCoordinatorTypes.OperatorReward[] memory opRewards)
    {
        opRewards = new IRewardsCoordinatorTypes.OperatorReward[](operators.length);

        for (uint256 i = 0; i < operators.length; i++) {
            uint256 opValidatorCount = validatorsPerOperator[i];

            if (opValidatorCount == 0) {
                revert OperatorHasNoValidators();
            }

            // Share of the total validatorAmount = amount * (opCount/totalCount)
            uint256 share = (validatorAmount * opValidatorCount) / totalValidatorCount;

            if (share == 0) {
                revert ZeroOperatorShare();
            }

            opRewards[i] = IRewardsCoordinatorTypes.OperatorReward({
                operator: operators[i],
                amount: share
            });
        }

        return opRewards;
    }

    /**
     * @notice Create validator rewards submission
     * @param submission Original submission parameters
     * @param opRewards Operator rewards array
     * @return validatorSubmissions Array with single submission entry
     */
    function _createValidatorSubmission(
        IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission calldata submission,
        IRewardsCoordinatorTypes.OperatorReward[] memory opRewards
    )
        internal
        pure
        returns (IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission[] memory)
    {
        IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission[] memory
            validatorSubmissions =
                new IRewardsCoordinatorTypes.OperatorDirectedRewardsSubmission[](1);

        validatorSubmissions[0] = IRewardsCoordinatorTypes
            .OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: submission.strategiesAndMultipliers,
            token: submission.token,
            operatorRewards: opRewards,
            startTimestamp: submission.startTimestamp,
            duration: submission.duration,
            description: string(
                abi.encodePacked(submission.description, " (Validator portion)")
            )
        });

        return validatorSubmissions;
    }

    /**
     * @notice Helper to get an operator's active registration root
     * @param operator The operator address
     * @return The active registration root
     */
    function getActiveRegistrationRoot(address operator) public view returns (bytes32) {
        // Get all registration roots for this operator
        bytes32[] memory roots = middleware.getOperatorRegistrationRoots(operator);
        if (roots.length == 0) {
            return bytes32(0);
        }

        // For simplicity, return the first registration root
        // In a production system, you might want to implement more sophisticated logic
        // to determine which registration root is "active"
        return roots[0];
    }
}

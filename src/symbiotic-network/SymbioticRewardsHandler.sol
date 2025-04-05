// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IERC20 } from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { Math } from "@openzeppelin-contracts/contracts/utils/math/Math.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { EnumerableMapLib } from "@solady/utils/EnumerableMapLib.sol";

import { ISymbioticNetworkMiddleware } from
    "../interfaces/ISymbioticNetworkMiddleware.sol";
import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";

/**
 * @title SymbioticRewardsHandler
 * @author Taiyi team
 * @notice Helper contract for handling rewards distribution logic for Symbiotic restaking
 * @dev This contract manages the distribution of rewards to both underwriters and validators
 *      based on specific allocation strategies for the Symbiotic network
 */
contract SymbioticRewardsHandler {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMapLib for EnumerableMapLib.Uint256ToBytes32Map;

    // ========= EVENTS =========

    /// @notice Emitted when rewards are processed for a subnetwork
    /// @param token The reward token address
    /// @param totalAmount The total amount of rewards
    /// @param subnetworkId The ID of the subnetwork
    event SubnetworkRewardsProcessed(
        address indexed token, uint256 totalAmount, uint96 subnetworkId
    );

    /// @notice Emitted when an operator receives rewards
    /// @param token The reward token address
    /// @param operator The operator address
    /// @param amount The amount of rewards
    /// @param subnetworkId The ID of the subnetwork
    event OperatorRewardDistributed(
        address indexed token,
        address indexed operator,
        uint256 amount,
        uint96 subnetworkId
    );

    // ========= ERRORS =========

    /// @notice Error thrown when the token transfer fails
    error TokenTransferFailed();

    /// @notice Error thrown when no operators are registered
    error NoOperatorsRegistered();

    /// @notice Error thrown when the reward per operator is zero
    error ZeroRewardPerOperator();

    /// @notice Error thrown when an operator has no stake
    error OperatorHasNoStake();

    // ========= STATE VARIABLES =========

    /// @notice Symbiotic middleware contract reference
    ISymbioticNetworkMiddleware public immutable middleware;

    // ========= CONSTRUCTOR =========

    /// @notice Constructor sets the middleware contract
    /// @param _middleware Address of the SymbioticNetworkMiddleware contract
    constructor(address _middleware) {
        middleware = ISymbioticNetworkMiddleware(_middleware);
    }

    // ========= EXTERNAL FUNCTIONS =========

    /// @notice Handle rewards distribution for a subnetwork
    /// @param token The token in which rewards are distributed
    /// @param amount The total amount to distribute
    /// @param subnetworkId The ID of the subnetwork (validator or underwriter)
    /// @return success Whether the distribution was successful
    function distributeRewards(
        address token,
        uint256 amount,
        uint96 subnetworkId
    )
        external
        returns (bool success)
    {
        // Transfer tokens from reward initiator to this contract
        if (!IERC20(token).transferFrom(msg.sender, address(this), amount)) {
            revert TokenTransferFailed();
        }

        // Get operators in the subnetwork
        ITaiyiRegistryCoordinator registryCoordinator =
            middleware.getRegistryCoordinator();
        address[] memory operators =
            registryCoordinator.getOperatorSetOperators(uint32(subnetworkId));

        if (operators.length == 0) {
            revert NoOperatorsRegistered();
        }

        // Get all operator stakes and calculate total stake
        (
            address[] memory vaults,
            address[] memory collateralTokens,
            uint256[] memory stakedAmounts
        ) = _getOperatorsStakeInformation(operators);

        uint256 totalStake = 0;
        for (uint256 i = 0; i < stakedAmounts.length; i++) {
            totalStake += stakedAmounts[i];
        }

        if (totalStake == 0) {
            revert ZeroRewardPerOperator();
        }

        // Distribute rewards proportionally based on stake
        uint256 remainingAmount = amount;

        for (uint256 i = 0; i < operators.length; i++) {
            // Calculate proportional share of rewards
            uint256 operatorReward;

            if (i == operators.length - 1) {
                // Last operator gets remaining rewards to handle rounding errors
                operatorReward = remainingAmount;
            } else {
                operatorReward = Math.mulDiv(amount, stakedAmounts[i], totalStake);
                remainingAmount -= operatorReward;
            }

            if (operatorReward > 0) {
                // Transfer rewards to the operator
                if (!IERC20(token).transfer(operators[i], operatorReward)) {
                    revert TokenTransferFailed();
                }

                emit OperatorRewardDistributed(
                    token, operators[i], operatorReward, subnetworkId
                );
            }
        }

        emit SubnetworkRewardsProcessed(token, amount, subnetworkId);
        return true;
    }

    // ========= INTERNAL FUNCTIONS =========

    /// @notice Get stake information for all operators
    /// @param operators Array of operator addresses
    /// @return vaults Array of vault addresses
    /// @return collateralTokens Array of collateral token addresses
    /// @return stakedAmounts Array of staked amounts
    function _getOperatorsStakeInformation(address[] memory operators)
        internal
        view
        returns (
            address[] memory vaults,
            address[] memory collateralTokens,
            uint256[] memory stakedAmounts
        )
    {
        uint256 totalOperators = operators.length;
        vaults = new address[](totalOperators);
        collateralTokens = new address[](totalOperators);
        stakedAmounts = new uint256[](totalOperators);

        for (uint256 i = 0; i < totalOperators; i++) {
            (
                address[] memory operatorVaults,
                address[] memory operatorCollateralTokens,
                uint256[] memory operatorStakedAmounts
            ) = middleware.getOperatorCollaterals(operators[i]);

            // Sum up all collateral for this operator
            uint256 totalStake = 0;
            for (uint256 j = 0; j < operatorStakedAmounts.length; j++) {
                totalStake += operatorStakedAmounts[j];
            }

            if (operatorVaults.length > 0) {
                vaults[i] = operatorVaults[0];
                collateralTokens[i] = operatorCollateralTokens[0];
            }

            stakedAmounts[i] = totalStake;
        }

        return (vaults, collateralTokens, stakedAmounts);
    }
}

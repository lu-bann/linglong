// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ISymbioticNetworkMiddleware } from "./ISymbioticNetworkMiddleware.sol";

/// @title ISymbioticRewardsHandler
/// @author Luban team
/// @notice Interface for the SymbioticRewardsHandler contract
/// @dev Defines the contract interface for handling rewards distribution logic for Symbiotic restaking
interface ISymbioticRewardsHandler {
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

    // ========= FUNCTIONS =========

    /// @notice Get the middleware contract address
    /// @return The address of the SymbioticNetworkMiddleware contract
    function middleware() external view returns (ISymbioticNetworkMiddleware);
}

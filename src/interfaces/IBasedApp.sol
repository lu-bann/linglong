// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IBasedAppManager } from "./IBasedAppManager.sol";

/// @title IBasedApp
/// @notice SSV IBasedApp interface (compatible with Solidity 0.8.27)
/// @dev Based on: https://github.com/ssvlabs/based-applications/blob/main/src/middleware/interfaces/IBasedApp.sol
/// Note: Due to version incompatibility (SSV uses 0.8.30, we use 0.8.27), we recreate the interface
interface IBasedApp {
    /// @notice Registers the bApp with SSV network
    /// @param tokenConfigs Array of token configurations for the bApp
    /// @param metadataURI Metadata URI for the bApp
    function registerBApp(
        IBasedAppManager.TokenConfig[] calldata tokenConfigs,
        string calldata metadataURI
    )
        external;

    /// @notice Allows operators to opt into the bApp with specific strategies
    /// @param strategyId The strategy ID to opt into
    /// @param tokens Array of token addresses
    /// @param obligationPercentages Array of obligation percentages for each token
    /// @param data Additional data for the opt-in process
    /// @return success Whether the opt-in was successful
    function optInToBApp(
        uint32 strategyId,
        address[] calldata tokens,
        uint32[] calldata obligationPercentages,
        bytes calldata data
    )
        external
        returns (bool success);

    /// @notice Handles slashing for validators
    /// @param strategyId The strategy ID being slashed
    /// @param token The token being slashed
    /// @param percentage The slashing percentage
    /// @param sender The address initiating the slash
    /// @param data Additional slashing data
    /// @return success Whether the slash was successful
    /// @return receiver The address receiving slashed funds
    /// @return exit Whether the validator should exit
    function slash(
        uint32 strategyId,
        address token,
        uint32 percentage,
        address sender,
        bytes calldata data
    )
        external
        returns (bool success, address receiver, bool exit);

    /// @notice Updates the metadata URI for the bApp
    /// @param metadataURI New metadata URI
    function updateBAppMetadataURI(string calldata metadataURI) external;

    /// @notice Updates the token configurations for the bApp
    /// @param tokenConfigs New token configurations
    function updateBAppTokens(IBasedAppManager.TokenConfig[] calldata tokenConfigs)
        external;

    /// @notice Error thrown when an unauthorized caller attempts to access a restricted function
    error UnauthorizedCaller();
}

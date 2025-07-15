// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

/// @title IBasedAppManager
/// @notice SSV IBasedAppManager interface (compatible with Solidity 0.8.27)
/// @dev Based on: https://github.com/ssvlabs/based-applications/blob/main/src/core/interfaces/IBasedAppManager.sol
/// Note: Due to version incompatibility (SSV uses 0.8.30, we use 0.8.27), we recreate the interface
interface IBasedAppManager {
    /// @notice Token configuration struct
    struct TokenConfig {
        address token;
        uint32 sharedRiskLevel;
    }

    event BAppMetadataURIUpdated(address indexed bApp, string metadataURI);
    event BAppRegistered(
        address indexed bApp, TokenConfig[] tokenConfigs, string metadataURI
    );
    event BAppTokensUpdated(address indexed bApp, TokenConfig[] tokenConfigs);

    function registerBApp(
        TokenConfig[] calldata tokenConfigs,
        string calldata metadataURI
    )
        external;
    function updateBAppMetadataURI(string calldata metadataURI) external;
    function updateBAppsTokens(TokenConfig[] calldata tokenConfigs) external;

    error BAppAlreadyRegistered();
    error BAppDoesNotSupportInterface();
    error BAppNotRegistered();
    error TokenAlreadyAddedToBApp(address token);
    error ZeroAddressNotAllowed();
}

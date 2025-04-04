// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITaiyiRegistryCoordinator } from "./ITaiyiRegistryCoordinator.sol";
import { BLS } from "@urc/lib/BLS.sol";
import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";

/**
 * @title ISymbioticNetworkMiddleware
 * @notice Interface for the SymbioticNetworkMiddleware contract that manages both gateway 
 * and validator networks in the Symbiotic ecosystem
 */
interface ISymbioticNetworkMiddleware {

    // ========= EVENTS =========

    /// @notice Emitted when a validator is registered
    /// @param operator The operator address
    /// @param registrationRoot The registration root
    event ValidatorRegistered(address indexed operator, bytes32 registrationRoot);

    /// @notice Emitted when a validator is unregistered
    /// @param operator The operator address
    /// @param registrationRoot The registration root
    event ValidatorUnregistered(address indexed operator, bytes32 registrationRoot);

    /// @notice Emitted when an operator is slashed
    /// @param operator The operator address
    /// @param subnetwork The subnetwork ID
    /// @param amount The amount slashed
    event OperatorSlashed(address indexed operator, uint96 indexed subnetwork, uint256 amount);

    // ========= ERRORS =========

    /// @notice Error thrown when an operator is not registered
    error OperatorNotRegistered();

    /// @notice Error thrown when an operator is already registered
    error OperatorAlreadyRegistered();

    /// @notice Error thrown when a registration operation fails
    error RegistrationFailed();

    /// @notice Error thrown when an invalid signature is provided
    error InvalidSignature();

    /// @notice Error thrown when no vaults are available to slash
    error NoVaultsToSlash();

    // ========= CONSTANTS =========

    /// @notice Subnetwork ID for validators
    function VALIDATOR_SUBNETWORK() external view returns (uint96);

    /// @notice Subnetwork ID for underwriters
    function UNDERWRITER_SUBNETWORK() external view returns (uint96);

    // ========= EXTERNAL FUNCTIONS =========

    /// @notice Register an operator with a key, vault, and subnetwork
    /// @param key The operator's key
    /// @param vault The vault address
    /// @param signature The signature proving ownership of the key
    /// @param subnetwork The subnetwork ID
    function registerOperator(
        bytes memory key,
        address vault,
        bytes memory signature,
        uint96 subnetwork
    ) external;

    /// @notice Register validators for an operator
    /// @param registrations Array of validator registrations
    /// @param delegationSignatures Array of delegation signatures
    /// @param delegateePubKey The delegatee's public key
    /// @param delegateeAddress The delegatee's address
    /// @param data Additional data for registration
    /// @return registrationRoot The registration root
    function registerValidators(
        IRegistry.Registration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata data
    ) external payable returns (bytes32 registrationRoot);

    /// @notice Unregister validators for an operator
    /// @param registrationRoot The registration root
    function unregisterValidators(bytes32 registrationRoot) external;

    /// @notice Set delegations for a registration root
    /// @param registrationRoot The registration root
    /// @param pubkeys Array of public keys
    /// @param delegations Array of signed delegations
    function batchSetDelegations(
        bytes32 registrationRoot,
        BLS.G1Point[] calldata pubkeys,
        ISlasher.SignedDelegation[] calldata delegations
    ) external;

    /// @notice Opt in to the slasher contract
    /// @param registrationRoot The registration root
    /// @param registrations Array of validator registrations
    /// @param delegationSignatures Array of delegation signatures
    /// @param delegateePubKey The delegatee's public key
    /// @param delegateeAddress The delegatee's address
    /// @param data Additional data for registration
    function optInToSlasher(
        bytes32 registrationRoot,
        IRegistry.Registration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata data
    ) external;

    /// @notice Slash an operator
    /// @param params The slash parameters
    function slash(SlashParams calldata params) external;

    /// @notice Get all registration roots for an operator
    /// @param operator The operator address
    /// @return Array of registration roots
    function getOperatorRegistrationRoots(address operator) external view returns (bytes32[] memory);

    /// @notice Get all delegations for an operator
    /// @param operator The operator address
    /// @param registrationRoot The registration root
    /// @return pubkeys Array of public keys
    /// @return delegations Array of signed delegations
    function getAllDelegations(
        address operator,
        bytes32 registrationRoot
    ) external view returns (
        BLS.G1Point[] memory pubkeys,
        ISlasher.SignedDelegation[] memory delegations
    );

    /// @notice Get collateral information for an operator
    /// @param operator The operator address
    /// @return vaults Array of vault addresses
    /// @return collateralTokens Array of collateral token addresses
    /// @return stakedAmounts Array of staked amounts
    function getOperatorCollaterals(address operator) external view returns (
        address[] memory vaults,
        address[] memory collateralTokens,
        uint256[] memory stakedAmounts
    );

    /// @notice Get the registry coordinator
    /// @return The registry coordinator
    function getRegistryCoordinator() external view returns (ITaiyiRegistryCoordinator);

    /// @notice Get the total power of a list of operators
    /// @param operators Array of operator addresses
    /// @return The total power
    function totalPower(address[] memory operators) external view returns (uint256);

    // ========= STRUCTS =========

    /// @notice Parameters for slashing an operator
    struct SlashParams {
        uint48 timestamp;
        bytes key;
        uint256 amount;
        bytes32 subnetwork;
        bytes[] slashHints;
    }
} 
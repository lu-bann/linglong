// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITaiyiRegistryCoordinator } from "./ITaiyiRegistryCoordinator.sol";

import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { BLS } from "@urc/lib/BLS.sol";

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
    event OperatorSlashed(
        address indexed operator, uint96 indexed subnetwork, uint256 amount
    );

    /// @notice Emit when rewards handler is set
    event RewardsHandlerSet(address rewardsHandler);

    // ========= ERRORS =========

    /// @notice Error thrown when an operator is already registered
    error OperatorAlreadyRegistered();

    /// @notice Error thrown when a registration operation fails
    error RegistrationFailed();

    /// @notice Error thrown when an invalid signature is provided
    error InvalidSignature();

    /// @notice Error thrown when no vaults are available to slash
    error NoVaultsToSlash();

    /// @notice Error when rewards handler is not set
    error RewardsHandlerNotSet();

    /// @notice Error when operator is not yet registered in validator operator set
    error OperatorIsNotYetRegisteredInValidatorOperatorSet();

    /// @notice Error for registration failures
    error RegistrationRootNotFound();
    error OperatorNotOwnerOfRegistrationRoot();
    error PubKeyNotFound();
    // Note: OperatorNotRegistered is already defined in BaseOperators
    error OperatorUnregistered();
    error OperatorFraudProofPeriodNotOver();

    /// @notice Error for slash failures
    error InactiveSubnetworkSlash();
    error InactiveKeySlash();
    error InactiveOperatorSlash();
    error OperatorIsNotYetRegisteredInUnderwriterOperatorSet();
    error SubnetworkNotActive();

    // ========= EXTERNAL FUNCTIONS =========

    /// @notice Register an operator with a key, vault, and subnetworks
    /// @param key The operator's key
    /// @param vault The vault address
    /// @param signature The signature proving ownership of the key
    /// @param subnetworks The subnetwork IDs
    function registerOperator(
        bytes memory key,
        address vault,
        bytes memory signature,
        uint96[] memory subnetworks
    )
        external;

    /// @notice Register validators for an operator
    /// @param registrations Array of validator registrations
    /// @param delegationSignatures Array of delegation signatures
    /// @param delegateePubKey The delegatee's public key
    /// @param delegateeAddress The delegatee's address
    /// @param data Additional data for registration
    /// @return registrationRoot The registration root
    function registerValidators(
        IRegistry.SignedRegistration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata data
    )
        external
        payable
        returns (bytes32 registrationRoot);

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
    )
        external;

    /// @notice Opt in to the slasher contract
    /// @param registrationRoot The registration root
    /// @param registrations Array of validator registrations
    /// @param delegationSignatures Array of delegation signatures
    /// @param delegateePubKey The delegatee's public key
    /// @param delegateeAddress The delegatee's address
    /// @param data Additional data for registration
    function optInToSlasher(
        bytes32 registrationRoot,
        IRegistry.SignedRegistration[] calldata registrations,
        BLS.G2Point[] calldata delegationSignatures,
        BLS.G1Point calldata delegateePubKey,
        address delegateeAddress,
        bytes[] calldata data
    )
        external;

    /// @notice Slash an operator
    /// @param params The slash parameters
    function slash(SlashParams calldata params) external;

    /// @notice Get all registration roots for an operator
    /// @param operator The operator address
    /// @return Array of registration roots
    function getOperatorRegistrationRoots(address operator)
        external
        view
        returns (bytes32[] memory);

    /// @notice Get all delegations for an operator
    /// @param operator The operator address
    /// @param registrationRoot The registration root
    /// @return pubkeys Array of public keys
    /// @return delegations Array of signed delegations
    function getAllDelegations(
        address operator,
        bytes32 registrationRoot
    )
        external
        view
        returns (
            BLS.G1Point[] memory pubkeys,
            ISlasher.SignedDelegation[] memory delegations
        );

    /// @notice Get collateral information for an operator
    /// @param operator The operator address
    /// @param subnetworkId The subnetwork ID
    /// @return vaults Array of vault addresses
    /// @return collateralTokens Array of collateral token addresses
    /// @return stakedAmounts Array of staked amounts
    function getOperatorCollaterals(
        address operator,
        uint96 subnetworkId
    )
        external
        view
        returns (
            address[] memory vaults,
            address[] memory collateralTokens,
            uint256[] memory stakedAmounts
        );

    /// @notice Get the registry coordinator
    /// @return The registry coordinator
    function getRegistryCoordinator() external view returns (ITaiyiRegistryCoordinator);

    /// @notice Get the number of subnetworks
    /// @return The number of subnetworks
    function getSubnetworkCount() external view returns (uint96);

    /// @notice Gets all subnetworks that have allocated stake to a specific operator
    /// @param operator The operator address to check
    /// @return allocatedSubnetworks Array of subnetwork IDs that have stake allocated to the operator
    function getOperatorAllocatedSubnetworks(address operator)
        external
        view
        returns (uint96[] memory allocatedSubnetworks);

    // ========= STRUCTS =========

    /// @notice Parameters for slashing an operator
    struct SlashParams {
        uint48 timestamp;
        bytes key;
        uint256 amount;
        uint96 subnetwork;
        bytes[] slashHints;
    }
}

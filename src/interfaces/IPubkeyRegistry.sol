// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import { BN254 } from "../libs/BN254.sol";

/// @title Interface for the PubkeyRegistry contract
/// @notice Manages BLS public key registration and verification for operators
interface IPubkeyRegistry {
    /// @notice Gets or registers an operator's ID
    /// @param operator The operator's address
    /// @param params The public key registration parameters
    /// @return operatorId The unique identifier for the operator
    function getOrRegisterOperatorId(
        address operator,
        PubkeyRegistrationParams calldata params
    )
        external
        returns (bytes32 operatorId);

    /// @notice Gets an operator's ID (pubkey hash)
    /// @param operator The operator's address
    /// @return The operator's ID
    function getOperatorId(address operator) external view returns (bytes32);

    /// @notice Gets an operator's address from an operator ID
    /// @param operatorId The operator's ID
    /// @return The operator's address
    function getOperatorFromId(bytes32 operatorId) external view returns (address);

    /// @notice Gets an operator's G2 public key
    /// @param operator The operator's address
    /// @return The operator's G2 public key
    function getOperatorPubkey(address operator) external view returns (bytes memory);

    /// @dev Struct for public key registration parameters
    /// @param pubkeyG1 The G1 public key
    /// @param pubkeyG2 The G2 public key
    /// @param pubkeyRegistrationSignature The signature proving ownership of the keys
    struct PubkeyRegistrationParams {
        bytes blsPubkey;
        address operator;
        bytes pubkeyRegistrationSignature;
    }

    /// @notice Error when trying to register a zero public key
    error ZeroPubKey();

    /// @notice Error when operator is already registered
    error OperatorAlreadyRegistered();

    /// @notice Error when BLS public key is already registered
    error BLSPubkeyAlreadyRegistered();

    /// @notice Error when operator is not registered
    error OperatorNotRegistered();

    /// @notice Error when BLS signature or private key is invalid
    error InvalidBLSSignatureOrPrivateKey();

    /// @notice Error when ECDSA signature is invalid
    error InvalidECDSASignature();

    /// @notice Error when G2 public key is already set
    error G2PubkeyAlreadySet();

    /// @notice Error when caller is not registry coordinator owner
    error OnlyRegistryCoordinatorOwner();

    /// @notice Error when caller is not the registry coordinator
    error OnlyRegistryCoordinator();

    /// @notice Emitted when a new public key is registered
    event NewPubkeyRegistration(address indexed operator, bytes blsPubkey);

    /// @notice Emitted when a new G2 public key is registered
    event NewG2PubkeyRegistration(address indexed operator, BN254.G2Point pubkeyG2);

    /// @notice Emitted when a new operator is registered
    event OperatorRegistered(address indexed operator, bytes32 operatorId);
}

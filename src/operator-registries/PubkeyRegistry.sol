// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IPubkeyRegistry } from "../interfaces/IPubkeyRegistry.sol";
import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { BN254 } from "../libs/BN254.sol";
import { PubkeyRegistryStorage } from "../storage/PubkeyRegistryStorage.sol";
import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";

contract PubkeyRegistry is PubkeyRegistryStorage, IPubkeyRegistry {
    using BN254 for BN254.G1Point;

    /// @notice when applied to a function, only allows the RegistryCoordinator to call it
    modifier onlyRegistryCoordinator() {
        _checkRegistryCoordinator();
        _;
    }

    /// @notice when applied to a function, only allows the RegistryCoordinator owner to call it
    modifier onlyRegistryCoordinatorOwner() {
        _checkRegistryCoordinatorOwner();
        _;
    }

    /// @notice Sets the (immutable) `registryCoordinator` address
    constructor(ITaiyiRegistryCoordinator _registryCoordinator)
        PubkeyRegistryStorage(_registryCoordinator)
    { }

    function splitSignature(bytes memory sig)
        public
        pure
        returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
    }

    function recoverSigner(
        bytes32 _ethSignedMessageHash,
        bytes memory _signature
    )
        public
        pure
        returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }
    // Todo: remove bypass in test mode
    /// @inheritdoc IPubkeyRegistry

    function registerBLSPublicKey(
        address operator,
        PubkeyRegistrationParams calldata params
    )
        public
        onlyRegistryCoordinator
        returns (bytes32 operatorId)
    {
        bytes32 pubkeyHash = keccak256(params.blsPubkey);
        require(pubkeyHash != ZERO_PK_HASH, ZeroPubKey());
        require(getOperatorId(operator) == bytes32(0), OperatorAlreadyRegistered());
        require(
            pubkeyHashToOperator[pubkeyHash] == address(0), BLSPubkeyAlreadyRegistered()
        );

        bytes32 messageHash =
            keccak256(abi.encodePacked(params.operator, params.blsPubkey));

        /// Verify ecdsa the signature
        require(
            recoverSigner(messageHash, params.pubkeyRegistrationSignature)
                == params.operator,
            InvalidECDSASignature()
        );

        pubkeyHashToPubkey[pubkeyHash] = params.blsPubkey;
        operatorToPubkeyHash[operator] = pubkeyHash;
        pubkeyHashToOperator[pubkeyHash] = operator;

        emit NewPubkeyRegistration(operator, params.blsPubkey);
        return pubkeyHash;
    }

    function getOrRegisterOperatorId(
        address operator,
        PubkeyRegistrationParams calldata params
    )
        external
        onlyRegistryCoordinator
        returns (bytes32 operatorId)
    {
        operatorId = getOperatorId(operator);
        if (operatorId == 0) {
            operatorId = registerBLSPublicKey(operator, params);
        }
        return operatorId;
    }

    /// @inheritdoc IPubkeyRegistry
    function getOperatorFromId(bytes32 operatorId) public view returns (address) {
        return pubkeyHashToOperator[operatorId];
    }

    /// @inheritdoc IPubkeyRegistry
    function getOperatorId(address operator) public view returns (bytes32) {
        return operatorToPubkeyHash[operator];
    }

    /// @inheritdoc IPubkeyRegistry
    function getOperatorPubkey(address operator)
        public
        view
        override
        returns (bytes memory)
    {
        return pubkeyHashToPubkey[getOperatorId(operator)];
    }

    function _checkRegistryCoordinator() internal view {
        require(msg.sender == address(registryCoordinator), OnlyRegistryCoordinator());
    }

    function _checkRegistryCoordinatorOwner() internal view {
        require(
            msg.sender == OwnableUpgradeable(address(registryCoordinator)).owner(),
            OnlyRegistryCoordinatorOwner()
        );
    }
}

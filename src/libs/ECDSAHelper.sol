// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "../types/PreconfRequestBTypes.sol";
import "./PreconfRequestLib.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title ECDSAHelper
 * @dev Library for verifying ECDSA signatures
 */
library ECDSAHelper {
    using PreconfRequestLib for PreconfRequestBType;

    /**
     * @dev Computes the hash of a signature
     * @param signature The signature to hash
     * @return The keccak256 hash of the signature
     */
    function hashSignature(bytes memory signature) internal pure returns (bytes32) {
        return keccak256(signature);
    }

    /**
     * @dev Verifies if a signature was signed by the expected signer
     * @param hashValue The hash that was signed
     * @param signer The expected signer address
     * @param signature The signature to verify
     * @param errorMessage Error message to revert with if verification fails
     */
    function verifySignature(
        bytes32 hashValue,
        address signer,
        bytes memory signature,
        string memory errorMessage
    )
        internal
        pure
    {
        address hash_signer = ECDSA.recover(hashValue, signature);
        require(hash_signer == signer, errorMessage);
    }

    /**
     * @dev Verifies if a signature was signed by the expected signer
     * @param hashValue The value to hash and then verify
     * @param signer The expected signer address
     * @param signature The signature to verify
     * @param errorMessage Error message to revert with if verification fails
     */
    function verifySignature(
        bytes memory hashValue,
        address signer,
        bytes memory signature,
        string memory errorMessage
    )
        internal
        pure
    {
        bytes32 hashValue32 = keccak256(hashValue);
        address hash_signer = ECDSA.recover(hashValue32, signature);
        require(hash_signer == signer, errorMessage);
    }
}

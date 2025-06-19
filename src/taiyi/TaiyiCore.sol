// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ITaiyiCore } from "../interfaces/ITaiyiCore.sol";
import { PreconfRequestLib } from "../libs/PreconfRequestLib.sol";
import { TaiyiCoreStorage } from "../storage/TaiyiCoreStorage.sol";
import { TaiyiEscrow } from "./TaiyiEscrow.sol";

import { SlotLib } from "../libs/SlotLib.sol";
import { PreconfRequestStatus } from "../types/CommonTypes.sol";
import {
    BlockspaceAllocation, PreconfRequestBType
} from "../types/PreconfRequestBTypes.sol";

import { ECDSALib } from "../libs/ECDSALib.sol";

import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { UUPSUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import { ECDSA } from "@openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import { SignatureChecker } from
    "@openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol";

contract TaiyiCore is
    OwnableUpgradeable,
    UUPSUpgradeable,
    ITaiyiCore,
    TaiyiEscrow,
    TaiyiCoreStorage
{
    using PreconfRequestLib for *;
    using SignatureChecker for address;
    using ECDSALib for bytes;

    ///////////////////////////////////////////////////////////////
    /// EVENTS
    ///////////////////////////////////////////////////////////////

    event Exhausted(address indexed preconfer, uint256 amount);
    event TipCollected(uint256 amount, bytes32 preconfRequestHash);
    event PreconfRequestExecuted(bytes32 indexed preconfRequestHash, uint256 tipAmount);
    event TipReceived(bytes32 indexed preconfRequestHash, uint256 amount);
    event EthSponsored(address indexed recipient, uint256 amount);

    ///////////////////////////////////////////////////////////////
    /// CONSTRUCTOR
    ///////////////////////////////////////////////////////////////

    // Replace constructor with disable-initializers
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    ///////////////////////////////////////////////////////////////
    /// VIEW FUNCTIONS
    ///////////////////////////////////////////////////////////////

    /// @notice Returns the status of a given PreconfRequest
    /// @dev Retrieves the status of a PreconfRequest using its hash
    /// @param preconfRequestHash The hash of the PreconfRequest
    /// @return The status of the PreconfRequest
    function getPreconfRequestStatus(bytes32 preconfRequestHash)
        public
        view
        returns (PreconfRequestStatus)
    {
        return preconfRequestStatus[preconfRequestHash];
    }

    /// @notice Checks if a given PreconfRequest is included
    /// @dev Checks the inclusion status of a PreconfRequest using its hash
    /// @param preconfRequestHash The hash of the PreconfRequest
    /// @return True if the PreconfRequest is included, false otherwise
    function checkInclusion(bytes32 preconfRequestHash) external view returns (bool) {
        return inclusionStatusMap[preconfRequestHash];
    }

    /// @notice Returns the collected tip amount
    /// @dev Retrieves the total amount of collected tips
    /// @return The collected tip amount
    function getCollectedTip() external view returns (uint256) {
        return collectedTip;
    }

    ///////////////////////////////////////////////////////////////
    /// EXTERNAL/PUBLIC FUNCTIONS
    ///////////////////////////////////////////////////////////////

    // Initializer instead of constructor
    function initialize(address initialOwner) external initializer {
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner { }

    function getTip(PreconfRequestBType calldata preconfRequestBType)
        public
        payable
        nonReentrant
    {
        _getTip(preconfRequestBType);
    }

    function exhaust(PreconfRequestBType calldata preconfRequestBType)
        external
        onlyOwner
    {
        _exhaust(preconfRequestBType);
    }

    function collectTip(bytes32 preconfRequestHash) public {
        _collectTip(preconfRequestHash);
    }

    function sponsorEthBatch(
        address[] calldata recipients,
        uint256[] calldata amounts
    )
        external
        payable
        onlyOwner
    {
        _sponsorEthBatch(recipients, amounts);
    }

    ///////////////////////////////////////////////////////////////
    /// INTERNAL FUNCTIONS
    ///////////////////////////////////////////////////////////////

    /// @notice Batch transfer ETH to multiple recipients in a single transaction
    /// @dev Transfers specified ETH amounts to corresponding recipient addresses. Used by Gateway to sponsor ETH for preconf Txs
    /// @param recipients Array of addresses to receive ETH
    /// @param amounts Array of ETH amounts to send to each recipient
    function _sponsorEthBatch(
        address[] calldata recipients,
        uint256[] calldata amounts
    )
        internal
    {
        require(recipients.length == amounts.length, "Mismatched array lengths");

        uint256 totalRequired;
        for (uint256 i = 0; i < amounts.length; i++) {
            totalRequired += amounts[i];
        }
        require(totalRequired <= msg.value, "Insufficient ETH sent");

        for (uint256 i = 0; i < recipients.length; i++) {
            (bool success,) = recipients[i].call{ value: amounts[i] }("");
            require(success, "ETH transfer failed");
            emit EthSponsored(recipients[i], amounts[i]);
        }
    }

    /// @notice Validates the given PreconfRequestBType
    /// @dev Checks the signatures of the provided PreconfRequestBType
    /// @param preconfRequestBType The PreconfRequestBType to validate
    function _validatePreconfRequestBType(
        PreconfRequestBType calldata preconfRequestBType
    )
        public
        view
    {
        require(
            preconfRequestBType.blockspaceAllocation.recipient == owner(),
            "Tip is not to the owner"
        );

        BlockspaceAllocation calldata blockspaceAllocation =
            preconfRequestBType.blockspaceAllocation;
        bytes32 blockspaceAllocationHash =
            blockspaceAllocation.getBlockspaceAllocationHash();

        ECDSALib.verifySignature(
            blockspaceAllocationHash,
            blockspaceAllocation.sender,
            preconfRequestBType.blockspaceAllocationSignature,
            "invalid blockspace allocation signature"
        );
        ECDSALib.verifySignature(
            preconfRequestBType.blockspaceAllocationSignature,
            blockspaceAllocation.recipient,
            preconfRequestBType.underwriterSignedBlockspaceAllocation,
            "invalid underwriter signature"
        );
        ECDSALib.verifySignature(
            preconfRequestBType.rawTx,
            blockspaceAllocation.recipient,
            preconfRequestBType.underwriterSignedRawTx,
            "invalid raw tx signature"
        );
    }

    /// @notice Burns gas by transferring the specified amount to the coinbase
    /// @dev Attempts to transfer the given amount of gas to the block's coinbase
    /// @param amount The amount of gas to be burned
    function _gasBurner(uint256 amount) internal {
        (bool success,) = payable(block.coinbase).call{ value: amount }("");
        require(success, "Gas burn failed");
    }

    /// @notice Handles payment by updating preconfer tips
    /// @dev Adds the specified amount to the preconfer tips
    /// @param amount The amount to be added to the preconfer tips
    /// @param preconfRequestHash The hash of the PreconfRequest
    function _handlePayment(uint256 amount, bytes32 preconfRequestHash) internal {
        preconferTips[preconfRequestHash] += amount;
        emit TipReceived(preconfRequestHash, amount);
    }

    /// @notice Processes and validates a tip payment for a preconfirmation request
    /// @dev This function:
    ///      1. Verifies the request hasn't been previously used
    ///      2. Validates the request parameters
    ///      3. Processes the payment including deposit and tip
    ///      4. Updates request status to executed
    /// @param preconfRequestBType The preconfirmation request containing blockspace allocation and signatures
    function _getTip(PreconfRequestBType calldata preconfRequestBType) internal {
        require(
            inclusionStatusMap[preconfRequestBType.getPreconfRequestBTypeHash()] == false,
            "PreconfRequest has been exhausted"
        );
        _validatePreconfRequestBType(preconfRequestBType);

        uint256 amount = payout(preconfRequestBType.blockspaceAllocation, true);
        bytes32 requestHash = preconfRequestBType.getPreconfRequestBTypeHash();
        _handlePayment(amount, requestHash);

        preconfRequestStatus[requestHash] = PreconfRequestStatus.Executed;
        inclusionStatusMap[requestHash] = true;

        emit PreconfRequestExecuted(requestHash, amount);
    }

    /// @notice Exhausts a preconfirmation request by burning gas and handling payment
    /// @dev This function validates the request, burns gas according to the allocation,
    ///      processes payment, and marks the request as exhausted
    /// @param preconfRequestBType The preconfirmation request to exhaust
    function _exhaust(PreconfRequestBType calldata preconfRequestBType) internal {
        _validatePreconfRequestBType(preconfRequestBType);
        BlockspaceAllocation calldata blockspaceAllocation =
            preconfRequestBType.blockspaceAllocation;
        require(blockspaceAllocation.recipient == owner(), "Tip to is not the owner");

        _gasBurner(blockspaceAllocation.gasLimit);

        uint256 amount = payout(blockspaceAllocation, false);
        _handlePayment(amount, preconfRequestBType.getPreconfRequestBTypeHash());
        preconfRequestStatus[preconfRequestBType.getPreconfRequestBTypeHash()] =
            PreconfRequestStatus.Exhausted;

        bytes32 txHash = preconfRequestBType.getPreconfRequestBTypeHash();
        inclusionStatusMap[txHash] = true;
        emit Exhausted(msg.sender, blockspaceAllocation.tip);
    }

    /// @notice Collects the tip amount for a specific preconfirmation request
    /// @dev Transfers the accumulated tip amount to the contract's collected tips
    ///      and marks the request as collected
    /// @param preconfRequestHash The hash of the preconfirmation request to collect tips for
    function _collectTip(bytes32 preconfRequestHash) internal {
        uint256 tipAmount = preconferTips[preconfRequestHash];
        require(tipAmount > 0, "No tip to collect");

        preconfRequestStatus[preconfRequestHash] = PreconfRequestStatus.Collected;

        emit TipCollected(tipAmount, preconfRequestHash);
        collectedTip += tipAmount;
    }
}

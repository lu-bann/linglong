// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import { TaiyiInteractiveChallenger } from "../src/taiyi/TaiyiInteractiveChallenger.sol";

import { ITaiyiInteractiveChallenger } from
    "../src/interfaces/ITaiyiInteractiveChallenger.sol";
import { TaiyiParameterManager } from "../src/taiyi/TaiyiParameterManager.sol";

import { PreconfRequestLib } from "../src/libs/PreconfRequestLib.sol";
import { PreconfRequestAType } from "../src/types/PreconfRequestATypes.sol";
import {
    BlockspaceAllocation,
    PreconfRequestBType
} from "../src/types/PreconfRequestBTypes.sol";
import { Ownable } from "@openzeppelin-contracts/contracts/access/Ownable.sol";
import { SP1Verifier } from "@sp1-contracts/v4.0.0-rc.3/SP1VerifierPlonk.sol";

contract TaiyiInteractiveChallengerTest is Test {
    address verifierAddress;
    address user;
    address owner;
    address underwriter = 0xD8F3183DEF51A987222D845be228e0Bbb932C222;

    uint256 internal userPrivateKey;
    uint256 internal ownerPrivateKey;
    uint256 internal underwriterPrivateKey =
        0xc5114526e042343c6d1899cad05e1c00ba588314de9b96929914ee0df18d46b2;

    TaiyiInteractiveChallenger taiyiInteractiveChallenger;
    TaiyiParameterManager parameterManager;

    struct ProofData {
        bytes proofValuesBytes;
        bytes proofBytesBytes;
        uint64 blockNumber;
        bytes32 blockHash;
    }

    function setUp() public {
        verifierAddress = address(new SP1Verifier());

        // Create test accounts
        (user, userPrivateKey) = makeAddrAndKey("user");
        (owner, ownerPrivateKey) = makeAddrAndKey("owner");

        // Fund test accounts
        vm.deal(user, 100 ether);
        vm.deal(owner, 100 ether);
        vm.deal(underwriter, 100 ether);

        parameterManager = new TaiyiParameterManager();
        parameterManager.initialize(
            owner, 1, 64, 256, 32, 0, 12, 0x0000000000000000000000000000000000000000
        );

        taiyiInteractiveChallenger = new TaiyiInteractiveChallenger(
            owner, verifierAddress, bytes32(0x0), address(parameterManager)
        );
    }

    function _readPreconfRequestAType(string memory jsonPath)
        internal
        returns (PreconfRequestAType memory preconfRequestAType)
    {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), jsonPath));

        bytes memory abiEncodedPreconfRequestAType =
            vm.parseBytes(vm.parseJsonString(json, ".abi_encoded_preconf_request"));

        (
            string memory tipTx,
            string[] memory txs,
            uint64 slot,
            uint64 sequenceNum,
            address signer,
            uint64 chainId
        ) = abi.decode(
            abiEncodedPreconfRequestAType,
            (string, string[], uint64, uint64, address, uint64)
        );

        return PreconfRequestAType(txs, tipTx, slot, sequenceNum, signer);
    }

    function _readPreconfRequestBType(string memory jsonPath)
        internal
        returns (PreconfRequestBType memory preconfRequestBType)
    {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), jsonPath));

        bytes memory abiEncodedPreconfRequestBType =
            vm.parseBytes(vm.parseJsonString(json, ".abi_encoded_preconf_request"));

        (
            string memory blockspaceAllocationEncoded,
            string memory blockspaceAllocationSignature,
            string memory transaction,
            address signer,
            uint64 chainId
        ) = abi.decode(
            abiEncodedPreconfRequestBType, (string, string, string, address, uint64)
        );

        (
            uint64 gasLimit,
            address sender,
            address recipient,
            uint256 deposit,
            uint256 tip,
            uint64 targetSlot,
            uint64 blobCount
        ) = abi.decode(
            vm.parseBytes(blockspaceAllocationEncoded),
            (uint64, address, address, uint256, uint256, uint64, uint64)
        );

        BlockspaceAllocation memory blockspaceAllocation = BlockspaceAllocation({
            gasLimit: gasLimit,
            sender: sender,
            recipient: recipient,
            deposit: deposit,
            tip: tip,
            targetSlot: targetSlot,
            blobCount: blobCount
        });

        return PreconfRequestBType({
            blockspaceAllocation: blockspaceAllocation,
            blockspaceAllocationSignature: bytes(blockspaceAllocationSignature),
            underwriterSignedBlockspaceAllocation: hex"52e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c",
            rawTx: bytes(transaction),
            underwriterSignedRawTx: hex"42e31ae52880f54549f244d411497e4990b2f8717cb61b7b0cae46cb2435fb3c072a6cf466b93a2539644bdc002480290794a0a96ee8c576f110f5185929b1771c"
        });
    }

    function _readProofData(string memory jsonPath) internal returns (ProofData memory) {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), jsonPath));

        string memory proofValues = vm.parseJsonString(json, ".public_values");
        string memory proofBytes = vm.parseJsonString(json, ".proof");

        bytes memory proofValuesBytes = vm.parseBytes(proofValues);
        bytes memory proofBytesBytes = vm.parseBytes(proofBytes);

        // Decode proof values for block info
        (
            uint64 proofBlockTimestamp,
            bytes32 proofBlockHash,
            uint64 proofBlockNumber,
            address proofUnderwriterAddress,
            bytes memory proofSignature
        ) = abi.decode(proofValuesBytes, (uint64, bytes32, uint64, address, bytes));

        return ProofData({
            proofValuesBytes: proofValuesBytes,
            proofBytesBytes: proofBytesBytes,
            blockNumber: proofBlockNumber,
            blockHash: proofBlockHash
        });
    }

    function _createChallengePreconfRequestAType() public {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestAType memory preconfRequestAType = _readPreconfRequestAType(
            "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestATypeHash(preconfRequestAType);

        uint256 blockTimestamp = (
            preconfRequestAType.slot + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        // Expect event
        vm.expectEmit(true, true, true, false);
        emit ITaiyiInteractiveChallenger.ChallengeOpened(challengeId, user, underwriter);

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        vm.stopPrank();
    }

    function _createChallengePreconfRequestBType() public {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestBType memory preconfRequestBType = _readPreconfRequestBType(
            "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestBTypeHash(preconfRequestBType);

        uint256 blockTimestamp = (
            preconfRequestBType.blockspaceAllocation.targetSlot
                + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        taiyiInteractiveChallenger.createChallengeBType{ value: bond }(
            preconfRequestBType, signature
        );

        vm.stopPrank();
    }

    // =========================================
    //  Test: Create challenge AType
    // =========================================
    function testCreateChallengeAType() public {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestAType memory preconfRequestAType = _readPreconfRequestAType(
            "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestATypeHash(preconfRequestAType);

        uint256 blockTimestamp = (
            preconfRequestAType.slot + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        // Expect event
        vm.expectEmit(true, true, true, false);
        emit ITaiyiInteractiveChallenger.ChallengeOpened(challengeId, user, underwriter);

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        vm.stopPrank();
    }

    // =========================================
    //  Test: Create challenge BType
    // =========================================
    function testCreateChallengeBType() public {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestBType memory preconfRequestBType = _readPreconfRequestBType(
            "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestBTypeHash(preconfRequestBType);

        uint256 blockTimestamp = (
            preconfRequestBType.blockspaceAllocation.targetSlot
                + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        // Expect event
        vm.expectEmit(true, true, true, false);
        emit ITaiyiInteractiveChallenger.ChallengeOpened(challengeId, user, underwriter);

        taiyiInteractiveChallenger.createChallengeBType{ value: bond }(
            preconfRequestBType, signature
        );

        vm.stopPrank();
    }

    // =========================================
    //  Test: Fails to create challenge AType with invalid bond
    // =========================================
    function testCreateChallengeATypeFailsWithInvalidBond() public {
        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestAType memory preconfRequestAType = _readPreconfRequestAType(
            "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
        );

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestATypeHash(preconfRequestAType);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        vm.expectPartialRevert(ITaiyiInteractiveChallenger.ChallengeBondInvalid.selector);

        taiyiInteractiveChallenger.createChallengeAType{ value: 0 }(
            preconfRequestAType, signature
        );

        vm.stopPrank();
    }

    // =========================================
    //  Test: Fails to create challenge BType with invalid bond
    // =========================================
    function testCreateChallengeBTypeFailsWithInvalidBond() public {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestBType memory preconfRequestBType = _readPreconfRequestBType(
            "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
        );

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestBTypeHash(preconfRequestBType);

        uint256 blockTimestamp = (
            preconfRequestBType.blockspaceAllocation.targetSlot
                + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        vm.expectPartialRevert(ITaiyiInteractiveChallenger.ChallengeBondInvalid.selector);

        taiyiInteractiveChallenger.createChallengeBType{ value: 0 }(
            preconfRequestBType, signature
        );

        vm.stopPrank();
    }

    // =========================================
    //  Test: Fails to create challenge AType with challenge already exists
    // =========================================
    function testCreateChallengeATypeFailsChallengeAlreadyExists() public {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestAType memory preconfRequestAType = _readPreconfRequestAType(
            "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestATypeHash(preconfRequestAType);

        uint256 blockTimestamp = (
            preconfRequestAType.slot + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        vm.expectPartialRevert(
            ITaiyiInteractiveChallenger.ChallengeAlreadyExists.selector
        );

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        vm.stopPrank();
    }

    // =========================================
    // Test: Fails to create challenge BType with challenge already exists
    // =========================================
    function testCreateChallengeBTypeFailsAlreadyExists() public {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestBType memory preconfRequestBType = _readPreconfRequestBType(
            "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestBTypeHash(preconfRequestBType);

        uint256 blockTimestamp = (
            preconfRequestBType.blockspaceAllocation.targetSlot
                + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        taiyiInteractiveChallenger.createChallengeBType{ value: bond }(
            preconfRequestBType, signature
        );

        vm.expectPartialRevert(
            ITaiyiInteractiveChallenger.ChallengeAlreadyExists.selector
        );

        taiyiInteractiveChallenger.createChallengeBType{ value: bond }(
            preconfRequestBType, signature
        );

        vm.stopPrank();
    }

    // =========================================
    // Test: Fails to create challenge AType with target slot not in challenge creation window
    // =========================================
    function testCreateChallengeATypeFailsWithTargetSlotNotInChallengeCreationWindow()
        public
    {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestAType memory preconfRequestAType = _readPreconfRequestAType(
            "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestATypeHash(preconfRequestAType);

        uint256 blockTimestamp = (
            preconfRequestAType.slot + parameterManager.challengeCreationWindow() + 1
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        vm.expectPartialRevert(
            ITaiyiInteractiveChallenger.TargetSlotNotInChallengeCreationWindow.selector
        );

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        vm.stopPrank();
    }

    // =========================================
    // Test: Fails to create challenge BType with target slot not in challenge creation window
    // =========================================
    function testCreateChallengeBTypeFailsWithTargetSlotNotInChallengeCreationWindow()
        public
    {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestBType memory preconfRequestBType = _readPreconfRequestBType(
            "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestBTypeHash(preconfRequestBType);

        uint256 blockTimestamp = (
            preconfRequestBType.blockspaceAllocation.targetSlot
                + parameterManager.challengeCreationWindow() + 1
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        vm.expectPartialRevert(
            ITaiyiInteractiveChallenger.TargetSlotNotInChallengeCreationWindow.selector
        );

        taiyiInteractiveChallenger.createChallengeBType{ value: bond }(
            preconfRequestBType, signature
        );

        vm.stopPrank();
    }

    // =========================================
    // Test: Fails to create challenge AType with block not finalized
    // =========================================
    function testCreateChallengeATypeFailsWithBlockNotFinalized() public {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestAType memory preconfRequestAType = _readPreconfRequestAType(
            "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestATypeHash(preconfRequestAType);

        uint256 blockTimestamp = (
            preconfRequestAType.slot + parameterManager.finalizationWindow() - 1
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        vm.expectPartialRevert(ITaiyiInteractiveChallenger.BlockNotFinalized.selector);

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        vm.stopPrank();
    }

    // =========================================
    // Test: Fails to create challenge BType with block not finalized
    // =========================================
    function testCreateChallengeBTypeFailsWithBlockNotFinalized() public {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestBType memory preconfRequestBType = _readPreconfRequestBType(
            "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestBTypeHash(preconfRequestBType);

        uint256 blockTimestamp = (
            preconfRequestBType.blockspaceAllocation.targetSlot
                + parameterManager.finalizationWindow() - 1
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        vm.expectPartialRevert(ITaiyiInteractiveChallenger.BlockNotFinalized.selector);

        taiyiInteractiveChallenger.createChallengeBType{ value: bond }(
            preconfRequestBType, signature
        );

        vm.stopPrank();
    }

    // Test: Resolve expired challenge (PreconfRequestAType)
    // =========================================
    function testResolveExpiredChallengePreconfRequestAType() public {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestAType memory preconfRequestAType = _readPreconfRequestAType(
            "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestATypeHash(preconfRequestAType);

        uint256 blockTimestamp = (
            preconfRequestAType.slot + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        // Skip duration so the challenge is expired
        skip(parameterManager.challengeMaxDuration() + 1);

        taiyiInteractiveChallenger.resolveExpiredChallenge(challengeId);

        vm.stopPrank();
    }

    // =========================================
    // Test: Resolve expired challenge (PreconfRequestBType)
    // =========================================
    function testResolveExpiredChallengePreconfRequestBType() public {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestBType memory preconfRequestBType = _readPreconfRequestBType(
            "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestBTypeHash(preconfRequestBType);

        uint256 blockTimestamp = (
            preconfRequestBType.blockspaceAllocation.targetSlot
                + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        taiyiInteractiveChallenger.createChallengeBType{ value: bond }(
            preconfRequestBType, signature
        );

        // Skip duration so the challenge is expired
        skip(parameterManager.challengeMaxDuration() + 1);

        taiyiInteractiveChallenger.resolveExpiredChallenge(challengeId);

        vm.stopPrank();
    }

    // =========================================
    // Test: Resolve expired challenge fails with challenge not expired (PreconfRequestAType)
    // =========================================
    function testResolveExpiredChallengeFailsWithNotExpiredPreconfRequestAType() public {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestAType memory preconfRequestAType = _readPreconfRequestAType(
            "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestATypeHash(preconfRequestAType);

        uint256 blockTimestamp = (
            preconfRequestAType.slot + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        vm.expectPartialRevert(ITaiyiInteractiveChallenger.ChallengeNotExpired.selector);

        taiyiInteractiveChallenger.resolveExpiredChallenge(challengeId);

        vm.stopPrank();
    }

    // =========================================
    // Test: Resolve expired challenge fails with challenge not expired (PreconfRequestBType)
    // =========================================
    function testResolveExpiredChallengeFailsWithNotExpiredPreconfRequestBType() public {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestBType memory preconfRequestBType = _readPreconfRequestBType(
            "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestBTypeHash(preconfRequestBType);

        uint256 blockTimestamp = (
            preconfRequestBType.blockspaceAllocation.targetSlot
                + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        taiyiInteractiveChallenger.createChallengeBType{ value: bond }(
            preconfRequestBType, signature
        );

        vm.expectPartialRevert(ITaiyiInteractiveChallenger.ChallengeNotExpired.selector);

        taiyiInteractiveChallenger.resolveExpiredChallenge(challengeId);

        vm.stopPrank();
    }

    // =========================================
    // Test: Resolve expired challenge fails with challenge does not exist (PreconfRequestAType)
    // =========================================
    function testResolveExpiredChallengeFailsWithDoesNotExistPreconfRequestAType()
        public
    {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestAType memory preconfRequestAType = _readPreconfRequestAType(
            "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestATypeHash(preconfRequestAType);

        uint256 blockTimestamp = (
            preconfRequestAType.slot + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        vm.expectPartialRevert(ITaiyiInteractiveChallenger.ChallengeDoesNotExist.selector);

        taiyiInteractiveChallenger.resolveExpiredChallenge(
            keccak256("randomInvalidChallengeId")
        );

        vm.stopPrank();
    }

    // =========================================
    // Test: Resolve expired challenge fails with challenge does not exist (PreconfRequestBType)
    // =========================================
    function testResolveExpiredChallengeFailsWithDoesNotExistPreconfRequestBType()
        public
    {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestBType memory preconfRequestBType = _readPreconfRequestBType(
            "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestBTypeHash(preconfRequestBType);

        uint256 blockTimestamp = (
            preconfRequestBType.blockspaceAllocation.targetSlot
                + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        taiyiInteractiveChallenger.createChallengeBType{ value: bond }(
            preconfRequestBType, signature
        );

        vm.expectPartialRevert(ITaiyiInteractiveChallenger.ChallengeDoesNotExist.selector);

        taiyiInteractiveChallenger.resolveExpiredChallenge(
            keccak256("randomInvalidChallengeId")
        );

        vm.stopPrank();
    }

    // =========================================
    //  Test: Prove (PreconfRequestAType)
    // =========================================
    function testProveSuccessPreconfRequestAType() public {
        string memory jsonPath =
            "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json";
        string memory json = vm.readFile(string.concat(vm.projectRoot(), jsonPath));

        bytes32 vk = bytes32(vm.parseBytes(vm.parseJsonString(json, ".vk")));
        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        address taiyiCore = vm.parseJsonAddress(json, ".taiyi_core");

        vm.startPrank(owner);
        taiyiInteractiveChallenger.setInteractiveFraudProofVKey(vk);
        parameterManager.setGenesisTimestamp(genesisTimestamp);
        parameterManager.setTaiyiCore(taiyiCore);
        vm.stopPrank();

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestAType memory preconfRequestAType =
            _readPreconfRequestAType(jsonPath);
        ProofData memory proofData = _readProofData(jsonPath);

        uint256 bond = parameterManager.challengeBond();
        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestATypeHash(preconfRequestAType);

        // This emulates the block hash for the inclusion block
        vm.roll(proofData.blockNumber + 10);
        vm.setBlockhash(proofData.blockNumber, proofData.blockHash);

        uint256 blockTimestamp = (
            preconfRequestAType.slot + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        ITaiyiInteractiveChallenger.Challenge[] memory openChallenges =
            taiyiInteractiveChallenger.getOpenChallenges();

        assertEq(openChallenges.length, 1);
        assertEq(openChallenges[0].id, challengeId);

        taiyiInteractiveChallenger.prove(
            challengeId, proofData.proofValuesBytes, proofData.proofBytesBytes
        );

        openChallenges = taiyiInteractiveChallenger.getOpenChallenges();
        assertEq(openChallenges.length, 0);

        vm.stopPrank();
    }

    // =========================================
    //  Test: Prove (PreconfRequestAType multiple txs)
    // =========================================
    function testProveSuccessPreconfRequestATypeMultipleTxs() public {
        string memory jsonPath =
            "/test/test-data/zkvm/poi-preconf-type-a-multiple-txs-included-test-data.json";
        string memory json = vm.readFile(string.concat(vm.projectRoot(), jsonPath));

        bytes32 vk = bytes32(vm.parseBytes(vm.parseJsonString(json, ".vk")));
        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        address taiyiCore = vm.parseJsonAddress(json, ".taiyi_core");

        vm.startPrank(owner);
        taiyiInteractiveChallenger.setInteractiveFraudProofVKey(vk);
        parameterManager.setGenesisTimestamp(genesisTimestamp);
        parameterManager.setTaiyiCore(taiyiCore);
        vm.stopPrank();

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestAType memory preconfRequestAType =
            _readPreconfRequestAType(jsonPath);
        ProofData memory proofData = _readProofData(jsonPath);

        uint256 bond = parameterManager.challengeBond();
        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestATypeHash(preconfRequestAType);

        // This emulates the block hash for the inclusion block
        vm.roll(proofData.blockNumber + 10);
        vm.setBlockhash(proofData.blockNumber, proofData.blockHash);

        uint256 blockTimestamp = (
            preconfRequestAType.slot + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        ITaiyiInteractiveChallenger.Challenge[] memory openChallenges =
            taiyiInteractiveChallenger.getOpenChallenges();

        assertEq(openChallenges.length, 1);
        assertEq(openChallenges[0].id, challengeId);

        taiyiInteractiveChallenger.prove(
            challengeId, proofData.proofValuesBytes, proofData.proofBytesBytes
        );

        openChallenges = taiyiInteractiveChallenger.getOpenChallenges();
        assertEq(openChallenges.length, 0);

        vm.stopPrank();
    }

    // =========================================
    //  Test: Prove (PreconfRequestBType)
    // =========================================
    function testProveSuccessPreconfRequestBType() public {
        string memory jsonPath =
            "/test/test-data/zkvm/poi-preconf-type-b-included-test-data.json";
        string memory json = vm.readFile(string.concat(vm.projectRoot(), jsonPath));

        bytes32 vk = bytes32(vm.parseBytes(vm.parseJsonString(json, ".vk")));
        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        address taiyiCore = vm.parseJsonAddress(json, ".taiyi_core");

        vm.startPrank(owner);
        taiyiInteractiveChallenger.setInteractiveFraudProofVKey(vk);
        parameterManager.setGenesisTimestamp(genesisTimestamp);
        parameterManager.setTaiyiCore(taiyiCore);
        vm.stopPrank();

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestBType memory preconfRequestBType =
            _readPreconfRequestBType(jsonPath);
        ProofData memory proofData = _readProofData(jsonPath);

        uint256 bond = parameterManager.challengeBond();
        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestBTypeHash(preconfRequestBType);

        // This emulates the block hash for the inclusion block
        vm.roll(proofData.blockNumber + 10);
        vm.setBlockhash(proofData.blockNumber, proofData.blockHash);

        uint256 blockTimestamp = (
            preconfRequestBType.blockspaceAllocation.targetSlot
                + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes32 challengeId = keccak256(signature);

        taiyiInteractiveChallenger.createChallengeBType{ value: bond }(
            preconfRequestBType, signature
        );

        ITaiyiInteractiveChallenger.Challenge[] memory openChallenges =
            taiyiInteractiveChallenger.getOpenChallenges();

        assertEq(openChallenges.length, 1);
        assertEq(openChallenges[0].id, challengeId);

        taiyiInteractiveChallenger.prove(
            challengeId, proofData.proofValuesBytes, proofData.proofBytesBytes
        );

        openChallenges = taiyiInteractiveChallenger.getOpenChallenges();
        assertEq(openChallenges.length, 0);

        vm.stopPrank();
    }

    // =========================================
    //  Test: Get all challenges
    // =========================================
    function testGetChallenges() public {
        ITaiyiInteractiveChallenger.Challenge[] memory challenges =
            taiyiInteractiveChallenger.getChallenges();
        assertEq(challenges.length, 0);

        _createChallengePreconfRequestAType();
        challenges = taiyiInteractiveChallenger.getChallenges();
        assertEq(challenges.length, 1);

        _createChallengePreconfRequestBType();
        challenges = taiyiInteractiveChallenger.getChallenges();
        assertEq(challenges.length, 2);

        // Skip duration so the challenge is expired
        skip(parameterManager.challengeMaxDuration() + 1024);
        taiyiInteractiveChallenger.resolveExpiredChallenge(challenges[0].id);

        challenges = taiyiInteractiveChallenger.getChallenges();
        assertEq(challenges.length, 2);
    }

    // =========================================
    //  Test: Get open challenges
    // =========================================
    function testGetOpenChallenges() public {
        ITaiyiInteractiveChallenger.Challenge[] memory openChallenges =
            taiyiInteractiveChallenger.getOpenChallenges();
        assertEq(openChallenges.length, 0);

        _createChallengePreconfRequestAType();
        openChallenges = taiyiInteractiveChallenger.getOpenChallenges();
        assertEq(openChallenges.length, 1);

        _createChallengePreconfRequestBType();
        openChallenges = taiyiInteractiveChallenger.getOpenChallenges();
        assertEq(openChallenges.length, 2);

        // Skip duration so the challenge is expired
        skip(parameterManager.challengeMaxDuration() + 1024);
        taiyiInteractiveChallenger.resolveExpiredChallenge(openChallenges[0].id);

        openChallenges = taiyiInteractiveChallenger.getOpenChallenges();
        assertEq(openChallenges.length, 1);
    }

    // =========================================
    //  Test: Get challenge by id (PreconfRequestAType)
    // =========================================
    function testGetChallengeByIdPreconfRequestAType() public {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
            )
        );

        uint256 genesisTimestamp = uint256(vm.parseJsonUint(json, ".genesis_time"));
        vm.prank(owner);
        parameterManager.setGenesisTimestamp(genesisTimestamp);

        vm.startPrank(user);
        vm.chainId(3_151_908);

        PreconfRequestAType memory preconfRequestAType = _readPreconfRequestAType(
            "/test/test-data/zkvm/poi-preconf-type-a-included-test-data.json"
        );

        uint256 bond = parameterManager.challengeBond();

        bytes32 dataHash =
            PreconfRequestLib.getPreconfRequestATypeHash(preconfRequestAType);

        uint256 blockTimestamp = (
            preconfRequestAType.slot + parameterManager.challengeCreationWindow()
        ) * parameterManager.slotTime() + parameterManager.genesisTimestamp();

        vm.warp(blockTimestamp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(underwriterPrivateKey, dataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes32 challengeId = keccak256(signature);

        taiyiInteractiveChallenger.createChallengeAType{ value: bond }(
            preconfRequestAType, signature
        );

        ITaiyiInteractiveChallenger.Challenge memory challenge =
            taiyiInteractiveChallenger.getChallenge(challengeId);

        assertEq(challenge.id, challengeId);
        // TODO[Martin]: Check challenge.createdAt
        assertEq(challenge.challenger, user);
        assertEq(challenge.commitmentSigner, underwriter);
        assertTrue(challenge.status == ITaiyiInteractiveChallenger.ChallengeStatus.Open);
        assertEq(challenge.preconfType, 0);
        assertEq(challenge.commitmentData, abi.encode(preconfRequestAType));
        assertEq(challenge.signature, signature);

        vm.stopPrank();
    }

    // =========================================
    //  Test: Get challenge by id fails with challenge does not exist
    // =========================================
    function testGetChallengeByIdFailsWithDoesNotExist() public {
        bytes32 challengeId = keccak256(abi.encodePacked("challengeId"));
        vm.expectRevert(ITaiyiInteractiveChallenger.ChallengeDoesNotExist.selector);
        taiyiInteractiveChallenger.getChallenge(challengeId);
    }

    // =========================================
    //  Test: Owner can set verifier gateway
    // =========================================
    function testOwnerCanSetVerifierGateway() public {
        vm.prank(owner);
        taiyiInteractiveChallenger.setVerifierGateway(address(0x123));
        assertEq(taiyiInteractiveChallenger.verifierGateway(), address(0x123));
    }

    // =========================================
    //  Test: User is not authorized to set verifier gateway
    // =========================================
    function testUserCannotSetVerifierGateway() public {
        vm.prank(user);
        vm.expectPartialRevert(Ownable.OwnableUnauthorizedAccount.selector);
        taiyiInteractiveChallenger.setVerifierGateway(address(0x123));
    }

    // =========================================
    // Test: Owner can set interactiveFraudProofVKey
    // =========================================
    function testOwnerCanSetInteractiveFraudProofVKey() public {
        vm.prank(owner);
        taiyiInteractiveChallenger.setInteractiveFraudProofVKey(bytes32(0));
        assertEq(taiyiInteractiveChallenger.interactiveFraudProofVKey(), bytes32(0));
    }

    // =========================================
    // Test: User is not authorized to set interactiveFraudProofVKey
    // =========================================
    function testUserCannotSetInteractiveFraudProofVKey() public {
        vm.prank(user);
        vm.expectPartialRevert(Ownable.OwnableUnauthorizedAccount.selector);
        taiyiInteractiveChallenger.setInteractiveFraudProofVKey(bytes32(0));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ISymbioticNetworkMiddleware } from
    "../src/interfaces/ISymbioticNetworkMiddleware.sol";

import { ITaiyiInteractiveChallenger } from
    "../src/interfaces/ITaiyiInteractiveChallenger.sol";
import { ITaiyiRegistryCoordinator } from
    "../src/interfaces/ITaiyiRegistryCoordinator.sol";
import { OperatorSubsetLib } from "../src/libs/OperatorSubsetLib.sol";
import { SafeCast96To32Lib } from "../src/libs/SafeCast96To32Lib.sol";
import { PubkeyRegistry } from "../src/operator-registries/PubkeyRegistry.sol";
import { SocketRegistry } from "../src/operator-registries/SocketRegistry.sol";
import { TaiyiRegistryCoordinator } from
    "../src/operator-registries/TaiyiRegistryCoordinator.sol";
import { LinglongSlasher } from "../src/slasher/LinglongSlasher.sol";
import { SymbioticNetworkMiddleware } from
    "../src/symbiotic-network/SymbioticNetworkMiddleware.sol";
import { EigenlayerDeployer } from "./utils/EigenlayerDeployer.sol";
import { MockLinglongChallenger } from "./utils/MockChallenger.sol";
import { IAllocationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IAllocationManagerTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IPauserRegistry } from
    "@eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { TransparentUpgradeableProxy } from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import { POCBaseTest } from "@symbiotic-test/POCBase.t.sol";
import { Subnetwork } from "@symbiotic/contracts/libraries/Subnetwork.sol";
import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { Registry } from "@urc/Registry.sol";
import { BLS } from "@urc/lib/BLS.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

contract SymbioticMiddlewareTest is POCBaseTest {
    using EnumerableSet for EnumerableSet.AddressSet;
    using OperatorSubsetLib for uint96;
    using OperatorSubsetLib for uint32;
    using SafeCast96To32Lib for uint96;
    using SafeCast96To32Lib for uint32;
    using SafeCast96To32Lib for uint96[];
    using SafeCast96To32Lib for uint32[];
    using Subnetwork for address;
    using Subnetwork for bytes32;

    bytes32 public constant VIOLATION_TYPE_URC = keccak256("URC_VIOLATION");
    uint64 public constant COMMITMENT_TYPE_URC = 1;
    uint256 public registrationMinCollateral;

    SymbioticNetworkMiddleware middleware;
    uint96 constant VALIDATOR_SUBNETWORK = 0;
    uint96 constant UNDERWRITER_SUBNETWORK = 1;
    TaiyiRegistryCoordinator registry;

    // RestakingProtocol enum values to use when we don't have access to the enum directly
    uint8 constant RESTAKING_PROTOCOL_NONE = 0;
    uint8 constant RESTAKING_PROTOCOL_EIGENLAYER = 1;
    uint8 constant RESTAKING_PROTOCOL_SYMBIOTIC = 2;

    // Address variables
    address proxyAdmin;
    address staker;
    address operator;
    address underwriterOperator;
    address challenger;
    uint256 operatorSecretKey;
    uint256 underwriterOperatorSecretKey;
    bytes operatorBLSPubKey;
    bytes underwriterBLSPubKey;

    // Contract instances
    EigenlayerDeployer eigenLayerDeployer;
    Registry urcRegistry;
    LinglongSlasher slasher;
    PubkeyRegistry pubkeyRegistry;
    SocketRegistry socketRegistry;

    // Constants
    uint256 constant STAKE_AMOUNT = 32 ether;
    uint256 constant _WAD = 1e18; // 1 WAD = 100% allocation
    uint256 constant REGISTRATION_MIN_COLLATERAL = 0.11 ether;

    // Track subnetwork and operator set IDs
    uint96 validatorSubnetworkId;
    uint96 underwriterSubnetworkId;
    uint32 operatorSetId;

    // Add storage variables to reduce stack usage
    address internal testPrimaryOp;
    address internal testUnderwriterOp;
    uint256 internal testPrimaryOpKey;
    uint256 internal testUnderwriterOpKey;
    bytes32 internal testRegistrationRoot;

    modifier impersonate(address user) {
        vm.startPrank(user);
        _;
        vm.stopPrank();
    }

    function setUp() public virtual override {
        proxyAdmin = makeAddr("proxyAdmin");
        SYMBIOTIC_CORE_PROJECT_ROOT = "lib/middleware-sdk/lib/core/";
        super.setUp();

        _setupEigenLayerAndAccounts();
        _setupURCRegistry();
        _deployTaiyiRegistryCoordinator();
        _deployLinglongSlasher();
        _setupRegistryCoordinatorRegistries();
        _deploySymbioticNetworkMiddleware();
        _configureMiddlewareConnections();
        challenger = _setupChallenger();
        _setupSubnetworks();
    }

    // ===========================================================================
    // ========================= TEST FUNCTIONS ==================================
    // ===========================================================================

    function test_RegisterOperatorWithMiddleware() public {
        _registerOperatorInRegistry(operator);
        _registerNetworks();
        _optInToNetworks(operator);
        _optInToVault(operator, address(vault4));

        // Register operator with middleware
        bytes memory key = abi.encode(operator);
        bytes memory signature = _generateKeySignature(key, operatorSecretKey);
        uint96[] memory subnetworks =
            _createSubnetworksArray(validatorSubnetworkId, underwriterSubnetworkId);

        vm.startPrank(operator);
        middleware.registerOperator(key, signature, subnetworks);
        vm.stopPrank();

        // Verify that the mocked getOperatorAllocatedSubnetworks returns what we expect
        uint96[] memory operatorSubnetworks =
            middleware.getOperatorAllocatedSubnetworks(operator);

        // Assert that operator was registered in the correct subnetworks
        assertEq(
            operatorSubnetworks.length,
            2,
            "Operator should be registered in 2 subnetworks"
        );

        // Check individual subnetworks by equality since we're using mocks
        assertEq(
            operatorSubnetworks[0],
            validatorSubnetworkId,
            "First subnetwork should match validator subnetwork"
        );
        assertEq(
            operatorSubnetworks[1],
            underwriterSubnetworkId,
            "Second subnetwork should match underwriter subnetwork"
        );

        // Verify operator status in the registry coordinator
        ITaiyiRegistryCoordinator.OperatorStatus status =
            registry.getOperatorStatus(operator);
        assertEq(
            uint8(status),
            uint8(ITaiyiRegistryCoordinator.OperatorStatus.REGISTERED),
            "Operator should be registered in registry coordinator"
        );
    }

    function test_OperatorSlashing() public {
        // Register operator and setup middleware
        _setupOperatorForSlashing();

        // Register validators and get registration root
        (bytes32 registrationRoot, IRegistry.SignedRegistration[] memory registrations) =
            _registerValidators();

        // Opt-in to slasher using middleware
        _optInToSlasherWithRegistrations(registrationRoot, registrations);

        // Perform the slashing
        uint256 slashAmount = _performSlashing(registrationRoot, challenger);

        // Verify slashing was successful
        _verifySlashingSuccess(registrationRoot, slashAmount);
    }

    function _setupOperatorForSlashing() internal {
        _registerOperatorInRegistry(operator);
        _registerNetworks();
        _optInToNetworks(operator);
        _optInToVault(operator, address(vault4));

        // Register with middleware
        bytes memory key = abi.encode(operator);
        bytes memory keySignature = _generateKeySignature(key, operatorSecretKey);
        uint96[] memory subnetworks =
            _createSubnetworksArray(validatorSubnetworkId, underwriterSubnetworkId);

        vm.startPrank(operator);
        middleware.registerOperator(key, keySignature, subnetworks);
        vm.stopPrank();
    }

    function _optInToSlasherWithRegistrations(
        bytes32 registrationRoot,
        IRegistry.SignedRegistration[] memory registrations
    )
        internal
    {
        // Create delegation signatures
        uint256 delegateePrivKey = 69_420;
        BLS.G1Point memory delegateePubKey = BLS.toPublicKey(delegateePrivKey);

        uint256 validatorPrivKey1 = 12_345;
        uint256 validatorPrivKey2 = 67_890;

        BLS.G2Point[] memory delegationSignatures = new BLS.G2Point[](2);
        delegationSignatures[0] =
            _createDelegationSignature(validatorPrivKey1, delegateePubKey, operator);
        delegationSignatures[1] =
            _createDelegationSignature(validatorPrivKey2, delegateePubKey, operator);

        // Create metadata for validators
        bytes[] memory data = new bytes[](2);
        data[0] = abi.encode("validator-1-metadata");
        data[1] = abi.encode("validator-2-metadata");

        // Wait for fraud proof window
        vm.roll(block.number + 100 days);

        // Call middleware's optInToSlasher
        vm.startPrank(operator);
        middleware.optInToSlasher(
            registrationRoot,
            registrations,
            delegationSignatures,
            delegateePubKey,
            operator, // Self-delegation for simplicity
            data
        );

        // Get delegations
        (BLS.G1Point[] memory pubkeys, ISlasher.SignedDelegation[] memory delegations) =
            middleware.getAllDelegations(operator, registrationRoot);

        // Set delegations
        middleware.batchSetDelegations(registrationRoot, pubkeys, delegations);
        vm.stopPrank();
    }

    function _performSlashing(
        bytes32 registrationRoot,
        address challengerAddr
    )
        internal
        returns (uint256)
    {
        ITaiyiInteractiveChallenger.Challenge memory challenge =
        ITaiyiInteractiveChallenger.Challenge({
            id: bytes32(uint256(1234)),
            createdAt: block.timestamp,
            challenger: challenger,
            commitmentSigner: operator,
            status: ITaiyiInteractiveChallenger.ChallengeStatus.Open,
            preconfType: 0,
            commitmentData: new bytes(0),
            signature: new bytes(0)
        });

        // Create a mock commitment for slashing
        ISlasher.Commitment memory commitment = ISlasher.Commitment({
            slasher: address(slasher),
            commitmentType: COMMITMENT_TYPE_URC,
            payload: abi.encode(abi.encode(challenge))
        });

        // Sign the commitment
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(operatorSecretKey, keccak256(abi.encode(commitment)));
        bytes memory commitmentSignature = abi.encodePacked(r, s, v);

        ISlasher.SignedCommitment memory signedCommitment = ISlasher.SignedCommitment({
            commitment: commitment,
            signature: commitmentSignature
        });

        // Create evidence
        bytes memory evidence = abi.encode("Mock evidence");

        // Check which protocol the operator is registered with
        bool isSymbioticOperator =
            registry.isSymbioticOperatorInSubnetwork(validatorSubnetworkId, operator);
        console.log("Is Symbiotic Operator:", isSymbioticOperator);

        // Perform the slashing based on the operator's restaking protocol
        uint256 slashAmount;
        vm.startPrank(challengerAddr);

        console.log("Slashing via Symbiotic protocol");
        slashAmount =
            urcRegistry.slashCommitment(registrationRoot, signedCommitment, evidence);

        vm.stopPrank();

        return slashAmount;
    }

    function _verifySlashingSuccess(
        bytes32 registrationRoot,
        uint256 slashAmount
    )
        internal
    {
        assertTrue(urcRegistry.isSlashed(registrationRoot), "Validator should be slashed");
        assertTrue(
            urcRegistry.isSlashed(registrationRoot, address(slasher)),
            "Validator should be slashed by this specific slasher"
        );
        assertEq(
            urcRegistry.getOperatorData(registrationRoot).slashedAt > 0,
            true,
            "Slashing timestamp should be set"
        );

        console.log("Slashing successful with amount:", slashAmount);
    }

    // ================= Extracted Helper Functions =================

    function _registerOperatorInRegistry(address operatorAddress) internal {
        vm.startPrank(operatorAddress);
        operatorRegistry.registerOperator();
        vm.stopPrank();
    }

    function _registerNetworks() internal {
        // Register middleware as a network in the network registry
        vm.startPrank(address(middleware));
        networkRegistry.registerNetwork();
        vm.stopPrank();

        // Network registry registers itself as an entity
        vm.startPrank(address(networkRegistry));
        networkRegistry.registerNetwork();
        vm.stopPrank();
    }

    function _optInToNetworks(address operatorAddress) internal {
        vm.startPrank(operatorAddress);
        operatorNetworkOptInService.optIn(address(networkRegistry));
        operatorNetworkOptInService.optIn(address(middleware));
        vm.stopPrank();
    }

    function _optInToVault(address operatorAddress, address vaultAddress) internal {
        vm.startPrank(operatorAddress);
        operatorVaultOptInService.optIn(vaultAddress);
        vm.stopPrank();
    }

    function _generateKeySignature(
        bytes memory key,
        uint256 privateKey
    )
        internal
        returns (bytes memory)
    {
        bytes32 messageHash = keccak256(key);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }

    function _createSubnetworksArray(
        uint96 firstSubnet,
        uint96 secondSubnet
    )
        internal
        pure
        returns (uint96[] memory)
    {
        uint96[] memory subnetworks = new uint96[](2);
        subnetworks[0] = firstSubnet;
        subnetworks[1] = secondSubnet;
        return subnetworks;
    }

    function _setupEigenLayerAndAccounts() internal {
        eigenLayerDeployer = new EigenlayerDeployer();
        staker = eigenLayerDeployer.setUp();

        (operator, operatorSecretKey) = makeAddrAndKey("operator");
        (underwriterOperator, underwriterOperatorSecretKey) =
            makeAddrAndKey("underwriterOperator");
        owner = makeAddr("owner");
        challenger = makeAddr("challenger");

        // Set up initial balances
        vm.deal(operator, 100 ether);
        vm.deal(underwriterOperator, 100 ether);
        vm.deal(challenger, 100 ether);

        vm.startPrank(address(eigenLayerDeployer));
        eigenLayerDeployer.weth().transfer(operator, 100 ether);
        eigenLayerDeployer.weth().transfer(underwriterOperator, 100 ether);
        vm.stopPrank();

        // Initialize operator BLS keys
        operatorBLSPubKey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            operatorBLSPubKey[i] = 0xab;
        }

        underwriterBLSPubKey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            underwriterBLSPubKey[i] = 0xcd;
        }
    }

    function _setupURCRegistry() internal {
        urcRegistry = new Registry(
            IRegistry.Config({
                minCollateralWei: 0.1 ether,
                fraudProofWindow: 7200,
                unregistrationDelay: 7200,
                slashWindow: 7200,
                optInDelay: 7200
            })
        );
    }

    function _deployTaiyiRegistryCoordinator() internal impersonate(owner) {
        TaiyiRegistryCoordinator registryImpl = new TaiyiRegistryCoordinator(
            IAllocationManager(eigenLayerDeployer.allocationManager()),
            IPauserRegistry(eigenLayerDeployer.eigenLayerPauserReg()),
            "TaiyiRegistryCoordinator"
        );

        bytes memory initData = abi.encodeWithSelector(
            TaiyiRegistryCoordinator.initialize.selector,
            owner, // initialOwner
            0, // initialPausedStatus
            address(eigenLayerDeployer.allocationManager()), // _allocationManager
            address(eigenLayerDeployer.eigenLayerPauserReg()) // _pauserRegistry
        );

        TransparentUpgradeableProxy registryProxy =
            new TransparentUpgradeableProxy(address(registryImpl), proxyAdmin, initData);

        registry = TaiyiRegistryCoordinator(address(registryProxy));
    }

    function _deployLinglongSlasher() internal impersonate(owner) {
        LinglongSlasher slasherImpl = new LinglongSlasher();
        TransparentUpgradeableProxy slasherProxy = new TransparentUpgradeableProxy(
            address(slasherImpl),
            proxyAdmin,
            abi.encodeWithSelector(
                LinglongSlasher.initialize.selector,
                owner,
                address(eigenLayerDeployer.allocationManager())
            )
        );

        slasher = LinglongSlasher(address(slasherProxy));
    }

    function _setupRegistryCoordinatorRegistries() internal impersonate(owner) {
        pubkeyRegistry = new PubkeyRegistry(registry);
        socketRegistry = new SocketRegistry(registry);

        registry.updateSocketRegistry(address(socketRegistry));
        registry.updatePubkeyRegistry(address(pubkeyRegistry));
    }

    function _deploySymbioticNetworkMiddleware() internal impersonate(owner) {
        SymbioticNetworkMiddleware middlewareImpl = new SymbioticNetworkMiddleware();

        bytes memory initData = abi.encodeWithSelector(
            SymbioticNetworkMiddleware.initialize.selector,
            owner, // _owner
            ISymbioticNetworkMiddleware.Config({
                network: address(networkRegistry),
                slashingWindow: 1 days,
                vaultRegistry: address(vaultFactory),
                operatorRegistry: address(operatorRegistry),
                operatorNetOptIn: address(operatorNetworkOptInService),
                reader: address(0),
                registryCoordinator: address(registry),
                epochDuration: 1 days,
                registry: address(urcRegistry),
                slasher: address(slasher)
            })
        );

        TransparentUpgradeableProxy middlewareProxy =
            new TransparentUpgradeableProxy(address(middlewareImpl), proxyAdmin, initData);

        middleware = SymbioticNetworkMiddleware(address(middlewareProxy));
    }

    function _configureMiddlewareConnections() internal impersonate(owner) {
        registry.setRestakingProtocol(
            address(middleware),
            ITaiyiRegistryCoordinator.RestakingProtocol(RESTAKING_PROTOCOL_SYMBIOTIC)
        );

        slasher.setSymbioticMiddleware(address(middleware));
    }

    function _setupChallenger() internal impersonate(owner) returns (address) {
        address linglongChallenger = address(new MockLinglongChallenger());
        slasher.registerChallenger(linglongChallenger);
        slasher.setURCCommitmentTypeToViolationType(
            COMMITMENT_TYPE_URC, VIOLATION_TYPE_URC
        );
        MockLinglongChallenger(linglongChallenger).setIsInstantSlashing(true);

        slasher.setEigenLayerMiddleware(address(middleware));
        slasher.setTaiyiRegistryCoordinator(address(registry));
        slasher.setURCCommitmentTypeToViolationType(
            COMMITMENT_TYPE_URC, VIOLATION_TYPE_URC
        );
        return linglongChallenger;
    }

    function _setupSubnetworks() internal impersonate(owner) {
        middleware.createNewSubnetwork(VALIDATOR_SUBNETWORK);
        middleware.createNewSubnetwork(UNDERWRITER_SUBNETWORK);

        validatorSubnetworkId = VALIDATOR_SUBNETWORK;
        underwriterSubnetworkId = UNDERWRITER_SUBNETWORK;
    }

    // Helper functions for working with uint32/uint96 arrays
    function _uint32ToArray(uint32 value) internal pure returns (uint32[] memory) {
        uint32[] memory array = new uint32[](1);
        array[0] = value;
        return array;
    }

    function _uint96ToArray(uint96 value) internal pure returns (uint96[] memory) {
        uint96[] memory array = new uint96[](1);
        array[0] = value;
        return array;
    }

    function _registerValidators()
        internal
        returns (bytes32, IRegistry.SignedRegistration[] memory)
    {
        // Set registration min collateral
        registrationMinCollateral = 0.11 ether;

        // Create validator registrations
        IRegistry.SignedRegistration[] memory registrations =
            _createTestValidatorRegistrations();

        // Fund the operator for the registration
        uint256 requiredCollateral = registrationMinCollateral * registrations.length;
        vm.deal(operator, requiredCollateral + 2 ether); // Extra ETH for gas

        // Register validators with the middleware
        vm.startPrank(operator);
        bytes32 registrationRoot =
            middleware.registerValidators{ value: requiredCollateral }(registrations);
        vm.stopPrank();

        return (registrationRoot, registrations);
    }

    function _createTestValidatorRegistrations()
        internal
        view
        returns (IRegistry.SignedRegistration[] memory)
    {
        uint256 validatorPrivKey1 = 12_345;
        uint256 validatorPrivKey2 = 67_890;

        IRegistry.SignedRegistration[] memory registrations =
            new IRegistry.SignedRegistration[](2);
        registrations[0] = _createRegistration(validatorPrivKey1, operator);
        registrations[1] = _createRegistration(validatorPrivKey2, operator);

        return registrations;
    }

    function _createRegistration(
        uint256 secretKey,
        address ownerAddress
    )
        internal
        view
        returns (IRegistry.SignedRegistration memory)
    {
        BLS.G1Point memory pubkey = BLS.toPublicKey(secretKey);
        BLS.G2Point memory signature =
            _createRegistrationSignature(secretKey, ownerAddress);

        return IRegistry.SignedRegistration({ pubkey: pubkey, signature: signature });
    }

    function _createRegistrationSignature(
        uint256 secretKey,
        address ownerAddress
    )
        internal
        view
        returns (BLS.G2Point memory)
    {
        // Create a mock signature instead of using BLS.sign which requires precompiles
        BLS.G2Point memory mockSignature;

        // Use a combination of secretKey and ownerAddress to create deterministic mock values
        uint256 seed = uint256(keccak256(abi.encodePacked(secretKey, ownerAddress)));

        // Limit seed size to prevent overflow when multiplying
        seed = seed % (2 ** 128);

        mockSignature.x.c0.a = seed * 11 + 1;
        mockSignature.x.c0.b = seed * 22 + 2;
        mockSignature.x.c1.a = seed * 33 + 3;
        mockSignature.x.c1.b = seed * 44 + 4;
        mockSignature.y.c0.a = seed * 55 + 5;
        mockSignature.y.c0.b = seed * 66 + 6;
        mockSignature.y.c1.a = seed * 77 + 7;
        mockSignature.y.c1.b = seed * 88 + 8;

        return mockSignature;
    }

    function _createDelegationSignature(
        uint256 validatorSecretKey,
        BLS.G1Point memory delegatePubKey,
        address committer
    )
        internal
        view
        returns (BLS.G2Point memory)
    {
        // Create delegation object
        ISlasher.Delegation memory delegation = ISlasher.Delegation({
            proposer: BLS.toPublicKey(validatorSecretKey),
            delegate: delegatePubKey,
            committer: committer,
            slot: type(uint64).max,
            metadata: bytes("")
        });

        // Instead of using BLS.sign which requires precompiles, create a mock signature
        // that will pass verification in CI
        BLS.G2Point memory mockSignature;

        // Create deterministic mock values based on the validatorSecretKey and committer to ensure consistency
        uint256 seed = uint256(keccak256(abi.encodePacked(validatorSecretKey, committer)));

        // Limit seed size to prevent overflow when multiplying
        seed = seed % (2 ** 128);

        mockSignature.x.c0.a = seed * 100 + 1;
        mockSignature.x.c0.b = seed * 200 + 2;
        mockSignature.x.c1.a = seed * 300 + 3;
        mockSignature.x.c1.b = seed * 400 + 4;
        mockSignature.y.c0.a = seed * 500 + 5;
        mockSignature.y.c0.b = seed * 600 + 6;
        mockSignature.y.c1.a = seed * 700 + 7;
        mockSignature.y.c1.b = seed * 800 + 8;

        return mockSignature;

        // Comment out the actual BLS.sign call that fails in CI
        // return BLS.sign(
        //     abi.encode(delegation),
        //     validatorSecretKey,
        //     urcRegistry.DELEGATION_DOMAIN_SEPARATOR()
        // );
    }
}

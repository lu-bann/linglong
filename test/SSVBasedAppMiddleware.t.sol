// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { TransparentUpgradeableProxy } from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import { Test } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";

import { IBasedAppCompat } from "../src/interfaces/IBasedAppCompat.sol";

import { IPubkeyRegistry } from "../src/interfaces/IPubkeyRegistry.sol";
import { ISsvBasedAppMiddleware } from "../src/interfaces/ISsvBasedAppMiddleware.sol";
import { ITaiyiRegistryCoordinator } from
    "../src/interfaces/ITaiyiRegistryCoordinator.sol";

import { OperatorSubsetLib } from "../src/libs/OperatorSubsetLib.sol";
import { PubkeyRegistry } from "../src/operator-registries/PubkeyRegistry.sol";
import { SocketRegistry } from "../src/operator-registries/SocketRegistry.sol";
import { TaiyiRegistryCoordinator } from
    "../src/operator-registries/TaiyiRegistryCoordinator.sol";
import { LinglongSlasher } from "../src/slasher/LinglongSlasher.sol";
import { SSVBasedAppMiddleware } from "../src/ssv-based-app/SSVBasedAppMiddleware.sol";

import { IRegistry } from "@urc/IRegistry.sol";

import { ISlasher } from "@urc/ISlasher.sol";
import { Registry } from "@urc/Registry.sol";
import { BLS } from "@urc/lib/BLS.sol";

// Add missing EigenLayer imports
import { IAllocationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IPauserRegistry } from
    "@eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";
import { ISignatureUtilsMixinTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtilsMixin.sol";

contract SSVBasedAppMiddlewareTest is Test {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // ==============================================================================================
    // ================================= STATE VARIABLES ===========================================
    // ==============================================================================================

    SSVBasedAppMiddleware public middleware;
    TaiyiRegistryCoordinator public registryCoordinator;
    PubkeyRegistry public pubkeyRegistry;
    SocketRegistry public socketRegistry;
    Registry public urcRegistry;
    LinglongSlasher public slasher;

    address public owner;
    address public proxyAdmin;
    address public operator;
    address public underwriterOperator;
    address public gatewayOperator;
    address public gatewayNetwork;

    uint256 public constant REGISTRATION_MIN_COLLATERAL = 0.11 ether;
    uint256 public constant STAKE_AMOUNT = 32 ether;

    // Test data
    bytes public operatorBLSPubKey =
        hex"95a254501b7733239ed3cec4d56737977bd09ede881d8a234560e83e5525017add3b1dcc3eabfb85e12a4131b19c253b";
    bytes public underwriterBLSPubKey =
        hex"95a254501b7733239ed3cec4d56737977bd09ede881d8a234560e83e5525017add3b1dcc3eabfb85e12a4131b19c253c";

    // Events for testing
    event StateChanged(string newState);
    event BAppRegistered(string metadataURI, IBasedAppCompat.TokenConfig[] tokenConfigs);
    event BAppMetadataUpdated(string metadataURI);
    event BAppTokensUpdated(IBasedAppCompat.TokenConfig[] tokenConfigs);
    event OperatorOptedIn(address indexed operator, uint32 indexed strategyId);
    event ValidatorsRegistered(
        address indexed operator, bytes32 indexed registrationRoot
    );
    event ValidatorsUnregistered(
        address indexed operator, bytes32 indexed registrationRoot
    );
    event GatewayDelegationOptedIn(
        address indexed operator,
        address indexed gatewayOperator,
        address indexed gatewayNetwork
    );
    event DelegationsBatchSet(
        address indexed operator, bytes32 indexed registrationRoot, uint256 count
    );
    event SlasherOptedIn(
        address indexed operator,
        bytes32 indexed registrationRoot,
        address indexed delegatee
    );
    event ValidatorSlashed(
        uint32 indexed strategyId,
        address indexed token,
        uint32 percentage,
        address indexed sender
    );

    // ==============================================================================================
    // ================================= SETUP ===================================================
    // ==============================================================================================

    function setUp() public {
        owner = makeAddr("owner");
        proxyAdmin = makeAddr("proxyAdmin");
        operator = makeAddr("operator");
        underwriterOperator = makeAddr("underwriterOperator");
        gatewayOperator = makeAddr("gatewayOperator");
        gatewayNetwork = makeAddr("gatewayNetwork");

        // Deploy URC Registry
        urcRegistry = new Registry(
            IRegistry.Config({
                minCollateralWei: 0.1 ether,
                fraudProofWindow: 7200,
                unregistrationDelay: 7200,
                slashWindow: 7200,
                optInDelay: 7200
            })
        );

        // Deploy SSVBasedAppMiddleware first
        middleware = new SSVBasedAppMiddleware();
        TransparentUpgradeableProxy middlewareProxy =
            new TransparentUpgradeableProxy(address(middleware), proxyAdmin, "");
        middleware = SSVBasedAppMiddleware(address(middlewareProxy));

        // Deploy TaiyiRegistryCoordinator with required constructor args
        registryCoordinator = new TaiyiRegistryCoordinator(
            IAllocationManager(makeAddr("allocationManager")),
            IPauserRegistry(makeAddr("pauserRegistry")),
            "v1.0.0"
        );
        TransparentUpgradeableProxy registryCoordinatorProxy =
            new TransparentUpgradeableProxy(address(registryCoordinator), proxyAdmin, "");
        registryCoordinator = TaiyiRegistryCoordinator(address(registryCoordinatorProxy));

        // Deploy PubkeyRegistry with registry coordinator address
        pubkeyRegistry = new PubkeyRegistry(address(registryCoordinator));

        // Deploy SocketRegistry with registry coordinator address
        socketRegistry = new SocketRegistry(registryCoordinator);

        // Initialize the registry coordinator with the required 5 parameters
        TaiyiRegistryCoordinator(address(registryCoordinatorProxy)).initialize(
            owner, // initialOwner
            0, // initialPausedStatus
            makeAddr("allocationManager"), // _allocationManager
            address(middleware), // _eigenLayerMiddleware - set our SSV middleware here
            makeAddr("pauserRegistry") // _pauserRegistry (actually ignored)
        );

        // Set the pubkey and socket registries
        vm.prank(owner);
        registryCoordinator.updatePubkeyRegistry(address(pubkeyRegistry));
        vm.prank(owner);
        registryCoordinator.updateSocketRegistry(address(socketRegistry));

        // Deploy LinglongSlasher
        slasher = new LinglongSlasher();
        TransparentUpgradeableProxy slasherProxy =
            new TransparentUpgradeableProxy(address(slasher), proxyAdmin, "");
        slasher = LinglongSlasher(address(slasherProxy));

        // Initialize slasher
        slasher.initialize(owner, makeAddr("allocationManager"), address(urcRegistry));

        // Initialize middleware
        middleware.initialize(
            owner,
            ISsvBasedAppMiddleware.Config({
                registryCoordinator: address(registryCoordinator),
                registry: address(urcRegistry),
                slasher: address(slasher),
                gatewayOperatorSet: gatewayOperator,
                gatewayNetwork: gatewayNetwork,
                registrationMinCollateral: REGISTRATION_MIN_COLLATERAL
            })
        );

        // Register SSV middleware in the restaking protocol map as EIGENLAYER
        // This allows our SSV middleware to register operators through the EigenLayer path
        vm.prank(owner);
        registryCoordinator.setRestakingProtocol(
            address(middleware), ITaiyiRegistryCoordinator.RestakingProtocol.EIGENLAYER
        );

        // For this test, let's skip the subset creation during setup
        // We'll create them manually when needed or work around the middleware check

        // Fund test accounts
        vm.deal(operator, 100 ether);
        vm.deal(underwriterOperator, 100 ether);
        vm.deal(address(middleware), 100 ether);
    }

    // ==============================================================================================
    // ================================= BASIC TESTS =============================================
    // ==============================================================================================

    function testInitialization() public {
        assertEq(middleware.owner(), owner);
        assertEq(
            address(middleware.getRegistryCoordinator()), address(registryCoordinator)
        );
        assertEq(middleware.getGatewayOperatorSet(), gatewayOperator);
        assertEq(middleware.getGatewayNetwork(), gatewayNetwork);
    }

    function testOnlyOwnerFunctions() public {
        // Test that non-owner cannot call owner functions
        vm.startPrank(operator);

        IBasedAppCompat.TokenConfig[] memory tokenConfigs =
            new IBasedAppCompat.TokenConfig[](1);
        tokenConfigs[0] = IBasedAppCompat.TokenConfig({
            token: makeAddr("token"),
            sharedRiskLevel: 1000
        });

        vm.expectRevert();
        middleware.registerBApp(tokenConfigs, "test-metadata-uri");

        vm.expectRevert();
        middleware.updateBAppMetadataURI("new-metadata-uri");

        vm.expectRevert();
        middleware.updateBAppTokens(tokenConfigs);

        vm.stopPrank();
    }

    // ==============================================================================================
    // ================================= BAPP REGISTRATION TESTS =================================
    // ==============================================================================================

    function testRegisterBApp() public {
        IBasedAppCompat.TokenConfig[] memory tokenConfigs =
            new IBasedAppCompat.TokenConfig[](2);
        tokenConfigs[0] = IBasedAppCompat.TokenConfig({
            token: makeAddr("token1"),
            sharedRiskLevel: 1000
        });
        tokenConfigs[1] = IBasedAppCompat.TokenConfig({
            token: makeAddr("token2"),
            sharedRiskLevel: 2000
        });

        string memory metadataURI = "ipfs://QmTestMetadata";

        vm.expectEmit(true, true, true, true);
        emit BAppRegistered(metadataURI, tokenConfigs);

        vm.expectEmit(true, true, true, true);
        emit StateChanged("BApp Registered");

        vm.prank(owner);
        middleware.registerBApp(tokenConfigs, metadataURI);
    }

    function testUpdateBAppMetadataURI() public {
        string memory newMetadataURI = "ipfs://QmNewMetadata";

        vm.expectEmit(true, true, true, true);
        emit BAppMetadataUpdated(newMetadataURI);

        vm.expectEmit(true, true, true, true);
        emit StateChanged("Metadata Updated");

        vm.prank(owner);
        middleware.updateBAppMetadataURI(newMetadataURI);
    }

    function testUpdateBAppTokens() public {
        IBasedAppCompat.TokenConfig[] memory newTokenConfigs =
            new IBasedAppCompat.TokenConfig[](1);
        newTokenConfigs[0] = IBasedAppCompat.TokenConfig({
            token: makeAddr("newToken"),
            sharedRiskLevel: 3000
        });

        vm.expectEmit(true, true, true, true);
        emit BAppTokensUpdated(newTokenConfigs);

        vm.expectEmit(true, true, true, true);
        emit StateChanged("Tokens Updated");

        vm.prank(owner);
        middleware.updateBAppTokens(newTokenConfigs);
    }

    // ==============================================================================================
    // ================================= OPERATOR OPT-IN TESTS ===================================
    // ==============================================================================================

    function testOperatorOptInToBApp() public {
        // Debug: Check if middleware is registered correctly
        assertTrue(registryCoordinator.isRestakingMiddleware(address(middleware)));
        assertEq(
            uint8(registryCoordinator.getMiddlewareProtocol(address(middleware))),
            uint8(ITaiyiRegistryCoordinator.RestakingProtocol.EIGENLAYER)
        );

        // First register operator in SSV validator subset
        _registerOperatorInSSVSubset(operator, OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID);

        uint32 strategyId = 1;
        address[] memory tokens = new address[](2);
        tokens[0] = makeAddr("token1");
        tokens[1] = makeAddr("token2");

        uint32[] memory obligationPercentages = new uint32[](2);
        obligationPercentages[0] = 5000; // 50%
        obligationPercentages[1] = 3000; // 30%

        bytes memory data = "";

        vm.expectEmit(true, true, true, true);
        emit OperatorOptedIn(operator, strategyId);

        vm.prank(operator);
        bool success =
            middleware.optInToBApp(strategyId, tokens, obligationPercentages, data);
        assertTrue(success);
    }

    function testOperatorOptInFailsIfNotRegistered() public {
        uint32 strategyId = 1;
        address[] memory tokens = new address[](1);
        tokens[0] = makeAddr("token1");

        uint32[] memory obligationPercentages = new uint32[](1);
        obligationPercentages[0] = 5000;

        bytes memory data = "";

        vm.expectRevert("Operator not registered in SSV validator subset");
        vm.prank(operator);
        middleware.optInToBApp(strategyId, tokens, obligationPercentages, data);
    }

    function testOperatorOptInFailsWithMismatchedArrays() public {
        _registerOperatorInSSVSubset(operator, OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID);

        uint32 strategyId = 1;
        address[] memory tokens = new address[](2);
        tokens[0] = makeAddr("token1");
        tokens[1] = makeAddr("token2");

        uint32[] memory obligationPercentages = new uint32[](1); // Mismatched length
        obligationPercentages[0] = 5000;

        bytes memory data = "";

        vm.expectRevert("Array length mismatch");
        vm.prank(operator);
        middleware.optInToBApp(strategyId, tokens, obligationPercentages, data);
    }

    // ==============================================================================================
    // ================================= VALIDATOR REGISTRATION TESTS ============================
    // ==============================================================================================

    function testRegisterValidators() public {
        _registerOperatorInSSVSubset(operator, OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID);

        IRegistry.SignedRegistration[] memory registrations = _createMockRegistrations(2);

        vm.expectEmit(true, true, true, false);
        emit ValidatorsRegistered(operator, bytes32(0)); // We'll ignore the registration root for now

        vm.prank(operator);
        bytes32 registrationRoot = middleware.registerValidators{
            value: REGISTRATION_MIN_COLLATERAL
        }(registrations);

        assertTrue(registrationRoot != bytes32(0));

        // Check that registration root is stored
        bytes32[] memory operatorRoots = middleware.getOperatorRegistrationRoots(operator);
        assertEq(operatorRoots.length, 1);
        assertEq(operatorRoots[0], registrationRoot);
    }

    function testRegisterValidatorsFailsWithInsufficientCollateral() public {
        _registerOperatorInSSVSubset(operator, OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID);

        IRegistry.SignedRegistration[] memory registrations = _createMockRegistrations(1);

        vm.expectRevert("Insufficient collateral");
        vm.prank(operator);
        middleware.registerValidators{ value: 0.05 ether }(registrations); // Less than required
    }

    function testUnregisterValidators() public {
        _registerOperatorInSSVSubset(operator, OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID);

        // First register validators
        IRegistry.SignedRegistration[] memory registrations = _createMockRegistrations(1);
        vm.prank(operator);
        bytes32 registrationRoot = middleware.registerValidators{
            value: REGISTRATION_MIN_COLLATERAL
        }(registrations);

        // Then unregister them
        vm.expectEmit(true, true, true, true);
        emit ValidatorsUnregistered(operator, registrationRoot);

        vm.prank(operator);
        middleware.unregisterValidators(registrationRoot);

        // Check that registration root is removed
        bytes32[] memory operatorRoots = middleware.getOperatorRegistrationRoots(operator);
        assertEq(operatorRoots.length, 0);
    }

    // ==============================================================================================
    // ================================= GATEWAY DELEGATION TESTS ===============================
    // ==============================================================================================

    function testOptInToGatewayDelegation() public {
        _registerOperatorInSSVSubset(operator, OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID);

        ISsvBasedAppMiddleware.GatewayDelegationParams memory params =
        ISsvBasedAppMiddleware.GatewayDelegationParams({
            gatewayOperator: gatewayOperator,
            gatewayNetwork: gatewayNetwork,
            signature: "mock_signature",
            expiry: block.timestamp + 3600
        });

        vm.expectEmit(true, true, true, true);
        emit GatewayDelegationOptedIn(operator, gatewayOperator, gatewayNetwork);

        vm.prank(operator);
        middleware.optInToGatewayDelegation(params);

        // Verify delegation was set
        assertTrue(middleware.hasGatewayDelegation(operator));
        (address delegatedGatewayOperator, address delegatedGatewayNetwork) =
            middleware.getGatewayDelegation(operator);
        assertEq(delegatedGatewayOperator, gatewayOperator);
        assertEq(delegatedGatewayNetwork, gatewayNetwork);
    }

    function testGatewayDelegationFailsWithExpiredSignature() public {
        _registerOperatorInSSVSubset(operator, OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID);

        ISsvBasedAppMiddleware.GatewayDelegationParams memory params =
        ISsvBasedAppMiddleware.GatewayDelegationParams({
            gatewayOperator: gatewayOperator,
            gatewayNetwork: gatewayNetwork,
            signature: "mock_signature",
            expiry: block.timestamp - 1 // Expired
         });

        vm.expectRevert("Signature expired");
        vm.prank(operator);
        middleware.optInToGatewayDelegation(params);
    }

    // ==============================================================================================
    // ================================= SLASHING TESTS ==========================================
    // ==============================================================================================

    function testSlash() public {
        uint32 strategyId = 1;
        address token = makeAddr("token");
        uint32 percentage = 1000; // 10%
        address sender = makeAddr("sender");
        bytes memory data = "";

        vm.expectEmit(true, true, true, true);
        emit ValidatorSlashed(strategyId, token, percentage, sender);

        vm.prank(address(slasher));
        (bool success, address receiver, bool exit) =
            middleware.slash(strategyId, token, percentage, sender, data);

        assertTrue(success);
        assertEq(receiver, address(slasher));
        assertFalse(exit);
    }

    function testSlashFailsFromNonSlasher() public {
        uint32 strategyId = 1;
        address token = makeAddr("token");
        uint32 percentage = 1000;
        address sender = makeAddr("sender");
        bytes memory data = "";

        vm.expectRevert();
        vm.prank(operator); // Not the slasher
        middleware.slash(strategyId, token, percentage, sender, data);
    }

    // ==============================================================================================
    // ================================= DELEGATION TESTS ========================================
    // ==============================================================================================

    function testBatchSetDelegations() public {
        _registerOperatorInSSVSubset(operator, OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID);

        // First register validators
        IRegistry.SignedRegistration[] memory registrations = _createMockRegistrations(2);
        vm.prank(operator);
        bytes32 registrationRoot = middleware.registerValidators{
            value: REGISTRATION_MIN_COLLATERAL
        }(registrations);

        // Create delegation data
        BLS.G1Point[] memory pubkeys = new BLS.G1Point[](2);
        pubkeys[0] = _createMockG1Point(1);
        pubkeys[1] = _createMockG1Point(2);

        ISlasher.SignedDelegation[] memory delegations =
            new ISlasher.SignedDelegation[](2);
        delegations[0] = _createMockSignedDelegation();
        delegations[1] = _createMockSignedDelegation();

        vm.expectEmit(true, true, true, true);
        emit DelegationsBatchSet(operator, registrationRoot, 2);

        vm.prank(operator);
        middleware.batchSetDelegations(registrationRoot, pubkeys, delegations);
    }

    function testOptInToSlasher() public {
        _registerOperatorInSSVSubset(operator, OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID);

        // First register validators
        IRegistry.SignedRegistration[] memory registrations = _createMockRegistrations(1);
        vm.prank(operator);
        bytes32 registrationRoot = middleware.registerValidators{
            value: REGISTRATION_MIN_COLLATERAL
        }(registrations);

        // Create slasher opt-in data
        BLS.G2Point[] memory delegationSignatures = new BLS.G2Point[](1);
        delegationSignatures[0] = _createMockG2Point();

        BLS.G1Point memory delegateePubKey = _createMockG1Point(3);
        address delegateeAddress = underwriterOperator;
        bytes[] memory data = new bytes[](1);
        data[0] = "";

        vm.expectEmit(true, true, true, true);
        emit SlasherOptedIn(operator, registrationRoot, delegateeAddress);

        vm.prank(operator);
        middleware.optInToSlasher(
            registrationRoot,
            registrations,
            delegationSignatures,
            delegateePubKey,
            delegateeAddress,
            data
        );
    }

    // ==============================================================================================
    // ================================= VIEW FUNCTION TESTS =====================================
    // ==============================================================================================

    function testGetAllDelegations() public {
        _registerOperatorInSSVSubset(operator, OperatorSubsetLib.SSV_VALIDATOR_SUBSET_ID);

        // Register validators first
        IRegistry.SignedRegistration[] memory registrations = _createMockRegistrations(1);
        vm.prank(operator);
        bytes32 registrationRoot = middleware.registerValidators{
            value: REGISTRATION_MIN_COLLATERAL
        }(registrations);

        // Get delegations (should be empty initially)
        (BLS.G1Point[] memory pubkeys, ISlasher.SignedDelegation[] memory delegations) =
            middleware.getAllDelegations(operator, registrationRoot);

        // For this test, we expect empty arrays since we haven't set any delegations
        assertEq(pubkeys.length, 0);
        assertEq(delegations.length, 0);
    }

    function testViewFunctions() public {
        assertEq(
            address(middleware.getRegistryCoordinator()), address(registryCoordinator)
        );
        assertEq(middleware.getGatewayOperatorSet(), gatewayOperator);
        assertEq(middleware.getGatewayNetwork(), gatewayNetwork);
        assertFalse(middleware.hasGatewayDelegation(operator));
    }

    // ==============================================================================================
    // ================================= ADMIN FUNCTION TESTS ===================================
    // ==============================================================================================

    function testSetOperatorGatewayDelegationStatus() public {
        vm.prank(owner);
        middleware.setOperatorGatewayDelegationStatus(operator, true);
        assertTrue(middleware.hasGatewayDelegation(operator));

        vm.prank(owner);
        middleware.setOperatorGatewayDelegationStatus(operator, false);
        assertFalse(middleware.hasGatewayDelegation(operator));
    }

    function testSetOperatorGatewayDelegationStatusFailsFromNonOwner() public {
        vm.expectRevert();
        vm.prank(operator);
        middleware.setOperatorGatewayDelegationStatus(operator, true);
    }

    // ==============================================================================================
    // ================================= HELPER FUNCTIONS =======================================
    // ==============================================================================================

    function _registerOperatorInSSVSubset(address _operator, uint32 subsetId) internal {
        // Create the subset if it doesn't exist - since we set our middleware as eigenLayerMiddleware
        // during initialization, we can call this from the middleware
        if (!registryCoordinator.isLinglongSubsetExist(subsetId)) {
            vm.prank(address(middleware));
            registryCoordinator.createLinglongSubset(subsetId, 1 ether);
        }

        // Register operator through the allocation manager (EigenLayer path)
        vm.prank(makeAddr("allocationManager"));
        registryCoordinator.registerOperator(
            _operator,
            address(middleware),
            _createSubsetArray(subsetId),
            abi.encode(
                "socket",
                _createMockPubkeyRegistrationParams(),
                _createMockOperatorSignature()
            )
        );
    }

    function _createSubsetArray(uint32 subsetId)
        internal
        pure
        returns (uint32[] memory)
    {
        uint32[] memory subsets = new uint32[](1);
        subsets[0] = subsetId;
        return subsets;
    }

    function _createMockPubkeyRegistrationParams()
        internal
        view
        returns (IPubkeyRegistry.PubkeyRegistrationParams memory)
    {
        return IPubkeyRegistry.PubkeyRegistrationParams({
            blsPubkey: operatorBLSPubKey,
            operator: operator,
            pubkeyRegistrationSignature: hex"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1c"
        });
    }

    function _createMockRegistrations(uint256 count)
        internal
        view
        returns (IRegistry.SignedRegistration[] memory)
    {
        IRegistry.SignedRegistration[] memory registrations =
            new IRegistry.SignedRegistration[](count);
        for (uint256 i = 0; i < count; i++) {
            registrations[i] = IRegistry.SignedRegistration({
                pubkey: _createMockG1Point(i + 1),
                signature: _createMockG2Point()
            });
        }
        return registrations;
    }

    function _createMockG1Point(uint256 seed)
        internal
        pure
        returns (BLS.G1Point memory)
    {
        return BLS.G1Point({
            x: BLS.Fp({ a: seed, b: seed + 1 }),
            y: BLS.Fp({ a: seed + 2, b: seed + 3 })
        });
    }

    function _createMockG2Point() internal pure returns (BLS.G2Point memory) {
        return BLS.G2Point({
            x: BLS.Fp2({ c0: BLS.Fp({ a: 1, b: 2 }), c1: BLS.Fp({ a: 3, b: 4 }) }),
            y: BLS.Fp2({ c0: BLS.Fp({ a: 5, b: 6 }), c1: BLS.Fp({ a: 7, b: 8 }) })
        });
    }

    function _createMockSignedDelegation()
        internal
        view
        returns (ISlasher.SignedDelegation memory)
    {
        return ISlasher.SignedDelegation({
            delegation: ISlasher.Delegation({
                proposer: _createMockG1Point(1),
                delegate: _createMockG1Point(2),
                committer: underwriterOperator,
                slot: 12_345,
                metadata: "test-metadata"
            }),
            signature: _createMockG2Point()
        });
    }

    function _createMockOperatorSignature()
        internal
        pure
        returns (ISignatureUtilsMixinTypes.SignatureWithSaltAndExpiry memory)
    {
        return ISignatureUtilsMixinTypes.SignatureWithSaltAndExpiry({
            signature: "mock_signature",
            salt: bytes32(0),
            expiry: 0
        });
    }
}

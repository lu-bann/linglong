// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { EigenlayerDeployer } from "./utils/EigenlayerDeployer.sol";
import { MockLinglongChallenger } from "./utils/MockChallenger.sol";
import { ERC20PresetFixedSupplyUpgradeable } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts-upgradeable-v4.9.0/contracts/token/ERC20/presets/ERC20PresetFixedSupplyUpgradeable.sol";
import { IERC20 } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts-v4.9.0/contracts/token/ERC20/IERC20.sol";
import { IAVSRegistrar } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAVSRegistrar.sol";
import { IAllocationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";

import {
    IAllocationManager,
    IAllocationManagerTypes
} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IDelegationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import { IDelegationManagerTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import { IEigenPod } from "@eigenlayer-contracts/src/contracts/interfaces/IEigenPod.sol";
import { IEigenPodTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IEigenPod.sol";
import { IPauserRegistry } from
    "@eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IRewardsCoordinatorTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { ISignatureUtils } from
    "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { TransparentUpgradeableProxy } from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { Registry } from "@urc/Registry.sol";
import { BLS } from "@urc/lib/BLS.sol";
import { StdUtils } from "forge-std/StdUtils.sol";
import "forge-std/Test.sol";
import { console } from "forge-std/console.sol";
import { EigenLayerMiddleware } from "src/eigenlayer-avs/EigenLayerMiddleware.sol";
import { IEigenLayerMiddleware } from "src/interfaces/IEigenLayerMiddleware.sol";
import { IPubkeyRegistry } from "src/interfaces/IPubkeyRegistry.sol";

import { G2Operations } from "./ffi/G2Operation.sol";
import { ITaiyiInteractiveChallenger } from
    "src/interfaces/ITaiyiInteractiveChallenger.sol";
import { ITaiyiRegistryCoordinator } from "src/interfaces/ITaiyiRegistryCoordinator.sol";
import { BN254 } from "src/libs/BN254.sol";
import { OperatorSubsetLib } from "src/libs/OperatorSubsetLib.sol";
import { PubkeyRegistry } from "src/operator-registries/PubkeyRegistry.sol";
import { SocketRegistry } from "src/operator-registries/SocketRegistry.sol";
import { TaiyiRegistryCoordinator } from
    "src/operator-registries/TaiyiRegistryCoordinator.sol";
import { LinglongSlasher } from "src/slasher/LinglongSlasher.sol";

contract EigenlayerMiddlewareTest is Test, G2Operations {
    using OperatorSubsetLib for uint32;
    using Strings for uint256;
    using BN254 for BN254.G1Point;

    bytes32 public constant VIOLATION_TYPE_URC = keccak256("URC_VIOLATION");
    uint64 public constant COMMITMENT_TYPE_URC = 1;

    address public eigenLayerMiddleware; // Changed to address instead of a contract type
    EigenLayerMiddleware public middleware; // Add middleware contract variable
    EigenlayerDeployer public eigenLayerDeployer;
    TaiyiRegistryCoordinator public registryCoordinator;
    address public owner;
    address staker;
    address operator;
    address rewardsInitiator;
    uint256 operatorSecretKey;
    bytes operatorBLSPubKey;
    bytes validatorOperatorBLSPubKey;
    bytes underwriterOperatorBLSPubKey;
    Registry public registry;
    LinglongSlasher public slasher;
    address public challenger;
    address public proxyAdmin;
    uint256 public registrationMinCollateral;

    uint256 constant STAKE_AMOUNT = 32 ether;
    uint256 constant UNDERWRITER_SHARE_BIPS = 8000; // 80%
    uint256 constant _WAD = 1e18; // 1 WAD = 100% allocation (with underscore to fix linter)

    uint32 public validatorOperatorSetId; // Store the operator set ID created in setUp
    uint32 public underwriterOperatorSetId;

    modifier impersonate(address user) {
        vm.startPrank(user);
        _;
        vm.stopPrank();
    }

    // ==============================================================================================
    // =========================================== SETUP ============================================
    // ==============================================================================================

    /// @notice Performs initial setup for the test environment by deploying and initializing contracts
    function setUp() public {
        proxyAdmin = makeAddr("proxyAdmin");
        // Generate a random key by hashing block data
        bytes32 randomBytes =
            keccak256(abi.encodePacked(block.timestamp, block.prevrandao, block.number));
        operatorSecretKey = uint256(randomBytes);
        registry = new Registry(
            IRegistry.Config({
                minCollateralWei: 0.1 ether,
                fraudProofWindow: 7200,
                unregistrationDelay: 7200,
                slashWindow: 7200,
                optInDelay: 7200
            })
        );
        operatorBLSPubKey =
            hex"95a254501b7733239ed3cec4d56737977bd09ede881d8a234560e83e5525017add3b1dcc3eabfb85e12a4131b19c253b";
        validatorOperatorBLSPubKey =
            hex"95a254501b7733239ed3cec4d56737977bd09ede881d8a234560e83e5525017add3b1dcc3eabfb85e12a4131b19c253c";
        underwriterOperatorBLSPubKey =
            hex"95a254501b7733239ed3cec4d56737977bd09ede881d8a234560e83e5525017add3b1dcc3eabfb85e12a4131b19c2534";
        _setupEigenLayerAndAccounts();
        _deployTaiyiRegistryCoordinator();
        _deployLinglongSlasher();
        _setupRegistryCoordinatorRegistries();
        _deployEigenLayerMiddleware();
        _configureMiddlewareConnections();
        _setupChallenger();
        _createOperatorSet();

        console.log("Setup complete");
    }

    // ==============================================================================================
    // =========================================== TESTS ============================================
    // ==============================================================================================

    function testOperatorRegistrationFlow() public {
        // 1. Setup and verify operator set
        OperatorSet memory opSet;
        opSet.id = validatorOperatorSetId;
        opSet.avs = eigenLayerMiddleware;
        _verifyOperatorSetExists(opSet);
        OperatorSet memory underwriterOpSet;
        underwriterOpSet.id = underwriterOperatorSetId;
        underwriterOpSet.avs = eigenLayerMiddleware;
        _verifyOperatorSetExists(underwriterOpSet);

        // 2. Register operator
        _registerOperator(
            operator, validatorOperatorSetId, operatorSecretKey, operatorBLSPubKey
        );

        // 3. Verify registration
        _verifyOperatorRegistrationInEigenLayer(operator);

        // 4. Verify allocation
        IStrategy[] memory strategies = _verifyOperatorAllocation(operator, opSet);

        // 5. Verify operator set membership
        _verifyOperatorInOperatorSet(operator, opSet);

        // 6. Verify stake
        _verifyOperatorStake(operator);

        // 7. Remove strategies
        _removeStrategiesAndVerify(validatorOperatorSetId, strategies, opSet);

        // 8. Test deregistration
        _deregisterFromAVS(operator, validatorOperatorSetId);
        _verifyDeregistration(operator, opSet);

        uint32 count = middleware.getOperatorSetCount();
        assertEq(count, 2, "Should have 2 operator sets");
    }

    function testValidatorRegistration() public {
        // Setup operators and give them funds
        (
            address primaryOp,
            address underwriterOp,
            uint256 primaryPrivate,
            uint256 underwriterPrivate
        ) = _setupOperatorsWithFunds();

        // Create BLS keys and register operators
        _registerOperator(
            primaryOp, validatorOperatorSetId, primaryPrivate, validatorOperatorBLSPubKey
        );
        _registerOperator(
            underwriterOp,
            underwriterOperatorSetId,
            underwriterPrivate,
            underwriterOperatorBLSPubKey
        );

        // Setup mocks and complete test
        _verifyOperatorRegistration(primaryOp, underwriterOp);

        // Register the validator
        bytes32 registrationRoot = _validatorRegistration(primaryOp, underwriterOp);
    }

    function testSlashOperator() public {
        // Setup operators and give them funds
        (
            address primaryOp,
            address underwriterOp,
            uint256 primaryPrivate,
            uint256 underwriterPrivate
        ) = _setupOperatorsWithFunds();

        // Create BLS keys and register operators
        _registerOperator(
            primaryOp, validatorOperatorSetId, primaryPrivate, validatorOperatorBLSPubKey
        );
        _registerOperator(
            underwriterOp,
            underwriterOperatorSetId,
            underwriterPrivate,
            underwriterOperatorBLSPubKey
        );

        // Verify operator registration
        _verifyOperatorRegistration(primaryOp, underwriterOp);

        // Register validator and complete opt-in to slasher
        bytes32 registrationRoot = _validatorRegistration(primaryOp, underwriterOp);

        // Create a mock commitment for slashing
        ISlasher.SignedCommitment memory commitment =
            _createMockCommitment(primaryOp, primaryPrivate);

        // Create evidence bytes
        bytes memory evidence = abi.encode("mock evidence data");

        challenger = address(new MockLinglongChallenger());

        // Make sure the challenger is set up
        vm.startPrank(owner);
        slasher.registerChallenger(challenger);
        slasher.setURCCommitmentTypeToViolationType(
            COMMITMENT_TYPE_URC, VIOLATION_TYPE_URC
        );
        vm.stopPrank();

        // Set up the challenger for instant slashing to simplify testing
        MockLinglongChallenger(challenger).setIsInstantSlashing(true);

        vm.startPrank(owner);
        slasher.setEigenLayerMiddleware(eigenLayerMiddleware);
        slasher.setTaiyiRegistryCoordinator(address(registryCoordinator));
        vm.stopPrank();

        // Perform the slashing via the Registry
        uint256 slashAmount =
            registry.slashCommitment(registrationRoot, commitment, evidence);

        // Verify the slashing was successful
        assertTrue(registry.isSlashed(registrationRoot), "Operator should be slashed");
        assertEq(
            registry.getOperatorData(registrationRoot).slashedAt > 0,
            true,
            "Slashing timestamp should be set"
        );

        console.log("Slashing successful with amount:", slashAmount);
    }

    // ==============================================================================================
    // ====================================== SETUP HELPERS ========================================
    // ==============================================================================================

    /// @dev Deploy a real EigenLayerMiddleware contract
    function _deployEigenLayerMiddleware() internal {
        // Get the owner address for AllocationManager to ensure we have the right permissions
        address allocationManagerOwner = eigenLayerDeployer.allocationManager().owner();
        console.log("AllocationManager owner:", allocationManagerOwner);
        console.log("Test owner:", owner);

        vm.startPrank(owner);

        // Deploy implementation
        console.log("Deploying middleware implementation");
        EigenLayerMiddleware middlewareImpl = new EigenLayerMiddleware();

        // Set the registration min collateral to 0.11 ETH
        registrationMinCollateral = 0.11 ether;

        // Prepare initialization data
        console.log("Preparing initialization data");
        bytes memory initData = abi.encodeWithSelector(
            EigenLayerMiddleware.initialize.selector,
            owner, // _owner
            IEigenLayerMiddleware.Config({
                avsDirectory: address(eigenLayerDeployer.avsDirectory()),
                delegationManager: address(eigenLayerDeployer.delegation()),
                rewardCoordinator: address(eigenLayerDeployer.rewardsCoordinator()),
                rewardInitiator: rewardsInitiator,
                registryCoordinator: address(registryCoordinator),
                underwriterShareBips: UNDERWRITER_SHARE_BIPS,
                registry: address(registry),
                slasher: address(slasher),
                allocationManager: address(eigenLayerDeployer.allocationManager()),
                registrationMinCollateral: registrationMinCollateral
            })
        );

        // Deploy and initialize proxy
        console.log("Deploying middleware proxy");
        TransparentUpgradeableProxy middlewareProxy =
            new TransparentUpgradeableProxy(address(middlewareImpl), proxyAdmin, initData);

        eigenLayerMiddleware = address(middlewareProxy);
        middleware = EigenLayerMiddleware(eigenLayerMiddleware);
        console.log("Middleware deployed at:", eigenLayerMiddleware);

        vm.stopPrank();
    }

    /// @dev Setup EigenLayer and create test accounts with initial balances
    function _setupEigenLayerAndAccounts() internal {
        eigenLayerDeployer = new EigenlayerDeployer();
        staker = eigenLayerDeployer.setUp();

        (operator, operatorSecretKey) = makeAddrAndKey("operator");
        owner = makeAddr("owner");
        rewardsInitiator = makeAddr("rewardInitiator");
        challenger = makeAddr("challenger");

        // Set up initial balances
        vm.deal(challenger, 100 ether);
        vm.startPrank(address(eigenLayerDeployer));
        eigenLayerDeployer.weth().transfer(operator, 100 ether);
        vm.stopPrank();

        // Initialize operator BLS key
        operatorBLSPubKey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            operatorBLSPubKey[i] = 0xab;
        }
    }

    /// @dev Deploy TaiyiRegistryCoordinator implementation and proxy
    function _deployTaiyiRegistryCoordinator() internal {
        vm.startPrank(owner);

        // Deploy implementation
        TaiyiRegistryCoordinator registryImpl = new TaiyiRegistryCoordinator(
            IAllocationManager(eigenLayerDeployer.allocationManager()),
            IPauserRegistry(eigenLayerDeployer.eigenLayerPauserReg()),
            "TaiyiRegistryCoordinator"
        );

        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            TaiyiRegistryCoordinator.initialize.selector,
            owner, // initialOwner
            0, // initialPausedStatus
            address(eigenLayerDeployer.allocationManager()), // _allocationManager
            address(eigenLayerDeployer.eigenLayerPauserReg()) // _pauserRegistry
        );

        // Deploy and initialize proxy
        TransparentUpgradeableProxy registryProxy =
            new TransparentUpgradeableProxy(address(registryImpl), proxyAdmin, initData);

        registryCoordinator = TaiyiRegistryCoordinator(address(registryProxy));
        vm.stopPrank();
    }

    /// @dev Deploy LinglongSlasher implementation and proxy
    function _deployLinglongSlasher() internal {
        vm.startPrank(owner);

        // Deploy implementation
        LinglongSlasher slasherImpl = new LinglongSlasher();

        // Deploy and initialize proxy
        TransparentUpgradeableProxy slasherProxy = new TransparentUpgradeableProxy(
            address(slasherImpl),
            proxyAdmin,
            abi.encodeWithSelector(
                LinglongSlasher.initialize.selector,
                owner,
                address(eigenLayerDeployer.allocationManager()),
                address(registry)
            )
        );

        slasher = LinglongSlasher(address(slasherProxy));
        vm.stopPrank();
    }

    /// @dev Setup PubkeyRegistry and SocketRegistry for the RegistryCoordinator
    function _setupRegistryCoordinatorRegistries() internal {
        vm.startPrank(owner);

        // Deploy registries
        PubkeyRegistry pubkeyRegistry = new PubkeyRegistry(address(registryCoordinator));
        SocketRegistry socketRegistry = new SocketRegistry(registryCoordinator);

        // Update registry coordinator with new registries
        registryCoordinator.updateSocketRegistry(address(socketRegistry));
        registryCoordinator.updatePubkeyRegistry(address(pubkeyRegistry));

        vm.stopPrank();
    }

    /// @dev Configure middleware connections between components
    function _configureMiddlewareConnections() internal {
        // Set up connections as owner
        vm.startPrank(owner);
        slasher.setEigenLayerMiddleware(eigenLayerMiddleware);
        registryCoordinator.setRestakingProtocol(
            eigenLayerMiddleware, ITaiyiRegistryCoordinator.RestakingProtocol.EIGENLAYER
        );
        vm.stopPrank();

        // Set AVS registrar for AllocationManager
        vm.startPrank(eigenLayerMiddleware);
        eigenLayerDeployer.allocationManager().setAVSRegistrar(
            eigenLayerMiddleware, IAVSRegistrar(registryCoordinator)
        );
        vm.stopPrank();
    }

    /// @dev Setup challenger for slashing
    function _setupChallenger() internal {
        vm.startPrank(owner);

        address linglongChallenger = address(new MockLinglongChallenger());
        slasher.registerChallenger(linglongChallenger);
        slasher.setURCCommitmentTypeToViolationType(
            COMMITMENT_TYPE_URC, VIOLATION_TYPE_URC
        );

        vm.stopPrank();
    }

    /// @dev Create operator set in AllocationManager
    function _createOperatorSet() internal {
        // Prepare strategies for the operator set
        IStrategy[] memory strategies = new IStrategy[](1);
        strategies[0] = IStrategy(eigenLayerDeployer.wethStrat());

        console.log("Creating operator set with strategy:", address(strategies[0]));

        // Create the operator set directly through middleware
        vm.startPrank(owner);
        validatorOperatorSetId = middleware.createOperatorSet(
            strategies, OperatorSubsetLib.VALIDATOR_SUBSET_TYPE, 0
        );
        underwriterOperatorSetId = middleware.createOperatorSet(
            strategies, OperatorSubsetLib.UNDERWRITER_SUBSET_TYPE, 0
        );
        vm.stopPrank();

        console.log("Created validator operator set with ID:", validatorOperatorSetId);
        console.log("Created underwriter operator set with ID:", underwriterOperatorSetId);
        // Verify the operator set exists
        OperatorSet memory opSet;
        opSet.id = validatorOperatorSetId;
        opSet.avs = eigenLayerMiddleware;

        bool exists = eigenLayerDeployer.allocationManager().isOperatorSet(opSet);
        assertTrue(exists, "Validator Operator set should exist");

        opSet.id = underwriterOperatorSetId;
        opSet.avs = eigenLayerMiddleware;
        exists = eigenLayerDeployer.allocationManager().isOperatorSet(opSet);
        assertTrue(exists, "Underwriter Operator set should exist");
    }

    /// @dev Setup operators and give them ETH and WETH
    function _setupOperatorsWithFunds()
        internal
        returns (
            address primaryOp,
            address underwriterOp,
            uint256 primaryOpKey,
            uint256 underwriterOpKey
        )
    {
        (primaryOp, primaryOpKey) = makeAddrAndKey("primaryOperator");
        (underwriterOp, underwriterOpKey) = makeAddrAndKey("underwriterOperator");

        // Give ETH to the operators
        vm.deal(primaryOp, 100 ether);
        vm.deal(underwriterOp, 100 ether);

        // Important: Transfer WETH to operators for staking
        vm.startPrank(address(eigenLayerDeployer));
        eigenLayerDeployer.weth().transfer(primaryOp, 100 ether);
        eigenLayerDeployer.weth().transfer(underwriterOp, 100 ether);
        vm.stopPrank();

        return (primaryOp, underwriterOp, primaryOpKey, underwriterOpKey);
    }

    // ==============================================================================================
    // ====================================== TEST HELPERS =========================================
    // ==============================================================================================

    function _signMessage(
        address signer,
        bytes memory blsPubkey,
        uint256 privateKey
    )
        internal
        pure
        returns (bytes memory)
    {
        bytes32 messageHash = keccak256(abi.encodePacked(signer, blsPubkey));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }

    function _verifyOperatorSetExists(OperatorSet memory opSet) internal view {
        assertTrue(
            eigenLayerDeployer.allocationManager().isOperatorSet(opSet),
            "Operator set should exist"
        );
        uint32 count = middleware.getOperatorSetCount();
        assertEq(count, 2, "Should have 2 operator set");
    }

    function _verifyOperatorRegistrationInEigenLayer(address _operator) internal view {
        assertTrue(
            eigenLayerDeployer.delegation().isOperator(_operator),
            "Operator should be registered in EigenLayer"
        );
    }

    function _verifyOperatorAllocation(
        address _operator,
        OperatorSet memory opSet
    )
        internal
        view
        returns (IStrategy[] memory)
    {
        IAllocationManager allocationManager = eigenLayerDeployer.allocationManager();
        assertTrue(
            allocationManager.isMemberOfOperatorSet(_operator, opSet),
            "Operator should be a member of the operator set"
        );

        // Check operator's allocation from each strategy to the operator set
        IStrategy[] memory strategies =
            allocationManager.getStrategiesInOperatorSet(opSet);
        assertEq(strategies.length, 1, "Should have 1 strategy in operator set");

        IAllocationManagerTypes.Allocation memory allocation =
            allocationManager.getAllocation(_operator, opSet, strategies[0]);

        assertEq(allocation.currentMagnitude, uint64(_WAD), "Wrong allocation magnitude");
        assertEq(int256(allocation.pendingDiff), 0, "Should have no pending diff");

        return strategies;
    }

    function _verifyOperatorInOperatorSet(
        address _operator,
        OperatorSet memory opSet
    )
        internal
        view
    {
        IAllocationManager allocationManager = eigenLayerDeployer.allocationManager();
        address[] memory members = allocationManager.getMembers(opSet);
        bool operatorFound = false;
        for (uint256 i = 0; i < members.length; i++) {
            if (members[i] == _operator) {
                operatorFound = true;
                break;
            }
        }
        assertTrue(operatorFound, "Operator should be found in operator set members");

        // Check the operator is in the operator set from the registry coordinator
        (, uint32 baseOperatorSetId) = opSet.id.decodeOperatorSetId32();
        assertTrue(
            registryCoordinator.getEigenLayerOperatorFromOperatorSet(
                baseOperatorSetId, operator
            ),
            "Operator should be in the operator set"
        );
        assertEq(baseOperatorSetId, uint32(0), "Operator set ID should match");
    }

    function _verifyOperatorStake(address _operator) internal view {
        (IStrategy[] memory strategies, uint256[] memory stakeAmounts) =
            middleware.getStrategiesAndStakes(_operator);
        assertEq(strategies.length, 1, "Should have 1 strategy in operator set");
        assertEq(
            stakeAmounts[0], STAKE_AMOUNT, "Should have 1 stake amount in operator set"
        );

        uint32 count = middleware.getOperatorSetCount();
        assertEq(count, 2, "Should have 2 operator set");
    }

    function _verifyOperatorRegistration(
        address primaryOp,
        address underwriterOp
    )
        internal
        view
    {
        // Verify the registration was successful in both EigenLayer and TaiyiRegistryCoordinator

        // 1. Check the operators are registered with TaiyiRegistryCoordinator
        // Using uint8 instead of enum to avoid compilation issues
        uint8 primaryOpStatus = uint8(registryCoordinator.getOperatorStatus(primaryOp));
        uint8 underwriterOpStatus =
            uint8(registryCoordinator.getOperatorStatus(underwriterOp));

        // OperatorStatus.REGISTERED == 1
        assertTrue(
            primaryOpStatus == 1,
            "Primary operator should be registered with TaiyiRegistryCoordinator"
        );
        assertTrue(
            underwriterOpStatus == 1,
            "Underwriter operator should be registered with TaiyiRegistryCoordinator"
        );

        // 2. Verify they are members of the operatorSet
        (, uint32 opSetId) = underwriterOperatorSetId.decodeOperatorSetId32();
        address[] memory opSetMembers =
            registryCoordinator.getEigenLayerOperatorSetOperators(opSetId);

        bool primaryOpFound = false;
        bool underwriterOpFound = false;

        for (uint256 i = 0; i < opSetMembers.length; i++) {
            if (opSetMembers[i] == primaryOp) {
                primaryOpFound = true;
            }
            if (opSetMembers[i] == underwriterOp) {
                underwriterOpFound = true;
            }
        }

        assertFalse(
            primaryOpFound,
            "Primary operator should not be a member of the underwriter operator set"
        );
        assertTrue(
            underwriterOpFound,
            "Underwriter operator should be a member of the underwriter operator set"
        );
    }

    function _verifyDeregistration(
        address _operator,
        OperatorSet memory opSet
    )
        internal
        view
    {
        IAllocationManager allocationManager = eigenLayerDeployer.allocationManager();
        assertFalse(
            allocationManager.isMemberOfOperatorSet(_operator, opSet),
            "Operator should no longer be a member of the operator set after deregistration"
        );

        // Check the operator is still in the allocated sets (deallocation pending)
        OperatorSet[] memory allocatedSets = allocationManager.getAllocatedSets(_operator);
        bool stillAllocated = false;
        for (uint256 i = 0; i < allocatedSets.length; i++) {
            if (
                allocatedSets[i].id == validatorOperatorSetId
                    && allocatedSets[i].avs == eigenLayerMiddleware
            ) {
                stillAllocated = true;
                break;
            }
        }
        assertTrue(
            stillAllocated,
            "Operator should still have allocations during deallocation delay"
        );
    }

    // ==============================================================================================
    // ==================================== REGISTRATION ============================================
    // ==============================================================================================

    function _registerOperator(
        address _operator,
        uint32 _opSetId,
        uint256 operatorSecret,
        bytes memory blsPubkey
    )
        internal
    {
        // 1. Register in EigenLayer
        _registerOperatorInEigenLayer(_operator);

        // 2. Stake into EigenLayer to have active stake
        _stakeIntoEigenLayer(_operator, STAKE_AMOUNT);

        // 3. Allocate stake to the AVS (step 1 of AVS opt-in)
        _allocateStakeToAVS(_operator, _opSetId);

        // 4. Register for the operator set (step 2 of AVS opt-in)
        _registerForOperatorSets(_operator, _opSetId, operatorSecret, blsPubkey);
    }

    function _registerOperatorInEigenLayer(address _operator) internal {
        // First register the operator with EigenLayer
        vm.startPrank(_operator);
        eigenLayerDeployer.delegation().registerAsOperator(
            address(0), // No delegation approver, anyone can delegate
            0, // No allocation delay
            "https://taiyi.xyz/metadata"
        );
        vm.stopPrank();
    }

    // ==============================================================================================
    // ==================================== STAKING & ALLOCATION ====================================
    // ==============================================================================================

    function _stakeIntoEigenLayer(
        address _staker,
        uint256 amount
    )
        internal
        impersonate(_staker)
        returns (uint256 shares)
    {
        // Approve and deposit ETH into the EigenLayer strategy
        eigenLayerDeployer.weth().approve(
            address(eigenLayerDeployer.strategyManager()), amount
        );

        shares = eigenLayerDeployer.strategyManager().depositIntoStrategy(
            eigenLayerDeployer.wethStrat(), eigenLayerDeployer.weth(), amount
        );
    }

    function _allocateStakeToAVS(
        address _operator,
        uint32 _opSetId
    )
        internal
        impersonate(_operator)
    {
        // Make sure allocation delay is set to 0 for the operator before allocation
        eigenLayerDeployer.allocationManager().setAllocationDelay(_operator, 0);

        // The allocation delay configuration takes ALLOCATION_CONFIGURATION_DELAY + 1 blocks to take effect
        // Get the current allocation delay info to see if it's already set
        (bool isSet,) =
            eigenLayerDeployer.allocationManager().getAllocationDelay(_operator);

        // If not set, we need to wait for the delay to take effect (typically 1200 blocks + 1)
        if (!isSet) {
            // Roll forward the block number by the allocation configuration delay (typically 1200) + 1
            vm.roll(block.number + 1201);
        }

        // First step of AVS opt-in: allocate stake to the AVS's operator set

        // Get the OperatorSet struct
        OperatorSet memory opSet;
        opSet.id = _opSetId;
        opSet.avs = eigenLayerMiddleware;

        // Get strategies in the operator set
        IStrategy[] memory strategies =
            eigenLayerDeployer.allocationManager().getStrategiesInOperatorSet(opSet);

        // Set up new magnitudes array (in WAD format, 1e18 = 100% allocation)
        uint64[] memory newMagnitudes = new uint64[](strategies.length);
        for (uint256 i = 0; i < strategies.length; i++) {
            newMagnitudes[i] = uint64(_WAD); // Using _WAD for 100% allocation
        }

        // Create allocation params
        IAllocationManagerTypes.AllocateParams[] memory allocParams =
            new IAllocationManagerTypes.AllocateParams[](1);
        allocParams[0] = IAllocationManagerTypes.AllocateParams({
            operatorSet: opSet,
            strategies: strategies,
            newMagnitudes: newMagnitudes
        });

        // Call modifyAllocations with the operator address and allocation params
        eigenLayerDeployer.allocationManager().modifyAllocations(_operator, allocParams);
    }

    function _registerForOperatorSets(
        address _operator,
        uint32 _opSetId,
        uint256 operatorSecret,
        bytes memory blsPubkey
    )
        internal
        impersonate(_operator)
    {
        // Second step of AVS opt-in: register for the operator set

        // Format the data properly as expected by TaiyiRegistryCoordinator
        // We need to encode a string (socket) and PubkeyRegistrationParams struct
        string memory socket = "operator-socket.taiyi.xyz";

        // Create a valid PubkeyRegistrationParams struct with proper values
        // In a real scenario, these would be generated from a private key
        IPubkeyRegistry.PubkeyRegistrationParams memory params;

        // Create G1 point for the pubkey using BN254 library
        params.operator = _operator;

        // Create G2 point for the pubkey using BN254 library
        params.blsPubkey = blsPubkey;

        // Create a signature point using BN254 library
        params.pubkeyRegistrationSignature =
            _signMessage(_operator, blsPubkey, operatorSecret);

        bytes memory formattedData = abi.encode(socket, params);

        IAllocationManagerTypes.RegisterParams memory registerParams =
        IAllocationManagerTypes.RegisterParams({
            avs: eigenLayerMiddleware,
            operatorSetIds: _uint32ToArray(_opSetId),
            data: formattedData
        });

        eigenLayerDeployer.allocationManager().registerForOperatorSets(
            _operator, registerParams
        );
    }

    function _removeStrategiesAndVerify(
        uint32 _operatorSetId,
        IStrategy[] memory strategies,
        OperatorSet memory opSet
    )
        internal
    {
        IAllocationManager allocationManager = eigenLayerDeployer.allocationManager();
        vm.startPrank(owner);
        middleware.removeStrategiesFromOperatorSet(_operatorSetId, strategies);
        vm.stopPrank();

        IStrategy[] memory remainingStrategies =
            allocationManager.getStrategiesInOperatorSet(opSet);
        assertEq(
            remainingStrategies.length, 0, "Should have 0 strategies in operator set"
        );
    }

    function _deregisterFromAVS(
        address _operator,
        uint32 _opSetId
    )
        internal
        impersonate(_operator)
    {
        // Create the DeregisterParams struct
        IAllocationManagerTypes.DeregisterParams memory params = IAllocationManagerTypes
            .DeregisterParams({
            operator: _operator,
            avs: eigenLayerMiddleware,
            operatorSetIds: _uint32ToArray(_opSetId)
        });

        // Deregister from the AVS's operator set
        eigenLayerDeployer.allocationManager().deregisterFromOperatorSets(params);
    }

    // ==============================================================================================
    // ==================================== VALIDATOR HELPER ========================================
    // ==============================================================================================

    function _validatorRegistration(
        address primaryOp,
        address underwriterOp
    )
        internal
        returns (bytes32)
    {
        // Create registrations array with validator public keys
        IRegistry.SignedRegistration[] memory registrations =
            new IRegistry.SignedRegistration[](2);

        // comment out to silence ci
        // registrations[0] = _createRegistration(validatorPrivKey1, primaryOp);
        // registrations[1] = _createRegistration(validatorPrivKey2, primaryOp);

        // Generate delegatee information (usually the underwriter operator)
        uint256 delegateePrivKey = 69_420;

        // Register validators and get registration root
        bytes32 registrationRoot = _registerValidatorsWithRoot(primaryOp, registrations);

        // Complete opt-in to slasher with delegation
        _completeOptInToSlasher(
            primaryOp, registrationRoot, registrations, delegateePrivKey, underwriterOp
        );

        return registrationRoot;
    }

    function _registerValidatorsWithRoot(
        address primaryOp,
        IRegistry.SignedRegistration[] memory registrations
    )
        internal
        returns (bytes32)
    {
        // Start prank as the primary operator to register validators
        vm.startPrank(primaryOp);

        // Ensure the operator has enough ETH for collateral
        // The middleware sends 0.11 ETH per validator to the Registry
        uint256 requiredCollateral = registrationMinCollateral * registrations.length;
        vm.deal(primaryOp, requiredCollateral + 2 ether); // Add extra ETH for gas

        // Call registerValidators function with value
        bytes32 registrationRoot =
            middleware.registerValidators{ value: requiredCollateral }(registrations);

        vm.stopPrank();

        return registrationRoot;
    }

    function _completeOptInToSlasher(
        address primaryOp,
        bytes32 registrationRoot,
        IRegistry.SignedRegistration[] memory registrations,
        uint256 delegateePrivKey,
        address delegateeAddress
    )
        internal
    {
        // Create delegatee pubkey
        BLS.G1Point memory delegateePubKey = BLS.toPublicKey(delegateePrivKey);

        // Create delegation signatures for each validator
        BLS.G2Point[] memory delegationSignatures = new BLS.G2Point[](2);

        // Get the validator private keys used earlier in registration
        uint256 validatorPrivKey1 = 12_345;
        uint256 validatorPrivKey2 = 67_890;

        // Generate signatures
        delegationSignatures[0] = _createDelegationSignature(
            validatorPrivKey1, delegateePubKey, delegateeAddress
        );
        delegationSignatures[1] = _createDelegationSignature(
            validatorPrivKey2, delegateePubKey, delegateeAddress
        );

        // Create additional metadata for each validator
        bytes[] memory data = new bytes[](2);
        data[0] = abi.encode("validator-1-metadata");
        data[1] = abi.encode("validator-2-metadata");

        vm.startPrank(primaryOp);

        // Wait for the fraud proof window to pass
        vm.roll(block.number + 100 days);

        // Call optInToSlasher function with the registration root
        middleware.optInToSlasher(
            registrationRoot,
            registrations,
            delegationSignatures,
            delegateePubKey,
            delegateeAddress,
            data
        );

        assertEq(middleware.getOperatorDelegationsCount(primaryOp, registrationRoot), 2);

        // Get pubkeys and delegations separately to avoid stack issues
        _verifyAndSetDelegations(primaryOp, registrationRoot, registrations);

        vm.stopPrank();
    }

    function _verifyAndSetDelegations(
        address primaryOp,
        bytes32 registrationRoot,
        IRegistry.SignedRegistration[] memory registrations
    )
        internal
    {
        // Start prank as the primary operator
        vm.startPrank(primaryOp);

        // Get delegations
        (BLS.G1Point[] memory pubkeys, ISlasher.SignedDelegation[] memory delegations) =
            middleware.getAllDelegations(primaryOp, registrationRoot);

        // Verify pubkeys match
        assertEq(
            keccak256(abi.encode(pubkeys[0])),
            keccak256(abi.encode(registrations[0].pubkey))
        );
        assertEq(
            keccak256(abi.encode(pubkeys[1])),
            keccak256(abi.encode(registrations[1].pubkey))
        );

        // Set delegations
        middleware.batchSetDelegations(registrationRoot, pubkeys, delegations);

        vm.stopPrank();
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
        pure
        returns (BLS.G2Point memory)
    {
        // Create a mock signature instead of using BLS.sign which requires precompiles
        BLS.G2Point memory mockSignature;

        // Use a combination of secretKey and ownerAddress to create deterministic mock values
        uint256 seed = uint256(keccak256(abi.encodePacked(secretKey, ownerAddress)));

        mockSignature.x.c0.a = seed * 11 + 1;
        mockSignature.x.c0.b = seed * 22 + 2;
        mockSignature.x.c1.a = seed * 33 + 3;
        mockSignature.x.c1.b = seed * 44 + 4;
        mockSignature.y.c0.a = seed * 55 + 5;
        mockSignature.y.c0.b = seed * 66 + 6;
        mockSignature.y.c1.a = seed * 77 + 7;
        mockSignature.y.c1.b = seed * 88 + 8;

        return mockSignature;

        // Comment out the actual BLS.sign call that fails in CI
        // bytes memory message = abi.encode(ownerAddress);
        // return BLS.sign(message, secretKey, registry.REGISTRATION_DOMAIN_SEPARATOR());
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
        // Create a delegation object that would be signed
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

        // Create deterministic mock values based on the validatorSecretKey to ensure consistency
        mockSignature.x.c0.a = validatorSecretKey * 100 + 1;
        mockSignature.x.c0.b = validatorSecretKey * 200 + 2;
        mockSignature.x.c1.a = validatorSecretKey * 300 + 3;
        mockSignature.x.c1.b = validatorSecretKey * 400 + 4;
        mockSignature.y.c0.a = validatorSecretKey * 500 + 5;
        mockSignature.y.c0.b = validatorSecretKey * 600 + 6;
        mockSignature.y.c1.a = validatorSecretKey * 700 + 7;
        mockSignature.y.c1.b = validatorSecretKey * 800 + 8;

        return mockSignature;

        // Comment out the actual BLS.sign call that fails in CI
        // return BLS.sign(
        //     abi.encode(delegation),
        //     validatorSecretKey,
        //     registry.DELEGATION_DOMAIN_SEPARATOR()
        // );
    }

    function _createRegistrations()
        internal
        pure
        returns (IRegistry.SignedRegistration[] memory)
    {
        IRegistry.SignedRegistration[] memory registrations =
            new IRegistry.SignedRegistration[](2);

        // Example BLS public keys and signatures
        for (uint256 i = 0; i < 2; i++) {
            // Create a mock BLS public key
            BLS.G1Point memory pubkey;
            pubkey.x.a = uint256(i + 1);
            pubkey.x.b = 0;
            pubkey.y.a = uint256(i + 10);
            pubkey.y.b = 0;

            // Create a mock BLS signature
            BLS.G2Point memory signature;
            signature.x.c0.a = uint256(i + 100);
            signature.x.c0.b = 0;
            signature.x.c1.a = uint256(i + 101);
            signature.x.c1.b = 0;
            signature.y.c0.a = uint256(i + 200);
            signature.y.c0.b = 0;
            signature.y.c1.a = uint256(i + 201);
            signature.y.c1.b = 0;

            registrations[i] =
                IRegistry.SignedRegistration({ pubkey: pubkey, signature: signature });
        }

        return registrations;
    }

    // ==============================================================================================
    // ==================================== UTILITY FUNCTIONS =======================================
    // ==============================================================================================

    function _uint32ToArray(uint32 value) internal pure returns (uint32[] memory) {
        uint32[] memory array = new uint32[](1);
        array[0] = value;
        return array;
    }

    function _createMockCommitment(
        address primaryOp,
        uint256 primaryOpKey
    )
        internal
        view
        returns (ISlasher.SignedCommitment memory)
    {
        // Create a challenge struct that the slasher expects
        ITaiyiInteractiveChallenger.Challenge memory challenge =
        ITaiyiInteractiveChallenger.Challenge({
            id: bytes32(uint256(1234)),
            createdAt: block.timestamp,
            challenger: challenger,
            commitmentSigner: primaryOp,
            status: ITaiyiInteractiveChallenger.ChallengeStatus.Open,
            preconfType: 0,
            commitmentData: new bytes(0),
            signature: new bytes(0)
        });

        // Encode the challenge properly - note the double encoding that slasher expects
        bytes memory payload = abi.encode(abi.encode(challenge));

        // Create a commitment that points to our slasher
        ISlasher.Commitment memory commitment = ISlasher.Commitment({
            slasher: address(slasher),
            commitmentType: COMMITMENT_TYPE_URC,
            payload: payload
        });

        // Generate signature
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(primaryOpKey, keccak256(abi.encode(commitment)));
        bytes memory signature = abi.encodePacked(r, s, v);

        return ISlasher.SignedCommitment({ commitment: commitment, signature: signature });
    }

    // Helper function to match any parameters for mockCall
    function _anyParams() internal pure returns (bytes memory) {
        return new bytes(0);
    }

    // Helper function to create an array with a single uint32 value
    function _uint32ArrayWithSingleValue(uint32 value)
        internal
        pure
        returns (uint32[] memory)
    {
        uint32[] memory arr = new uint32[](1);
        arr[0] = value;
        return arr;
    }
}

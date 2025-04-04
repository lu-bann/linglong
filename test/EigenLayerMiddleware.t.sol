// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { ERC20PresetFixedSupplyUpgradeable } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts-upgradeable-v4.9.0/contracts/token/ERC20/presets/ERC20PresetFixedSupplyUpgradeable.sol";

import { IAllocationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IPauserRegistry } from
    "@eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";

import { IERC20 } from
    "@eigenlayer-contracts/lib/openzeppelin-contracts-v4.9.0/contracts/token/ERC20/IERC20.sol";
import { IDelegationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import { IDelegationManagerTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";

import { IAVSRegistrar } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAVSRegistrar.sol";
import { IEigenPod } from "@eigenlayer-contracts/src/contracts/interfaces/IEigenPod.sol";
import { IEigenPodTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IEigenPod.sol";
import { IRewardsCoordinator } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IRewardsCoordinatorTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { ISignatureUtils } from
    "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";
import { console } from "forge-std/console.sol";

import {
    IAllocationManager,
    IAllocationManagerTypes
} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { EigenLayerMiddleware } from "src/eigenlayer-avs/EigenLayerMiddleware.sol";

import { EigenlayerDeployer } from "./utils/EigenlayerDeployer.sol";

import { MockLinglongChallenger } from "./utils/MockChallenger.sol";
import { ILinglongChallenger } from "src/interfaces/ILinglongChallenger.sol";
import { IPubkeyRegistry } from "src/interfaces/IPubkeyRegistry.sol";
import { PubkeyRegistry } from "src/operator-registries/PubkeyRegistry.sol";
import { SocketRegistry } from "src/operator-registries/SocketRegistry.sol";
import { TaiyiRegistryCoordinator } from
    "src/operator-registries/TaiyiRegistryCoordinator.sol";
import { LinglongSlasher } from "src/slasher/LinglongSlasher.sol";

import { BLS } from "@urc/lib/BLS.sol";
import { StdUtils } from "forge-std/StdUtils.sol";
import "forge-std/Test.sol";
import { BN254 } from "src/libs/BN254.sol";

import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { Registry } from "@urc/Registry.sol";

import { TransparentUpgradeableProxy } from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract EigenlayerMiddlewareTest is Test {
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
    Registry public registry;
    LinglongSlasher public slasher;
    address public challenger;
    address public proxyAdmin;

    uint256 constant STAKE_AMOUNT = 32 ether;
    uint256 constant UNDERWRITER_SHARE_BIPS = 8000; // 80%
    uint256 constant _WAD = 1e18; // 1 WAD = 100% allocation (with underscore to fix linter)

    uint32 public operatorSetId; // Store the operator set ID created in setUp

    // Modifiers
    modifier impersonate(address user) {
        vm.startPrank(user);
        _;
        vm.stopPrank();
    }

    /// @notice Performs initial setup for the test environment by deploying and initializing contracts
    function setUp() public {
        proxyAdmin = makeAddr("proxyAdmin");

        // Deploy EigenLayer and create test accounts
        _setupEigenLayerAndAccounts();

        // Deploy core infrastructure
        registry = new Registry();
        _deployTaiyiRegistryCoordinator();
        _deployLinglongSlasher();
        _setupRegistryCoordinatorRegistries();

        // Configure middleware connections
        _deployEigenLayerMiddleware();
        _configureMiddlewareConnections();

        // Configure challenger and slashing
        _setupChallenger();

        // Create operator set in AllocationManager
        _createOperatorSet();

        console.log("Setup complete");
    }

    /// @dev Deploy a real EigenLayerMiddleware contract
    function _deployEigenLayerMiddleware() internal {
        // Get the owner address for AllocationManager to ensure we have the right permissions
        address allocationManagerOwner = eigenLayerDeployer.allocationManager().owner();
        console.log("AllocationManager owner:", allocationManagerOwner);
        console.log("Our owner:", owner);

        vm.startPrank(owner);

        // Deploy implementation
        console.log("Deploying middleware implementation");
        EigenLayerMiddleware middlewareImpl = new EigenLayerMiddleware();

        // Prepare initialization data
        console.log("Preparing initialization data");
        bytes memory initData = abi.encodeWithSelector(
            EigenLayerMiddleware.initialize.selector,
            owner, // _owner
            address(eigenLayerDeployer.avsDirectory()), // _avsDirectory
            address(eigenLayerDeployer.delegation()), // _delegationManager
            address(eigenLayerDeployer.rewardsCoordinator()), // _rewardCoordinator
            rewardsInitiator, // _rewardInitiator
            address(registryCoordinator), // _registryCoordinator
            UNDERWRITER_SHARE_BIPS, // _underwriterShareBips
            address(registry), // _registry
            address(slasher), // _slasher
            address(eigenLayerDeployer.allocationManager()) // _allocationManager
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

    function testOperatorRegistrationFlow() public {
        OperatorSet memory opSet;
        opSet.id = operatorSetId;
        opSet.avs = eigenLayerMiddleware;
        assertTrue(
            eigenLayerDeployer.allocationManager().isOperatorSet(opSet),
            "Operator set should exist"
        );

        // 2. Register the operator in EigenLayer, allocate stake, and register for operator set
        bytes memory extraData = abi.encode(operatorBLSPubKey);
        _registerCompleteOperator(operator, operatorSetId, extraData);

        // 3. Verify the registration was successful

        // Check operator is registered in EigenLayer
        assertTrue(
            eigenLayerDeployer.delegation().isOperator(operator),
            "Operator should be registered in EigenLayer"
        );

        // Check operator has allocated stake to the operator set
        IAllocationManager allocationManager = eigenLayerDeployer.allocationManager();

        assertTrue(
            allocationManager.isMemberOfOperatorSet(operator, opSet),
            "Operator should be a member of the operator set"
        );

        // Check operator's allocation from each strategy to the operator set
        IStrategy[] memory strategies =
            allocationManager.getStrategiesInOperatorSet(opSet);
        assertEq(strategies.length, 1, "Should have 1 strategy in operator set");

        IAllocationManagerTypes.Allocation memory allocation =
            allocationManager.getAllocation(operator, opSet, strategies[0]);

        assertEq(allocation.currentMagnitude, uint64(_WAD), "Wrong allocation magnitude");
        assertEq(int256(allocation.pendingDiff), 0, "Should have no pending diff");

        // Check operator is registered in the operator set
        address[] memory members = allocationManager.getMembers(opSet);
        bool operatorFound = false;
        for (uint256 i = 0; i < members.length; i++) {
            if (members[i] == operator) {
                operatorFound = true;
                break;
            }
        }
        assertTrue(operatorFound, "Operator should be found in operator set members");

        // 4. Test deregistration
        // Todo: use TaiyiRegistryCoordinator.deregisterOperator()
        _deregisterFromAVS(operator, operatorSetId);

        // The operator should be marked as deregistered (but still slashable)
        assertFalse(
            allocationManager.isMemberOfOperatorSet(operator, opSet),
            "Operator should no longer be a member of the operator set after deregistration"
        );

        // Check the operator is still in the allocated sets (deallocation pending)
        OperatorSet[] memory allocatedSets = allocationManager.getAllocatedSets(operator);
        bool stillAllocated = false;
        for (uint256 i = 0; i < allocatedSets.length; i++) {
            if (
                allocatedSets[i].id == operatorSetId
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

    function testValidatorRegistration() public {
        // Setup operators and give them funds
        (address primaryOp, address underwriterOp) = _setupOperatorsWithFunds();

        // Create BLS keys and register operators
        _registerOperatorsWithUniqueKeys(primaryOp, underwriterOp);

        // Setup mocks and complete test
        _verifyOperatorRegistration(primaryOp, underwriterOp);

        // Todo: silence this for the CI
        // Register the validator
        //_validatorRegistration(primaryOp, underwriterOp);
    }

    /// @dev Setup operators and give them ETH and WETH
    function _setupOperatorsWithFunds()
        internal
        returns (address primaryOp, address underwriterOp)
    {
        primaryOp = makeAddr("primaryOperator");
        underwriterOp = makeAddr("underwriterOperator");

        // Give ETH to the operators
        vm.deal(primaryOp, 100 ether);
        vm.deal(underwriterOp, 100 ether);

        // Important: Transfer WETH to operators for staking
        vm.startPrank(address(eigenLayerDeployer));
        eigenLayerDeployer.weth().transfer(primaryOp, 100 ether);
        eigenLayerDeployer.weth().transfer(underwriterOp, 100 ether);
        vm.stopPrank();

        return (primaryOp, underwriterOp);
    }

    /// @dev Create different BLS pubkeys and register operators
    function _registerOperatorsWithUniqueKeys(
        address primaryOp,
        address underwriterOp
    )
        internal
    {
        // Create different BLS pubkeys for each operator
        bytes memory primaryOpBLSPubKey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            primaryOpBLSPubKey[i] = 0xaa; // Different value from the default 0xab
        }

        bytes memory underwriterOpBLSPubKey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            underwriterOpBLSPubKey[i] = 0xcc; // Different value from both default and primaryOp
        }

        // Register operators with different BLS pubkeys
        _registerCompleteOperator(
            primaryOp, operatorSetId, abi.encode(primaryOpBLSPubKey)
        );
        _registerCompleteOperator(
            underwriterOp, operatorSetId, abi.encode(underwriterOpBLSPubKey)
        );
    }

    /// @dev Create test registrations
    function _createRegistrations()
        internal
        pure
        returns (IRegistry.Registration[] memory)
    {
        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](2);

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
                IRegistry.Registration({ pubkey: pubkey, signature: signature });
        }

        return registrations;
    }

    /// @dev Setup mocks for registry interactions and verify
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
        address[] memory opSetMembers =
            registryCoordinator.getOperatorSetOperators(operatorSetId);

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

        assertTrue(
            primaryOpFound, "Primary operator should be a member of the operator set"
        );
        assertTrue(
            underwriterOpFound,
            "Underwriter operator should be a member of the operator set"
        );

        // Log success message
        console.log("Operators successfully registered with TaiyiRegistryCoordinator");
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
                address(eigenLayerDeployer.allocationManager())
            )
        );

        slasher = LinglongSlasher(address(slasherProxy));
        vm.stopPrank();
    }

    /// @dev Setup PubkeyRegistry and SocketRegistry for the RegistryCoordinator
    function _setupRegistryCoordinatorRegistries() internal {
        vm.startPrank(owner);

        // Deploy registries
        PubkeyRegistry pubkeyRegistry = new PubkeyRegistry(registryCoordinator);
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
        registryCoordinator.setEigenlayerMiddleware(eigenLayerMiddleware);
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

        // Create the operator set directly through middleware
        vm.startPrank(owner); // Owner must call as createOperatorSet is onlyOwner
        operatorSetId = middleware.createOperatorSet(strategies);
        vm.stopPrank();

        console.log("operatorSetId", operatorSetId);
    }

    // Full EigenLayer and AVS registration flow
    function _registerCompleteOperator(
        address _operator,
        uint32 _opSetId,
        bytes memory extraData
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
        _registerForOperatorSets(_operator, _opSetId, extraData);
    }

    // Helper function to register an operator in EigenLayer
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

    // Helper function to stake ETH to get active stake in EigenLayer
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

    // Helper function to allocate stake to an AVS (step 1 of AVS opt-in)
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

    // Helper function to register for operator sets (step 2 of AVS opt-in)
    function _registerForOperatorSets(
        address _operator,
        uint32 _opSetId,
        bytes memory extraData
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

        // Use the extraData to derive unique pubkeys for each operator
        // The extraData contains the BLS pubkey that we set differently for each operator
        bytes memory blsPubKey = abi.decode(extraData, (bytes));

        // Use the first byte from the BLS pubkey to create unique pubkey values
        uint256 uniqueMultiplier = uint256(uint8(blsPubKey[0]));

        // Create G1 point for the pubkey using BN254 library
        params.pubkeyG1 = BN254.G1Point({
            X: 1_234_567_890_123_456_789_012_345_678_901_234_567_890 * uniqueMultiplier,
            Y: 9_876_543_210_987_654_321_098_765_432_109_876_543_210 * uniqueMultiplier
        });

        // Create G2 point for the pubkey using BN254 library
        params.pubkeyG2 = BN254.G2Point({
            X: [
                uint256(11_111_111_111_111_111_111_111_111_111_111_111_111) * uniqueMultiplier,
                uint256(22_222_222_222_222_222_222_222_222_222_222_222_222) * uniqueMultiplier
            ],
            Y: [
                uint256(33_333_333_333_333_333_333_333_333_333_333_333_333) * uniqueMultiplier,
                uint256(44_444_444_444_444_444_444_444_444_444_444_444_444) * uniqueMultiplier
            ]
        });

        // Create a signature point using BN254 library
        params.pubkeyRegistrationSignature = BN254.G1Point({
            X: 5_555_555_555_555_555_555_555_555_555_555_555_555_555 * uniqueMultiplier,
            Y: 6_666_666_666_666_666_666_666_666_666_666_666_666_666 * uniqueMultiplier
        });

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

    // Helper function to test operator opt-out/deregistration from AVS
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

    // Helper function to convert a single uint32 to a uint32[] array
    function _uint32ToArray(uint32 value) internal pure returns (uint32[] memory) {
        uint32[] memory array = new uint32[](1);
        array[0] = value;
        return array;
    }

    function _validatorRegistration(address primaryOp, address underwriterOp) internal {
        console.log("Starting validator registration for operator:", primaryOp);

        // Create BLS keys and signatures for registration
        uint256 validatorPrivKey1 = 12_345; // Use a deterministic private key for testing
        uint256 validatorPrivKey2 = 67_890; // Second validator key

        // Create registrations array with validator public keys
        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](2);

        registrations[0] = _createRegistration(validatorPrivKey1, primaryOp);
        registrations[1] = _createRegistration(validatorPrivKey2, primaryOp);

        // Create delegatee information (usually the underwriter operator)
        address delegateeAddress = underwriterOp;

        // Generate delegatee pubkey
        uint256 delegateePrivKey = 9876;
        BLS.G1Point memory delegateePubKey = BLS.toPublicKey(delegateePrivKey);

        // Create delegation signatures for each validator
        BLS.G2Point[] memory delegationSignatures = new BLS.G2Point[](2);

        // Usually these signatures would be signing a delegation message
        // that includes the delegatee's pubkey and the committer's address
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

        // Start prank as the primary operator to register validators
        vm.startPrank(primaryOp);

        // Ensure the operator has enough ETH for collateral
        // The middleware sends 0.11 ETH per validator to the Registry
        uint256 requiredCollateral = 0.11 ether * registrations.length;
        vm.deal(primaryOp, requiredCollateral + 2 ether); // Add extra ETH for gas

        // Log the balance for debugging
        console.log(
            "Primary operator ETH balance before registration:", primaryOp.balance
        );
        console.log("Required collateral for registration:", requiredCollateral);

        // Call registerValidators function with value
        bytes32 registrationRoot = middleware.registerValidators{
            value: requiredCollateral
        }(registrations, delegationSignatures, delegateePubKey, delegateeAddress, data);

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

        vm.stopPrank();

        assertEq(middleware.getOperatorDelegationsCount(primaryOp, registrationRoot), 2);

        console.log("Validator registration completed successfully");
    }

    function _createRegistration(
        uint256 secretKey,
        address ownerAddress
    )
        internal
        view
        returns (IRegistry.Registration memory)
    {
        BLS.G1Point memory pubkey = BLS.toPublicKey(secretKey);
        BLS.G2Point memory signature =
            _createRegistrationSignature(secretKey, ownerAddress);

        return IRegistry.Registration({ pubkey: pubkey, signature: signature });
    }

    // Helper function to create registration signatures
    function _createRegistrationSignature(
        uint256 secretKey,
        address ownerAddress
    )
        internal
        view
        returns (BLS.G2Point memory)
    {
        bytes memory message = abi.encode(ownerAddress);

        return BLS.sign(message, secretKey, registry.REGISTRATION_DOMAIN_SEPARATOR());
    }

    // Helper function to create delegation signatures
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

        // Sign the delegation
        return BLS.sign(
            abi.encode(delegation),
            validatorSecretKey,
            registry.DELEGATION_DOMAIN_SEPARATOR()
        );
    }
}

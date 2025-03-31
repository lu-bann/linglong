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

import { IPubkeyRegistry } from "src/interfaces/IPubkeyRegistry.sol";
import { PubkeyRegistry } from "src/operator-registries/PubkeyRegistry.sol";
import { SocketRegistry } from "src/operator-registries/SocketRegistry.sol";
import { TaiyiRegistryCoordinator } from
    "src/operator-registries/TaiyiRegistryCoordinator.sol";

import { StdUtils } from "forge-std/StdUtils.sol";
import "forge-std/Test.sol";
import { BLS12381 } from "src/libs/BLS12381.sol";
import { BN254 } from "src/libs/BN254.sol";

import { TransparentUpgradeableProxy } from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract EigenlayerMiddlewareTest is Test {
    using BLS12381 for BLS12381.G1Point;

    address public eigenLayerMiddleware; // Changed to address instead of a contract type
    EigenlayerDeployer public eigenLayerDeployer;
    TaiyiRegistryCoordinator public registryCoordinator;
    address public owner;
    address staker;
    address operator;
    address rewardsInitiator;
    uint256 operatorSecretKey;
    bytes operatorBLSPubKey;

    uint256 constant STAKE_AMOUNT = 32 ether;
    uint256 constant UNDERWRITER_SHARE_BIPS = 8000; // 80%
    uint256 constant _WAD = 1e18; // 1 WAD = 100% allocation (with underscore to fix linter)

    uint32 public operatorSetId; // Store the operator set ID created in setUp

    // Events to track
    event ValidatorOperatorRegistered(
        address indexed operator,
        address indexed avs,
        bytes delegatedGatewayPubKey,
        bytes validatorPubKey
    );

    // Modifiers
    modifier impersonate(address user) {
        vm.startPrank(user);
        _;
        vm.stopPrank();
    }

    /// @notice Performs initial setup for the test environment by deploying and initializing contracts
    function setUp() public {
        eigenLayerDeployer = new EigenlayerDeployer();
        staker = eigenLayerDeployer.setUp();

        (operator, operatorSecretKey) = makeAddrAndKey("operator");
        owner = makeAddr("owner");
        rewardsInitiator = makeAddr("rewardInitiator");
        address proxyAdmin = makeAddr("proxyAdmin");

        // Transfer some WETH to the operator so they can stake
        vm.startPrank(address(eigenLayerDeployer));
        eigenLayerDeployer.weth().transfer(operator, 100 ether);
        vm.stopPrank();

        operatorBLSPubKey = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            operatorBLSPubKey[i] = 0xab;
        }

        vm.startPrank(owner);

        // First, create the registry coordinator implementation
        TaiyiRegistryCoordinator registryImpl = new TaiyiRegistryCoordinator(
            IAllocationManager(eigenLayerDeployer.allocationManager()),
            IPauserRegistry(eigenLayerDeployer.eigenLayerPauserReg()),
            "TaiyiRegistryCoordinator"
        );

        // Now create a proxy for the registry coordinator with the right initialization data
        bytes memory initData = abi.encodeWithSelector(
            TaiyiRegistryCoordinator.initialize.selector,
            owner, // initialOwner
            0, // initialPausedStatus
            address(eigenLayerDeployer.allocationManager()), // _allocationManager
            address(eigenLayerDeployer.eigenLayerPauserReg()) // _pauserRegistry
        );

        TransparentUpgradeableProxy registryProxy =
            new TransparentUpgradeableProxy(address(registryImpl), proxyAdmin, initData);

        registryCoordinator = TaiyiRegistryCoordinator(address(registryProxy));

        PubkeyRegistry pubkeyRegistry = new PubkeyRegistry(registryCoordinator);
        SocketRegistry socketRegistry = new SocketRegistry(registryCoordinator);

        // Update the registry coordinator to use the new registries
        registryCoordinator.updateSocketRegistry(address(socketRegistry));

        // Update the pubkey registry in the registry coordinator
        registryCoordinator.updatePubkeyRegistry(address(pubkeyRegistry));

        // Store this test contract address as middleware
        eigenLayerMiddleware = address(this);

        // Set this test contract as the EigenLayerMiddleware
        registryCoordinator.setEigenlayerMiddleware(eigenLayerMiddleware);

        // Set this test contract as the AVS registrar for AllocationManager
        // This ensures that AllocationManager will call back to our registerOperator function
        vm.startPrank(eigenLayerMiddleware);
        eigenLayerDeployer.allocationManager().setAVSRegistrar(
            eigenLayerMiddleware, IAVSRegistrar(registryCoordinator)
        );
        vm.stopPrank();

        // We need to register our middleware with the AllocationManager as an AVS
        // Create an operator set through the EigenLayer allocation manager directly
        IAllocationManagerTypes.CreateSetParams[] memory createSetParams =
            new IAllocationManagerTypes.CreateSetParams[](1);

        // Use the same strategies the EigenlayerDeployer uses
        IStrategy[] memory strategies = new IStrategy[](1);
        strategies[0] = IStrategy(eigenLayerDeployer.wethStrat());

        createSetParams[0] = IAllocationManagerTypes.CreateSetParams({
            operatorSetId: 0, // First operator set
            strategies: strategies
        });

        // Call createOperatorSets directly on the AllocationManager
        vm.stopPrank();
        vm.prank(eigenLayerMiddleware);
        IAllocationManager(eigenLayerDeployer.allocationManager()).createOperatorSets(
            eigenLayerMiddleware, createSetParams
        );

        // Store this ID for later use
        operatorSetId = 0; // The first operator set we created
    }

    // Full EigenLayer and AVS registration flow
    function _registerCompleteOperator(
        address _operator,
        uint32 operatorSetId,
        bytes memory extraData
    )
        internal
    {
        // 1. Register in EigenLayer
        _registerOperatorInEigenLayer(_operator);

        // 2. Stake into EigenLayer to have active stake
        _stakeIntoEigenLayer(_operator, STAKE_AMOUNT);

        // 3. Allocate stake to the AVS (step 1 of AVS opt-in)
        _allocateStakeToAVS(_operator, operatorSetId);

        // 4. Register for the operator set (step 2 of AVS opt-in)
        _registerForOperatorSets(_operator, operatorSetId, extraData);
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
        uint32 operatorSetId
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
        opSet.id = operatorSetId;
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
        uint32 operatorSetId,
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

        // Create G1 point for the pubkey
        params.pubkeyG1 = BN254.G1Point({
            X: 1_234_567_890_123_456_789_012_345_678_901_234_567_890,
            Y: 9_876_543_210_987_654_321_098_765_432_109_876_543_210
        });

        // Create G2 point for the pubkey
        params.pubkeyG2 = BN254.G2Point({
            X: [
                uint256(11_111_111_111_111_111_111_111_111_111_111_111_111),
                uint256(22_222_222_222_222_222_222_222_222_222_222_222_222)
            ],
            Y: [
                uint256(33_333_333_333_333_333_333_333_333_333_333_333_333),
                uint256(44_444_444_444_444_444_444_444_444_444_444_444_444)
            ]
        });

        // Create a signature point
        params.pubkeyRegistrationSignature = BN254.G1Point({
            X: 5_555_555_555_555_555_555_555_555_555_555_555_555_555,
            Y: 6_666_666_666_666_666_666_666_666_666_666_666_666_666
        });

        bytes memory formattedData = abi.encode(socket, params);

        IAllocationManagerTypes.RegisterParams memory registerParams =
        IAllocationManagerTypes.RegisterParams({
            avs: eigenLayerMiddleware,
            operatorSetIds: _uint32ToArray(operatorSetId),
            data: formattedData
        });

        eigenLayerDeployer.allocationManager().registerForOperatorSets(
            _operator, registerParams
        );
    }

    // Helper function to test operator opt-out/deregistration from AVS
    function _deregisterFromAVS(
        address _operator,
        uint32 operatorSetId
    )
        internal
        impersonate(_operator)
    {
        // Create the DeregisterParams struct
        IAllocationManagerTypes.DeregisterParams memory params = IAllocationManagerTypes
            .DeregisterParams({
            operator: _operator,
            avs: eigenLayerMiddleware,
            operatorSetIds: _uint32ToArray(operatorSetId)
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

    function testOperatorRegistrationFlow() public {
        // Use the operatorSetId created in setUp

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
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { EigenlayerDeployer } from "./utils/EigenlayerDeployer.sol";
import { MockLinglongChallenger } from "./utils/MockChallenger.sol";

import { IAllocationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { TransparentUpgradeableProxy } from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import { IRegistry } from "@urc/IRegistry.sol";
import { ISlasher } from "@urc/ISlasher.sol";
import { Registry } from "@urc/Registry.sol";
import { Test } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";

import { ILinglongChallenger } from "src/interfaces/ILinglongChallenger.sol";
import { ILinglongSlasher } from "src/interfaces/ILinglongSlasher.sol";

import { ITaiyiInteractiveChallenger } from
    "src/interfaces/ITaiyiInteractiveChallenger.sol";
import { ITaiyiRegistryCoordinator } from "src/interfaces/ITaiyiRegistryCoordinator.sol";
import { LinglongSlasher } from "src/slasher/LinglongSlasher.sol";

contract LinglongSlasherTest is Test {
    bytes32 public constant VIOLATION_TYPE_URC = keccak256("URC_VIOLATION");
    uint64 public constant COMMITMENT_TYPE_URC = 1;

    LinglongSlasher public slasher;
    EigenlayerDeployer public eigenLayerDeployer;
    Registry public registry;
    address public owner;
    address public challenger;
    address public eigenLayerMiddleware;
    address public proxyAdmin;

    // Operator addresses
    address public operator;

    function setUp() public {
        // Setup accounts
        owner = makeAddr("owner");
        proxyAdmin = makeAddr("proxyAdmin");
        operator = makeAddr("operator");
        eigenLayerMiddleware = makeAddr("eigenLayerMiddleware");

        // Deploy EigenLayer
        eigenLayerDeployer = new EigenlayerDeployer();
        eigenLayerDeployer.setUp();

        // Deploy Registry
        registry = new Registry(
            IRegistry.Config({
                minCollateralWei: 0.1 ether,
                fraudProofWindow: 7200,
                unregistrationDelay: 7200,
                slashWindow: 7200,
                optInDelay: 7200
            })
        );

        // Deploy LinglongSlasher
        vm.startPrank(owner);
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

        // Setup challenger
        challenger = address(new MockLinglongChallenger());
        vm.stopPrank();
    }

    function testRegisterChallenger() public {
        // Register challenger
        vm.startPrank(owner);
        slasher.registerChallenger(challenger);
        vm.stopPrank();

        // Check if challenger is registered
        address[] memory challengers = slasher.getRegisteredChallengers();
        assertEq(challengers.length, 1, "Should have 1 registered challenger");
        assertEq(challengers[0], challenger, "Registered challenger should match");

        // Check violation types
        bytes32[] memory violationTypes = slasher.getRegisteredViolationTypes();
        assertEq(violationTypes.length, 1, "Should have 1 registered violation type");
        assertEq(violationTypes[0], VIOLATION_TYPE_URC, "Violation type should match");

        // Check challenger for violation type
        address registeredChallenger =
            slasher.getViolationTypeChallengers(VIOLATION_TYPE_URC);
        assertEq(
            registeredChallenger, challenger, "Challenger for violation type should match"
        );
    }

    function testSetURCCommitmentTypeToViolationType() public {
        vm.startPrank(owner);
        slasher.setURCCommitmentTypeToViolationType(
            COMMITMENT_TYPE_URC, VIOLATION_TYPE_URC
        );
        vm.stopPrank();

        bytes32 violationType =
            slasher.URCCommitmentTypeToViolationType(COMMITMENT_TYPE_URC);
        assertEq(
            violationType, VIOLATION_TYPE_URC, "Violation type mapping should be set"
        );
    }

    function testRegisterChallengerFailsForNonOwner() public {
        address nonOwner = makeAddr("nonOwner");

        vm.startPrank(nonOwner);
        vm.expectRevert();
        slasher.registerChallenger(challenger);
        vm.stopPrank();
    }

    function testRegisterChallengerFailsForZeroAddress() public {
        vm.startPrank(owner);
        vm.expectRevert(ILinglongSlasher.InvalidChallengerAddress.selector);
        slasher.registerChallenger(address(0));
        vm.stopPrank();
    }

    function testDeactivateChallengerFailsForNonRegistered() public {
        address nonRegisteredChallenger = makeAddr("nonRegisteredChallenger");

        vm.startPrank(owner);
        vm.expectRevert(ILinglongSlasher.ChallengerNotRegistered.selector);
        slasher.deactivateChallenger(nonRegisteredChallenger);
        vm.stopPrank();
    }

    function testReactivateChallengerFailsForNonRegistered() public {
        address nonRegisteredChallenger = makeAddr("nonRegisteredChallenger");

        vm.startPrank(owner);
        vm.expectRevert(ILinglongSlasher.ChallengerNotRegistered.selector);
        slasher.reactivateChallenger(nonRegisteredChallenger);
        vm.stopPrank();
    }

    function testGetChallengerViolationTypesFailsForNonRegistered() public {
        address nonRegisteredChallenger = makeAddr("nonRegisteredChallenger");

        vm.expectRevert(ILinglongSlasher.ChallengerNotRegistered.selector);
        slasher.getChallengerViolationTypes(nonRegisteredChallenger);
    }

    function testCannotRegisterSameChallenerTwice() public {
        vm.startPrank(owner);
        slasher.registerChallenger(challenger);

        vm.expectRevert(ILinglongSlasher.ChallengerAlreadyRegistered.selector);
        slasher.registerChallenger(challenger);
        vm.stopPrank();
    }

    function testSlashingInProgress() public {
        // Register challenger
        vm.startPrank(owner);
        slasher.registerChallenger(challenger);
        vm.stopPrank();

        // Set slashing in progress state in the mock challenger
        MockLinglongChallenger(challenger).setSlashingInProgress(true);

        // Check if slashing is in progress
        (bool inProgress, uint256 slashingId) = slasher.isSlashingInProgress(
            operator,
            1, // getOperatorSetId from MockLinglongChallenger always returns 1
            challenger
        );

        assertTrue(inProgress, "Slashing should be in progress");
        assertEq(slashingId, 1, "Slashing ID should be 1");

        // Set slashing not in progress
        MockLinglongChallenger(challenger).setSlashingInProgress(false);

        // Check if slashing is no longer in progress
        (inProgress, slashingId) = slasher.isSlashingInProgress(operator, 1, challenger);

        assertFalse(inProgress, "Slashing should not be in progress");
        assertEq(slashingId, 0, "Slashing ID should be 0");
    }

    function _uint32ArrayWithSingleValue(uint32 value)
        internal
        pure
        returns (uint32[] memory)
    {
        uint32[] memory result = new uint32[](1);
        result[0] = value;
        return result;
    }
}

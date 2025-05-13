// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITaiyiRegistryCoordinator } from
    "../src/interfaces/ITaiyiRegistryCoordinator.sol";
import { OperatorSubsetLib } from "../src/libs/OperatorSubsetLib.sol";

import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { Test } from "forge-std/Test.sol";

contract OperatorSubsetLibTest is Test {
    using OperatorSubsetLib for OperatorSubsetLib.LinglongSubsets;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.UintSet;

    OperatorSubsetLib.LinglongSubsets internal linglongSubsets;

    // Constants for subset IDs
    uint32 internal constant EIGENLAYER_VALIDATOR_SUBSET_ID = 0;
    uint32 internal constant EIGENLAYER_UNDERWRITER_SUBSET_ID = 1;
    uint32 internal constant SYMBIOTIC_VALIDATOR_SUBSET_ID = 2;
    uint32 internal constant SYMBIOTIC_UNDERWRITER_SUBSET_ID = 3;

    address internal constant OPERATOR_1 = address(0x1001);
    address internal constant OPERATOR_2 = address(0x1002);
    address internal constant OPERATOR_3 = address(0x1003);

    function setUp() public {
        // Create a new instance of LinglongSubsets for each test
        delete linglongSubsets;
    }

    // --- Protocol ID Tests ---

    function testIsEigenlayerProtocolID() public pure {
        assertTrue(
            OperatorSubsetLib.isEigenlayerProtocolID(EIGENLAYER_VALIDATOR_SUBSET_ID)
        );
        assertTrue(
            OperatorSubsetLib.isEigenlayerProtocolID(EIGENLAYER_UNDERWRITER_SUBSET_ID)
        );
        assertFalse(
            OperatorSubsetLib.isEigenlayerProtocolID(SYMBIOTIC_VALIDATOR_SUBSET_ID)
        );
        assertFalse(
            OperatorSubsetLib.isEigenlayerProtocolID(SYMBIOTIC_UNDERWRITER_SUBSET_ID)
        );
    }

    function testIsSymbioticProtocolID() public pure {
        assertFalse(
            OperatorSubsetLib.isSymbioticProtocolID(EIGENLAYER_VALIDATOR_SUBSET_ID)
        );
        assertFalse(
            OperatorSubsetLib.isSymbioticProtocolID(EIGENLAYER_UNDERWRITER_SUBSET_ID)
        );
        assertTrue(OperatorSubsetLib.isSymbioticProtocolID(SYMBIOTIC_VALIDATOR_SUBSET_ID));
        assertTrue(
            OperatorSubsetLib.isSymbioticProtocolID(SYMBIOTIC_UNDERWRITER_SUBSET_ID)
        );
    }

    // --- Set Management Tests ---

    function testCreateLinglongSubset() public {
        uint256 minStake = 1000;
        assertTrue(
            linglongSubsets.createLinglongSubset(EIGENLAYER_VALIDATOR_SUBSET_ID, minStake)
        );
        assertEq(linglongSubsets.getMinStake(EIGENLAYER_VALIDATOR_SUBSET_ID), minStake);

        // Test creating duplicate subset
        assertFalse(
            linglongSubsets.createLinglongSubset(EIGENLAYER_VALIDATOR_SUBSET_ID, minStake)
        );
    }

    // --- Operator Management Tests ---
    /// forge-config: default.allow_internal_expect_revert = true
    function testAddOperatorToLinglongSubset() public {
        // Create subset first
        linglongSubsets.createLinglongSubset(EIGENLAYER_VALIDATOR_SUBSET_ID, 0);

        // Test adding operator
        assertTrue(
            linglongSubsets.addOperatorToLinglongSubset(
                EIGENLAYER_VALIDATOR_SUBSET_ID, OPERATOR_1
            )
        );
        assertTrue(
            linglongSubsets.isOperatorInLinglongSubset(
                EIGENLAYER_VALIDATOR_SUBSET_ID, OPERATOR_1
            )
        );
        assertEq(
            linglongSubsets.getLinglongSubsetLength(EIGENLAYER_VALIDATOR_SUBSET_ID), 1
        );

        // Test adding duplicate operator
        assertFalse(
            linglongSubsets.addOperatorToLinglongSubset(
                EIGENLAYER_VALIDATOR_SUBSET_ID, OPERATOR_1
            )
        );

        // Test adding to non-existent subset
        // First ensure the subset doesn't exist
        assertFalse(
            linglongSubsets.isLinglongSubsetIdCreated(SYMBIOTIC_VALIDATOR_SUBSET_ID)
        );

        vm.expectRevert(
            OperatorSubsetLib.OperatorSetLib__OperatorSetDoesNotExist.selector
        );
        linglongSubsets.addOperatorToLinglongSubset(
            SYMBIOTIC_VALIDATOR_SUBSET_ID, OPERATOR_1
        );
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testRemoveOperatorFromLinglongSubset() public {
        // Setup
        linglongSubsets.createLinglongSubset(EIGENLAYER_VALIDATOR_SUBSET_ID, 0);
        linglongSubsets.addOperatorToLinglongSubset(
            EIGENLAYER_VALIDATOR_SUBSET_ID, OPERATOR_1
        );
        linglongSubsets.addOperatorToLinglongSubset(
            EIGENLAYER_VALIDATOR_SUBSET_ID, OPERATOR_2
        );

        // Test removing operator
        assertTrue(
            linglongSubsets.removeOperatorFromLinglongSubset(
                EIGENLAYER_VALIDATOR_SUBSET_ID, OPERATOR_1
            )
        );
        assertFalse(
            linglongSubsets.isOperatorInLinglongSubset(
                EIGENLAYER_VALIDATOR_SUBSET_ID, OPERATOR_1
            )
        );
        assertTrue(
            linglongSubsets.isOperatorInLinglongSubset(
                EIGENLAYER_VALIDATOR_SUBSET_ID, OPERATOR_2
            )
        );

        // Test removing non-existent operator
        assertFalse(
            linglongSubsets.removeOperatorFromLinglongSubset(
                EIGENLAYER_VALIDATOR_SUBSET_ID, OPERATOR_3
            )
        );

        // Test removing from non-existent subset
        vm.expectRevert(
            OperatorSubsetLib.OperatorSetLib__OperatorSetDoesNotExist.selector
        );
        linglongSubsets.removeOperatorFromLinglongSubset(
            SYMBIOTIC_VALIDATOR_SUBSET_ID, OPERATOR_1
        );
    }

    function testAddOperatorToLinglongSubsets() public {
        // Setup
        uint32[] memory subsetIds = new uint32[](2);
        subsetIds[0] = EIGENLAYER_VALIDATOR_SUBSET_ID;
        subsetIds[1] = EIGENLAYER_UNDERWRITER_SUBSET_ID;

        linglongSubsets.createLinglongSubset(subsetIds[0], 0);
        linglongSubsets.createLinglongSubset(subsetIds[1], 0);

        // Test adding operator to multiple subsets
        linglongSubsets.addOperatorToLinglongSubsets(subsetIds, OPERATOR_1);

        assertTrue(linglongSubsets.isOperatorInLinglongSubset(subsetIds[0], OPERATOR_1));
        assertTrue(linglongSubsets.isOperatorInLinglongSubset(subsetIds[1], OPERATOR_1));
    }

    function testRemoveOperatorFromLinglongSubsets() public {
        // Setup
        uint32[] memory subsetIds = new uint32[](2);
        subsetIds[0] = EIGENLAYER_VALIDATOR_SUBSET_ID;
        subsetIds[1] = EIGENLAYER_UNDERWRITER_SUBSET_ID;

        linglongSubsets.createLinglongSubset(subsetIds[0], 0);
        linglongSubsets.createLinglongSubset(subsetIds[1], 0);
        linglongSubsets.addOperatorToLinglongSubset(subsetIds[0], OPERATOR_1);
        linglongSubsets.addOperatorToLinglongSubset(subsetIds[1], OPERATOR_1);

        // Test removing operator from multiple subsets
        linglongSubsets.removeOperatorFromLinglongSubsets(subsetIds, OPERATOR_1);

        assertFalse(linglongSubsets.isOperatorInLinglongSubset(subsetIds[0], OPERATOR_1));
        assertFalse(linglongSubsets.isOperatorInLinglongSubset(subsetIds[1], OPERATOR_1));
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testGetOperatorsInLinglongSubset() public {
        // Setup
        linglongSubsets.createLinglongSubset(EIGENLAYER_VALIDATOR_SUBSET_ID, 0);
        linglongSubsets.addOperatorToLinglongSubset(
            EIGENLAYER_VALIDATOR_SUBSET_ID, OPERATOR_1
        );
        linglongSubsets.addOperatorToLinglongSubset(
            EIGENLAYER_VALIDATOR_SUBSET_ID, OPERATOR_2
        );

        // Test getting operators
        address[] memory operators =
            linglongSubsets.getOperatorsInLinglongSubset(EIGENLAYER_VALIDATOR_SUBSET_ID);
        assertEq(operators.length, 2);
        assertTrue(operators[0] == OPERATOR_1 || operators[1] == OPERATOR_1);
        assertTrue(operators[0] == OPERATOR_2 || operators[1] == OPERATOR_2);

        // Test getting from non-existent subset
        vm.expectRevert(
            OperatorSubsetLib.OperatorSetLib__OperatorSetDoesNotExist.selector
        );
        linglongSubsets.getOperatorsInLinglongSubset(SYMBIOTIC_VALIDATOR_SUBSET_ID);
    }

    function testGetLinglongSubsetsFromOperator() public {
        // Setup
        linglongSubsets.createLinglongSubset(EIGENLAYER_VALIDATOR_SUBSET_ID, 0);
        linglongSubsets.createLinglongSubset(EIGENLAYER_UNDERWRITER_SUBSET_ID, 0);
        linglongSubsets.addOperatorToLinglongSubset(
            EIGENLAYER_VALIDATOR_SUBSET_ID, OPERATOR_1
        );
        linglongSubsets.addOperatorToLinglongSubset(
            EIGENLAYER_UNDERWRITER_SUBSET_ID, OPERATOR_1
        );

        // Test getting subsets for operator
        uint32[] memory subsets =
            linglongSubsets.getLinglongSubsetsFromOperator(OPERATOR_1);
        assertEq(subsets.length, 2);
        assertTrue(
            subsets[0] == EIGENLAYER_VALIDATOR_SUBSET_ID
                || subsets[1] == EIGENLAYER_VALIDATOR_SUBSET_ID
        );
        assertTrue(
            subsets[0] == EIGENLAYER_UNDERWRITER_SUBSET_ID
                || subsets[1] == EIGENLAYER_UNDERWRITER_SUBSET_ID
        );
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testGetLinglongSubsetLength() public {
        // Setup
        linglongSubsets.createLinglongSubset(EIGENLAYER_VALIDATOR_SUBSET_ID, 0);
        linglongSubsets.addOperatorToLinglongSubset(
            EIGENLAYER_VALIDATOR_SUBSET_ID, OPERATOR_1
        );
        linglongSubsets.addOperatorToLinglongSubset(
            EIGENLAYER_VALIDATOR_SUBSET_ID, OPERATOR_2
        );

        // Test getting length
        assertEq(
            linglongSubsets.getLinglongSubsetLength(EIGENLAYER_VALIDATOR_SUBSET_ID), 2
        );

        // Test getting length of non-existent subset
        vm.expectRevert(
            OperatorSubsetLib.OperatorSetLib__OperatorSetDoesNotExist.selector
        );
        linglongSubsets.getLinglongSubsetLength(SYMBIOTIC_VALIDATOR_SUBSET_ID);
    }

    function testGetMinStake() public {
        uint256 minStake = 1000;
        linglongSubsets.createLinglongSubset(EIGENLAYER_VALIDATOR_SUBSET_ID, minStake);
        assertEq(linglongSubsets.getMinStake(EIGENLAYER_VALIDATOR_SUBSET_ID), minStake);
    }
}

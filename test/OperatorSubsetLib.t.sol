// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ITaiyiRegistryCoordinator } from
    "../src/interfaces/ITaiyiRegistryCoordinator.sol";
import { OperatorSubsetLib } from "../src/libs/OperatorSubsetLib.sol";

import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { Test } from "forge-std/Test.sol";

contract OperatorSubsetLibTest is Test {
    using OperatorSubsetLib for OperatorSubsetLib.OperatorSets;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.UintSet;
    using SafeCast for uint96;

    OperatorSubsetLib.OperatorSets internal operatorSets;

    uint96 internal constant TEST_BASE_ID_1 = 12_345;
    uint96 internal constant TEST_BASE_ID_2 = 67_890;
    uint96 internal constant MAX_BASE_ID = (uint96(1) << 91) - 1;
    uint96 internal constant TOO_LARGE_BASE_ID = (uint96(1) << 91);

    // Constants for uint32 tests
    uint32 internal constant TEST_BASE_ID_32_1 = 12_345;
    uint32 internal constant TEST_BASE_ID_32_2 = 67_890;
    uint32 internal constant MAX_BASE_ID_32 = (uint32(1) << 27) - 1;
    uint32 internal constant TOO_LARGE_BASE_ID_32 = (uint32(1) << 27);

    ITaiyiRegistryCoordinator.RestakingProtocol internal constant PROTOCOL_1 =
        ITaiyiRegistryCoordinator.RestakingProtocol.EIGENLAYER;
    ITaiyiRegistryCoordinator.RestakingProtocol internal constant PROTOCOL_2 =
        ITaiyiRegistryCoordinator.RestakingProtocol.SYMBIOTIC;

    address internal constant OPERATOR_1 = address(0x1001);
    address internal constant OPERATOR_2 = address(0x1002);
    address internal constant OPERATOR_3 = address(0x1003);

    function setUp() public {
        // Create a new instance of OperatorSets for each test
        delete operatorSets;
    }

    // --- Encoding & Decoding Tests ---

    function testEncodeDecode96() public pure {
        uint96 encodedId96_1 =
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1);
        uint96 encodedId96_2 =
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_2, PROTOCOL_2);
        uint96 encodedId96Max =
            OperatorSubsetLib.encodeOperatorSetId96(MAX_BASE_ID, PROTOCOL_1);

        (
            ITaiyiRegistryCoordinator.RestakingProtocol decodedProtocol,
            uint96 decodedBaseId
        ) = OperatorSubsetLib.decodeOperatorSetId96(encodedId96_1);
        assertEq(uint8(decodedProtocol), uint8(PROTOCOL_1), "Decoded protocol 1 mismatch");
        assertEq(decodedBaseId, TEST_BASE_ID_1, "Decoded baseId 1 mismatch");

        (decodedProtocol, decodedBaseId) =
            OperatorSubsetLib.decodeOperatorSetId96(encodedId96_2);
        assertEq(uint8(decodedProtocol), uint8(PROTOCOL_2), "Decoded protocol 2 mismatch");
        assertEq(decodedBaseId, TEST_BASE_ID_2, "Decoded baseId 2 mismatch");

        (decodedProtocol, decodedBaseId) =
            OperatorSubsetLib.decodeOperatorSetId96(encodedId96Max);
        assertEq(
            uint8(decodedProtocol), uint8(PROTOCOL_1), "Decoded protocol max mismatch"
        );
        assertEq(decodedBaseId, MAX_BASE_ID, "Decoded baseId max mismatch");
    }

    function testEncodeDecode32() public pure {
        uint32 encodedId32_1 =
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1);
        uint32 encodedId32_2 =
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_2, PROTOCOL_2);
        uint32 encodedId32Max =
            OperatorSubsetLib.encodeOperatorSetId32(MAX_BASE_ID_32, PROTOCOL_1);

        (
            ITaiyiRegistryCoordinator.RestakingProtocol decodedProtocol,
            uint32 decodedBaseId
        ) = OperatorSubsetLib.decodeOperatorSetId32(encodedId32_1);
        assertEq(
            uint8(decodedProtocol), uint8(PROTOCOL_1), "Decoded protocol 1 mismatch (32)"
        );
        assertEq(decodedBaseId, TEST_BASE_ID_32_1, "Decoded baseId 1 mismatch (32)");

        (decodedProtocol, decodedBaseId) =
            OperatorSubsetLib.decodeOperatorSetId32(encodedId32_2);
        assertEq(
            uint8(decodedProtocol), uint8(PROTOCOL_2), "Decoded protocol 2 mismatch (32)"
        );
        assertEq(decodedBaseId, TEST_BASE_ID_32_2, "Decoded baseId 2 mismatch (32)");

        (decodedProtocol, decodedBaseId) =
            OperatorSubsetLib.decodeOperatorSetId32(encodedId32Max);
        assertEq(
            uint8(decodedProtocol),
            uint8(PROTOCOL_1),
            "Decoded protocol max mismatch (32)"
        );
        assertEq(decodedBaseId, MAX_BASE_ID_32, "Decoded baseId max mismatch (32)");
    }

    function testGetters96() public pure {
        uint96 encodedId96_1 =
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1);
        uint96 encodedId96_2 =
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_2, PROTOCOL_2);

        assertEq(
            uint8(OperatorSubsetLib.getProtocolType96(encodedId96_1)),
            uint8(PROTOCOL_1),
            "getProtocolType 1 mismatch"
        );
        assertEq(
            OperatorSubsetLib.getBaseId96(encodedId96_1),
            TEST_BASE_ID_1,
            "getBaseId 1 mismatch"
        );

        assertEq(
            uint8(OperatorSubsetLib.getProtocolType96(encodedId96_2)),
            uint8(PROTOCOL_2),
            "getProtocolType 2 mismatch"
        );
        assertEq(
            OperatorSubsetLib.getBaseId96(encodedId96_2),
            TEST_BASE_ID_2,
            "getBaseId 2 mismatch"
        );
    }

    function testGetters32() public pure {
        uint32 encodedId32_1 =
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1);
        uint32 encodedId32_2 =
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_2, PROTOCOL_2);

        assertEq(
            uint8(OperatorSubsetLib.getProtocolType32(encodedId32_1)),
            uint8(PROTOCOL_1),
            "getProtocolType 1 mismatch (32)"
        );
        assertEq(
            OperatorSubsetLib.getBaseId32(encodedId32_1),
            TEST_BASE_ID_32_1,
            "getBaseId 1 mismatch (32)"
        );

        assertEq(
            uint8(OperatorSubsetLib.getProtocolType32(encodedId32_2)),
            uint8(PROTOCOL_2),
            "getProtocolType 2 mismatch (32)"
        );
        assertEq(
            OperatorSubsetLib.getBaseId32(encodedId32_2),
            TEST_BASE_ID_32_2,
            "getBaseId 2 mismatch (32)"
        );
    }

    // --- Set Management Tests ---

    function testCreateSet() public {
        uint96 encodedId96_1 =
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1);
        uint96 encodedId96_2 =
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_2, PROTOCOL_2);
        uint32 encodedId32_1 =
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1);
        uint32 encodedId32_2 =
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_2, PROTOCOL_2);

        assertTrue(
            operatorSets.createOperatorSet96(encodedId96_1, 0), "Create set 96_1 failed"
        );
        assertTrue(
            operatorSets.createOperatorSet96(encodedId96_2, 0), "Create set 96_2 failed"
        );
        assertTrue(
            operatorSets.createOperatorSet32(encodedId32_1, 0), "Create set 32_1 failed"
        );
        assertTrue(
            operatorSets.createOperatorSet32(encodedId32_2, 0), "Create set 32_2 failed"
        );
    }

    function testGetOperatorSetsEmpty() public view {
        uint96[] memory sets96 = operatorSets.getOperatorSets96();
        assertEq(sets96.length, 0, "Should return empty array when no 96-bit sets");

        uint32[] memory sets32 = operatorSets.getOperatorSets32();
        assertEq(sets32.length, 0, "Should return empty array when no 32-bit sets");
    }

    function testGetOperatorSets() public {
        // Create sets with consistent protocol types
        uint96 encodedId96_1 =
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1);
        uint96 encodedId96_2 =
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_2, PROTOCOL_1);
        uint32 encodedId32_1 =
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1);
        uint32 encodedId32_2 =
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_2, PROTOCOL_1);

        operatorSets.createOperatorSet96(encodedId96_1, 0);
        operatorSets.createOperatorSet96(encodedId96_2, 0);
        operatorSets.createOperatorSet32(encodedId32_1, 0);
        operatorSets.createOperatorSet32(encodedId32_2, 0);

        uint96[] memory sets96 = operatorSets.getOperatorSets96();
        assertEq(sets96.length, 2, "Incorrect number of 96-bit sets returned");
        bool found96_1 = false;
        bool found96_2 = false;
        for (uint256 i = 0; i < sets96.length; i++) {
            if (sets96[i] == encodedId96_1) found96_1 = true;
            if (sets96[i] == encodedId96_2) found96_2 = true;
        }
        assertTrue(found96_1, "Encoded ID 96_1 not found in getOperatorSets96 result");
        assertTrue(found96_2, "Encoded ID 96_2 not found in getOperatorSets96 result");

        uint32[] memory sets32 = operatorSets.getOperatorSets32();
        assertEq(sets32.length, 2, "Incorrect number of 32-bit sets returned");
        bool found32_1 = false;
        bool found32_2 = false;
        for (uint256 i = 0; i < sets32.length; i++) {
            if (sets32[i] == encodedId32_1) found32_1 = true;
            if (sets32[i] == encodedId32_2) found32_2 = true;
        }
        assertTrue(found32_1, "Encoded ID 32_1 not found in getOperatorSets32 result");
        assertTrue(found32_2, "Encoded ID 32_2 not found in getOperatorSets32 result");
    }

    // --- Operator Management Tests ---

    function testAddOperatorToSet() public {
        // Test 96-bit set
        operatorSets.createOperatorSet96(
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1), 0
        );
        assertTrue(
            operatorSets.addOperatorToSet96(
                OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1),
                OPERATOR_1
            ),
            "Add operator 1 to 96-bit set failed"
        );
        assertTrue(
            operatorSets.isOperatorInSet96(
                OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1),
                OPERATOR_1
            ),
            "Operator 1 not in 96-bit set after add"
        );
        assertEq(
            operatorSets.getOperatorSetLength96(
                OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1)
            ),
            1,
            "96-bit set length mismatch after add 1"
        );

        // Test 32-bit set
        operatorSets.createOperatorSet32(
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1), 0
        );
        assertTrue(
            operatorSets.addOperatorToSet32(
                OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1),
                OPERATOR_1
            ),
            "Add operator 1 to 32-bit set failed"
        );
        assertTrue(
            operatorSets.isOperatorInSet32(
                OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1),
                OPERATOR_1
            ),
            "Operator 1 not in 32-bit set after add"
        );
        assertEq(
            operatorSets.getOperatorSetLength32(
                OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1)
            ),
            1,
            "32-bit set length mismatch after add 1"
        );

        // Test duplicate additions
        assertFalse(
            operatorSets.addOperatorToSet96(
                OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1),
                OPERATOR_1
            ),
            "Add existing operator to 96-bit set should return false"
        );
        assertFalse(
            operatorSets.addOperatorToSet32(
                OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1),
                OPERATOR_1
            ),
            "Add existing operator to 32-bit set should return false"
        );

        // Add second operator to both sets
        assertTrue(
            operatorSets.addOperatorToSet96(
                OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1),
                OPERATOR_2
            ),
            "Add operator 2 to 96-bit set failed"
        );
        assertTrue(
            operatorSets.addOperatorToSet32(
                OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1),
                OPERATOR_2
            ),
            "Add operator 2 to 32-bit set failed"
        );

        // Verify operators in both sets
        address[] memory operators96 = operatorSets.getOperatorsInSet96(
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1)
        );
        address[] memory operators32 = operatorSets.getOperatorsInSet32(
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1)
        );
        assertEq(operators96.length, 2, "Incorrect number of operators in 96-bit set");
        assertEq(operators32.length, 2, "Incorrect number of operators in 32-bit set");
    }

    function testRemoveOperatorFromSet() public {
        // Setup for 96-bit set
        operatorSets.createOperatorSet96(
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1), 0
        );
        operatorSets.addOperatorToSet96(
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1),
            OPERATOR_1
        );
        operatorSets.addOperatorToSet96(
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1),
            OPERATOR_2
        );

        // Setup for 32-bit set
        operatorSets.createOperatorSet32(
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1), 0
        );
        operatorSets.addOperatorToSet32(
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1),
            OPERATOR_1
        );
        operatorSets.addOperatorToSet32(
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1),
            OPERATOR_2
        );

        // Test removing non-existent operator
        assertFalse(
            operatorSets.removeOperatorFromSet96(
                OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1),
                OPERATOR_3
            ),
            "Remove non-existent operator from 96-bit set should return false"
        );
        assertFalse(
            operatorSets.removeOperatorFromSet32(
                OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1),
                OPERATOR_3
            ),
            "Remove non-existent operator from 32-bit set should return false"
        );

        // Test removing operators
        assertTrue(
            operatorSets.removeOperatorFromSet96(
                OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1),
                OPERATOR_1
            ),
            "Remove operator 1 from 96-bit set failed"
        );
        assertTrue(
            operatorSets.removeOperatorFromSet32(
                OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1),
                OPERATOR_1
            ),
            "Remove operator 1 from 32-bit set failed"
        );

        // Verify removals
        assertFalse(
            operatorSets.isOperatorInSet96(
                OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1),
                OPERATOR_1
            ),
            "Operator 1 still in 96-bit set after remove"
        );
        assertFalse(
            operatorSets.isOperatorInSet32(
                OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1),
                OPERATOR_1
            ),
            "Operator 1 still in 32-bit set after remove"
        );

        // Verify remaining operators
        assertTrue(
            operatorSets.isOperatorInSet96(
                OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1),
                OPERATOR_2
            ),
            "Operator 2 affected by remove in 96-bit set"
        );
        assertTrue(
            operatorSets.isOperatorInSet32(
                OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1),
                OPERATOR_2
            ),
            "Operator 2 affected by remove in 32-bit set"
        );

        // Remove remaining operators
        assertTrue(
            operatorSets.removeOperatorFromSet96(
                OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1),
                OPERATOR_2
            ),
            "Remove operator 2 from 96-bit set failed"
        );
        assertTrue(
            operatorSets.removeOperatorFromSet32(
                OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1),
                OPERATOR_2
            ),
            "Remove operator 2 from 32-bit set failed"
        );

        // Verify empty sets
        assertEq(
            operatorSets.getOperatorSetLength96(
                OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1)
            ),
            0,
            "96-bit set length should be 0 after removing all operators"
        );
        assertEq(
            operatorSets.getOperatorSetLength32(
                OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1)
            ),
            0,
            "32-bit set length should be 0 after removing all operators"
        );
    }

    function testAddOperatorToSets() public {
        // Setup for 96-bit sets
        uint96[] memory encodedIds96 = new uint96[](2);
        encodedIds96[0] =
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1);
        encodedIds96[1] =
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_2, PROTOCOL_1);

        // Create the sets first using encoded IDs
        operatorSets.createOperatorSet96(encodedIds96[0], 0);
        operatorSets.createOperatorSet96(encodedIds96[1], 0);

        // Setup for 32-bit sets
        uint32[] memory encodedIds32 = new uint32[](2);
        encodedIds32[0] =
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1);
        encodedIds32[1] =
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_2, PROTOCOL_1);

        // Create the sets first using encoded IDs
        operatorSets.createOperatorSet32(encodedIds32[0], 0);
        operatorSets.createOperatorSet32(encodedIds32[1], 0);

        // Add operator to multiple sets using encoded IDs
        operatorSets.addOperatorToSets96(encodedIds96, PROTOCOL_1, OPERATOR_1);
        operatorSets.addOperatorToSets32(encodedIds32, PROTOCOL_1, OPERATOR_1);

        // Verify additions using encoded IDs
        assertTrue(
            operatorSets.isOperatorInSet96(encodedIds96[0], OPERATOR_1),
            "Operator 1 not in 96-bit set 1 after multi-add"
        );
        assertTrue(
            operatorSets.isOperatorInSet96(encodedIds96[1], OPERATOR_1),
            "Operator 1 not in 96-bit set 2 after multi-add"
        );
        assertTrue(
            operatorSets.isOperatorInSet32(encodedIds32[0], OPERATOR_1),
            "Operator 1 not in 32-bit set 1 after multi-add"
        );
        assertTrue(
            operatorSets.isOperatorInSet32(encodedIds32[1], OPERATOR_1),
            "Operator 1 not in 32-bit set 2 after multi-add"
        );
    }

    function testRemoveOperatorFromSets() public {
        // Setup for 96-bit sets
        uint96[] memory baseIds96 = new uint96[](2);
        baseIds96[0] = TEST_BASE_ID_1;
        baseIds96[1] = TEST_BASE_ID_2;

        uint96[] memory encodedIds96 = new uint96[](2);
        encodedIds96[0] =
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_1, PROTOCOL_1);
        encodedIds96[1] =
            OperatorSubsetLib.encodeOperatorSetId96(TEST_BASE_ID_2, PROTOCOL_1);

        // Create and populate 96-bit sets using encoded IDs
        operatorSets.createOperatorSet96(encodedIds96[0], 0);
        operatorSets.createOperatorSet96(encodedIds96[1], 0);
        operatorSets.addOperatorToSet96(encodedIds96[0], OPERATOR_1);
        operatorSets.addOperatorToSet96(encodedIds96[1], OPERATOR_1);

        // Setup for 32-bit sets
        uint32[] memory baseIds32 = new uint32[](2);
        baseIds32[0] = TEST_BASE_ID_32_1;
        baseIds32[1] = TEST_BASE_ID_32_2;

        uint32[] memory encodedIds32 = new uint32[](2);
        encodedIds32[0] =
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_1, PROTOCOL_1);
        encodedIds32[1] =
            OperatorSubsetLib.encodeOperatorSetId32(TEST_BASE_ID_32_2, PROTOCOL_1);

        // Create and populate 32-bit sets using encoded IDs
        operatorSets.createOperatorSet32(encodedIds32[0], 0);
        operatorSets.createOperatorSet32(encodedIds32[1], 0);
        operatorSets.addOperatorToSet32(encodedIds32[0], OPERATOR_1);
        operatorSets.addOperatorToSet32(encodedIds32[1], OPERATOR_1);

        // Remove operator from multiple sets using base IDs
        operatorSets.removeOperatorFromSets96(baseIds96, PROTOCOL_1, OPERATOR_1);
        operatorSets.removeOperatorFromSets32(baseIds32, PROTOCOL_1, OPERATOR_1);

        // Verify removals using encoded IDs
        assertFalse(
            operatorSets.isOperatorInSet96(encodedIds96[0], OPERATOR_1),
            "Operator 1 still in 96-bit set 1 after multi-remove"
        );
        assertFalse(
            operatorSets.isOperatorInSet96(encodedIds96[1], OPERATOR_1),
            "Operator 1 still in 96-bit set 2 after multi-remove"
        );
        assertFalse(
            operatorSets.isOperatorInSet32(encodedIds32[0], OPERATOR_1),
            "Operator 1 still in 32-bit set 1 after multi-remove"
        );
        assertFalse(
            operatorSets.isOperatorInSet32(encodedIds32[1], OPERATOR_1),
            "Operator 1 still in 32-bit set 2 after multi-remove"
        );
    }
}

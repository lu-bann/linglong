// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "../src/interfaces/ITaiyiRegistryCoordinator.sol";
import "../src/libs/RestakingProtocolMapLib.sol";
import "forge-std/Test.sol";

contract RestakingProtocolMapLibTest is Test {
    using RestakingProtocolMapLib for RestakingProtocolMapLib.Map;

    RestakingProtocolMapLib.Map private map;
    address private addr1 = address(0x1);
    address private addr2 = address(0x2);
    address private addr3 = address(0x3);
    address private addr4 = address(0x4);

    function setUp() public {
        // Initialize the map with some values
        map.set(addr1, ITaiyiRegistryCoordinator.RestakingProtocol.EIGENLAYER);
        map.set(addr2, ITaiyiRegistryCoordinator.RestakingProtocol.SYMBIOTIC);
        map.set(addr3, ITaiyiRegistryCoordinator.RestakingProtocol.EIGENLAYER);
    }

    function testSet() public {
        // Test adding a new address
        bool result =
            map.set(addr4, ITaiyiRegistryCoordinator.RestakingProtocol.SYMBIOTIC);
        assertTrue(result, "Should return true when adding a new address");
        assertEq(
            uint256(map.get(addr4)),
            uint256(ITaiyiRegistryCoordinator.RestakingProtocol.SYMBIOTIC),
            "Protocol should match what was set"
        );

        // Test updating an existing address
        result = map.set(addr1, ITaiyiRegistryCoordinator.RestakingProtocol.SYMBIOTIC);
        assertFalse(result, "Should return false when updating an existing address");
        assertEq(
            uint256(map.get(addr1)),
            uint256(ITaiyiRegistryCoordinator.RestakingProtocol.SYMBIOTIC),
            "Protocol should be updated"
        );

        // Test setting to NONE
        result = map.set(addr1, ITaiyiRegistryCoordinator.RestakingProtocol.NONE);
        assertTrue(result, "Should return true when removing via NONE");
        assertEq(
            uint256(map.get(addr1)),
            uint256(ITaiyiRegistryCoordinator.RestakingProtocol.NONE),
            "Protocol should be NONE"
        );
        assertFalse(map.contains(addr1), "Address should be removed when set to NONE");
    }

    function testRemove() public {
        bool result = map.remove(addr1);
        assertTrue(result, "Should return true when removing an existing address");

        result = map.remove(address(0x5));
        assertFalse(result, "Should return false when removing a non-existent address");

        assertFalse(map.contains(addr1), "Address should no longer exist in the map");
        assertEq(
            uint256(map.get(addr1)),
            uint256(ITaiyiRegistryCoordinator.RestakingProtocol.NONE),
            "Protocol should be NONE after removal"
        );
    }

    function testLength() public {
        assertEq(map.length(), 3, "Length should be 3 after setup");

        map.set(addr4, ITaiyiRegistryCoordinator.RestakingProtocol.EIGENLAYER);
        assertEq(map.length(), 4, "Length should be 4 after adding an address");

        map.remove(addr1);
        assertEq(map.length(), 3, "Length should be 3 after removing an address");
    }

    function testAddressAt() public view {
        // The order is not guaranteed by EnumerableSet, but we can test that
        // all addresses are accessible via index
        address[] memory allAddresses = new address[](3);
        for (uint256 i = 0; i < map.length(); i++) {
            allAddresses[i] = map.addressAt(i);
        }

        assertTrue(
            containsAddress(allAddresses, addr1) && containsAddress(allAddresses, addr2)
                && containsAddress(allAddresses, addr3),
            "All addresses should be accessible via index"
        );
    }

    function testAddresses() public view {
        address[] memory addresses = map.addresses();
        assertEq(addresses.length, 3, "Should return all 3 addresses");

        assertTrue(
            containsAddress(addresses, addr1) && containsAddress(addresses, addr2)
                && containsAddress(addresses, addr3),
            "All addresses should be in the array"
        );
    }

    function testAddressesByProtocol() public view {
        address[] memory eigenlayerAddresses = map.addressesByProtocol(
            ITaiyiRegistryCoordinator.RestakingProtocol.EIGENLAYER
        );
        assertEq(eigenlayerAddresses.length, 2, "Should return 2 EIGENLAYER addresses");
        assertTrue(
            containsAddress(eigenlayerAddresses, addr1)
                && containsAddress(eigenlayerAddresses, addr3),
            "Should contain all EIGENLAYER addresses"
        );

        address[] memory symbioticAddresses =
            map.addressesByProtocol(ITaiyiRegistryCoordinator.RestakingProtocol.SYMBIOTIC);
        assertEq(symbioticAddresses.length, 1, "Should return 1 SYMBIOTIC address");
        assertTrue(
            containsAddress(symbioticAddresses, addr2),
            "Should contain all SYMBIOTIC addresses"
        );
    }

    function testProtocolAt() public view {
        // Since we don't know the order in EnumerableSet, we'll verify all protocols
        // are accessible via index
        bool foundEigenlayer = false;
        bool foundSymbiotic = false;

        for (uint256 i = 0; i < map.length(); i++) {
            ITaiyiRegistryCoordinator.RestakingProtocol protocol = map.protocolAt(i);
            if (protocol == ITaiyiRegistryCoordinator.RestakingProtocol.EIGENLAYER) {
                foundEigenlayer = true;
            } else if (protocol == ITaiyiRegistryCoordinator.RestakingProtocol.SYMBIOTIC)
            {
                foundSymbiotic = true;
            }
        }

        assertTrue(foundEigenlayer, "Should find at least one EIGENLAYER protocol");
        assertTrue(foundSymbiotic, "Should find at least one SYMBIOTIC protocol");
    }

    // Helper function to check if an address is in an array
    function containsAddress(
        address[] memory addresses,
        address addr
    )
        private
        pure
        returns (bool)
    {
        for (uint256 i = 0; i < addresses.length; i++) {
            if (addresses[i] == addr) {
                return true;
            }
        }
        return false;
    }
}

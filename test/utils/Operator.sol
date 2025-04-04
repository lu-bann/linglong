// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import "forge-std/Test.sol";

/// @dev This file is adapted from EigenLayer's test deployment contract
/// @custom:attribution
/// https://github.com/eigenfoundation/eigenlayer-contracts/blob/dbfa12128a41341b936f3e8da5d6da58c6233877/src/test/utils/Operators.sol
contract Operators is Test {
    string internal operatorConfigJson;

    constructor() {
        operatorConfigJson = vm.readFile("./test/test-data/operators.json");
    }

    function operatorPrefix(uint256 index) public pure returns (string memory) {
        return string.concat(".operators[", string.concat(vm.toString(index), "]."));
    }

    function getNumOperators() public view returns (uint256) {
        return stdJson.readUint(operatorConfigJson, ".numOperators");
    }

    function getOperatorAddress(uint256 index) public view returns (address) {
        return stdJson.readAddress(
            operatorConfigJson, string.concat(operatorPrefix(index), "Address")
        );
    }

    function getOperatorSecretKey(uint256 index) public view returns (uint256) {
        return readUint(operatorConfigJson, index, "SecretKey");
    }

    function readUint(
        string memory json,
        uint256 index,
        string memory key
    )
        public
        pure
        returns (uint256)
    {
        return stringToUint(
            stdJson.readString(json, string.concat(operatorPrefix(index), key))
        );
    }

    function stringToUint(string memory s) public pure returns (uint256) {
        bytes memory b = bytes(s);
        uint256 result = 0;
        for (uint256 i = 0; i < b.length; i++) {
            if (uint256(uint8(b[i])) >= 48 && uint256(uint8(b[i])) <= 57) {
                result = result * 10 + (uint256(uint8(b[i])) - 48);
            }
        }
        return result;
    }

    function setOperatorJsonFilePath(string memory filepath) public {
        operatorConfigJson = vm.readFile(filepath);
    }
}

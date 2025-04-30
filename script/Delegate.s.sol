// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { IDelegationManager } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import { ISignatureUtilsMixin, ISignatureUtilsMixinTypes } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/ISignatureUtilsMixin.sol";
import { Script } from "forge-std/Script.sol";
import { Test, console } from "forge-std/Test.sol";

contract ConvertWETH is Script, Test {
    function run() public {
        vm.startBroadcast();
        address operatorAddress = vm.envAddress("OPERATOR_ADDRESS");
        ISignatureUtilsMixinTypes.SignatureWithExpiry memory approverSignatureAndExpiry =
            ISignatureUtilsMixinTypes.SignatureWithExpiry({ signature: "", expiry: 0 });

        address payable delegationManagerAddress =
            payable(vm.envAddress("DELEGATION_MANAGER_ADDRESS"));
        IDelegationManager delegationManager =
            IDelegationManager(delegationManagerAddress);

        delegationManager.delegateTo(operatorAddress, approverSignatureAndExpiry, "");

        vm.stopBroadcast();
    }
}

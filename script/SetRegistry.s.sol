// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { TaiyiCore } from "../src/taiyi/TaiyiCore.sol";

import "forge-std/Script.sol";
import "forge-std/Test.sol";

import { EigenLayerMiddleware } from "../src/eigenlayer-avs/EigenLayerMiddleware.sol";
import { TaiyiRegistryCoordinator } from
    "../src/operator-registries/TaiyiRegistryCoordinator.sol";
import { Reverter } from "./lib/Reverter.sol";
import { WETH9 } from "./lib/WETH.sol";

import { DeployFromScratch } from
    "../lib/eigenlayer-contracts/script/deploy/local/Deploy_From_Scratch.s.sol";

import { IAllocationManager } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IPauserRegistry } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";
import { IStrategy } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { IStrategyManager } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IStrategyManager.sol";
import { ERC1967Proxy } from
    "../lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import { ProxyAdmin } from
    "../lib/openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";

import { AllocationManager } from
    "../lib/eigenlayer-contracts/src/contracts/core/AllocationManager.sol";
import {
    ITransparentUpgradeableProxy,
    TransparentUpgradeableProxy
} from
    "../lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import { PubkeyRegistry } from "src/operator-registries/PubkeyRegistry.sol";
import { SocketRegistry } from "src/operator-registries/SocketRegistry.sol";
import { LinglongSlasher } from "src/slasher/LinglongSlasher.sol";

import { ITaiyiRegistryCoordinator } from "src/interfaces/ITaiyiRegistryCoordinator.sol";

import { IAVSRegistrar } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IAVSRegistrar.sol";
import { PermissionController } from
    "../lib/eigenlayer-contracts/src/contracts/permissions/PermissionController.sol";

import { EmptyContract } from "./lib/EmptyContract.sol";

import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { StdStorage, stdStorage } from "forge-std/Test.sol";

contract SetRegistry is Script, Test {
    using stdStorage for StdStorage;

    function run() public {
        // Get deployer address from private key
        string memory pkString = vm.envString("PROXY_OWNER_PRIVATE_KEY");
        string memory implPkString = vm.envString("IMPL_OWNER_PRIVATE_KEY");
        // Check if pkString starts with "0x"; if not, add the prefix.
        bytes memory pkBytes = bytes(pkString);
        if (pkBytes.length < 2 || pkBytes[0] != 0x30 || pkBytes[1] != 0x78) {
            pkString = string.concat("0x", pkString);
        }
        bytes memory implPkBytes = bytes(implPkString);
        if (implPkBytes.length < 2 || implPkBytes[0] != 0x30 || implPkBytes[1] != 0x78) {
            implPkString = string.concat("0x", implPkString);
        }
        uint256 proxyDeployerPrivateKey = vm.parseUint(pkString); // Parse as hex
        uint256 implPrivateKey = vm.parseUint(implPkString); // Parse as hex
        address proxyDeployer = vm.addr(proxyDeployerPrivateKey);

        string memory outputFile =
            string(bytes("script/output/devnet/taiyiAddresses.json"));
        string memory output_data = vm.readFile(outputFile);

        TaiyiRegistryCoordinator taiyiRegistryCoordinator = TaiyiRegistryCoordinator(
            stdJson.readAddress(output_data, ".taiyiAddresses.taiyiRegistryCoordinator")
        );

        EigenLayerMiddleware eigenLayerMiddleware = EigenLayerMiddleware(
            stdJson.readAddress(output_data, ".taiyiAddresses.eigenLayerMiddleware")
        );

        string memory eigenLayerOutputFile =
            string(bytes("script/output/devnet/M2_from_scratch_deployment_data.json"));

        string memory eigenLayerOutput_data = vm.readFile(eigenLayerOutputFile);
        // address wethStrategyAddr =
        //     stdJson.readAddress(eigenLayerOutput_data, ".addresses.strategies.WETH");
        address allocationManagerAddr =
            stdJson.readAddress(eigenLayerOutput_data, ".addresses.allocationManager");
        address permissionController =
            stdJson.readAddress(eigenLayerOutput_data, ".addresses.permissionController");

        AllocationManager allocationManager = AllocationManager(allocationManagerAddr);

        vm.startBroadcast(implPrivateKey);

        // Update registry coordinator with new registries
        eigenLayerMiddleware.addAdminToPermissionController(
            proxyDeployer, permissionController
        );
        vm.stopBroadcast();
        vm.startBroadcast(proxyDeployerPrivateKey);
        PermissionController controller = PermissionController(permissionController);
        controller.acceptAdmin(address(eigenLayerMiddleware));

        AllocationManager manager = AllocationManager(allocationManager);
        manager.setAVSRegistrar(
            address(eigenLayerMiddleware), IAVSRegistrar(taiyiRegistryCoordinator)
        );
        vm.stopBroadcast();
    }
}

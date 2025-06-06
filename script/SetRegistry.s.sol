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
    "../lib/eigenlayer-contracts/script/deploy/local/deploy_from_scratch.slashing.s.sol";

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

    // Network enum for better readability
    enum Network {
        DEVNET,
        HOLESKY,
        HOODI
    }

    function getNetwork() internal view returns (Network) {
        string memory network = vm.envString("NETWORK");

        if (
            keccak256(abi.encodePacked(network)) == keccak256(abi.encodePacked("holesky"))
        ) {
            return Network.HOLESKY;
        } else if (
            keccak256(abi.encodePacked(network)) == keccak256(abi.encodePacked("hoodi"))
        ) {
            return Network.HOODI;
        } else {
            return Network.DEVNET;
        }
    }

    function getOutputDir(Network network) internal pure returns (string memory) {
        if (network == Network.HOLESKY) {
            return "script/output/holesky";
        } else if (network == Network.HOODI) {
            return "script/output/hoodi";
        } else {
            return "script/output/devnet";
        }
    }

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
        address implDeployer = vm.addr(implPrivateKey);

        // Get network and set up paths
        Network network = getNetwork();
        string memory outputDir = getOutputDir(network);
        string memory outputFile =
            string(bytes(string.concat(outputDir, "/taiyiAddresses.json")));

        // Create output directory if it doesn't exist
        vm.createDir(outputDir, true);

        string memory output_data = vm.readFile(outputFile);

        TaiyiRegistryCoordinator taiyiRegistryCoordinator = TaiyiRegistryCoordinator(
            stdJson.readAddress(output_data, ".taiyiAddresses.taiyiRegistryCoordinator")
        );

        EigenLayerMiddleware eigenLayerMiddleware = EigenLayerMiddleware(
            stdJson.readAddress(output_data, ".taiyiAddresses.eigenLayerMiddleware")
        );

        // Get network-specific addresses
        address allocationManagerAddr;
        address permissionControllerAddr;

        if (network == Network.DEVNET) {
            // Devnet deployment - read from file
            string memory eigenLayerOutputFile = string(
                bytes(
                    "script/output/devnet/SLASHING_deploy_from_scratch_deployment_data.json"
                )
            );

            string memory eigenLayerOutput_data = vm.readFile(eigenLayerOutputFile);
            allocationManagerAddr =
                stdJson.readAddress(eigenLayerOutput_data, ".addresses.allocationManager");
            permissionControllerAddr = stdJson.readAddress(
                eigenLayerOutput_data, ".addresses.permissionController"
            );
        } else if (network == Network.HOLESKY) {
            // Use hardcoded addresses for Holesky and Hoodi
            allocationManagerAddr = 0x78469728304326CBc65f8f95FA756B0B73164462;
            permissionControllerAddr = 0x598cb226B591155F767dA17AfE7A2241a68C5C10;
        } else if (network == Network.HOODI) {
            // Use hardcoded addresses for Holesky and Hoodi
            allocationManagerAddr = 0x95a7431400F362F3647a69535C5666cA0133CAA0;
            permissionControllerAddr = 0xdcCF401fD121d8C542E96BC1d0078884422aFAD2;
        } else {
            revert("Invalid network");
        }

        AllocationManager allocationManager = AllocationManager(allocationManagerAddr);
        PermissionController controller = PermissionController(permissionControllerAddr);

        vm.startBroadcast(implPrivateKey);

        // Update registry coordinator with new registries
        eigenLayerMiddleware.addAdminToPermissionController(
            proxyDeployer, permissionControllerAddr
        );
        eigenLayerMiddleware.addAdminToPermissionController(
            implDeployer, permissionControllerAddr
        );

        vm.stopBroadcast();
        vm.startBroadcast(proxyDeployerPrivateKey);

        controller.acceptAdmin(address(eigenLayerMiddleware));

        controller.setAppointee(
            address(eigenLayerMiddleware),
            address(eigenLayerMiddleware),
            address(allocationManager),
            allocationManager.createOperatorSets.selector
        );

        allocationManager.setAVSRegistrar(
            address(eigenLayerMiddleware), IAVSRegistrar(taiyiRegistryCoordinator)
        );

        // Use the same metadata URI for all networks
        string memory metadataURI =
            "https://github.com/lu-bann/eigenlayer-metadata-uri/raw/67e76ca2b1c3344ce0a4b43fcff4b5f82b1b046a/metadata.json";

        allocationManager.updateAVSMetadataURI(address(eigenLayerMiddleware), metadataURI);
        vm.stopBroadcast();
    }
}

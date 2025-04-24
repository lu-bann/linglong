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

contract SetupContract is Script, Test {
    using stdStorage for StdStorage;

    function run() public {
        // Get deployer address from private key
        string memory implPkString = vm.envString("IMPL_OWNER_PRIVATE_KEY");

        bytes memory implPkBytes = bytes(implPkString);
        if (implPkBytes.length < 2 || implPkBytes[0] != 0x30 || implPkBytes[1] != 0x78) {
            implPkString = string.concat("0x", implPkString);
        }
        uint256 implPrivateKey = vm.parseUint(implPkString); // Parse as hex
        address implOwner = vm.addr(implPrivateKey);

        string memory outputFile =
            string(bytes("script/output/devnet/taiyiAddresses.json"));
        string memory output_data = vm.readFile(outputFile);

        address socketRegistry =
            stdJson.readAddress(output_data, ".taiyiAddresses.socketRegistry");
        address pubkeyRegistry =
            stdJson.readAddress(output_data, ".taiyiAddresses.pubkeyRegistry");

        TaiyiRegistryCoordinator taiyiRegistryCoordinator = TaiyiRegistryCoordinator(
            stdJson.readAddress(output_data, ".taiyiAddresses.taiyiRegistryCoordinator")
        );

        EigenLayerMiddleware eigenLayerMiddleware = EigenLayerMiddleware(
            stdJson.readAddress(output_data, ".taiyiAddresses.eigenLayerMiddleware")
        );

        LinglongSlasher linglongSlasher = LinglongSlasher(
            stdJson.readAddress(output_data, ".taiyiAddresses.linglongSlasher")
        );
        string memory eigenLayerOutputFile =
            string(bytes("script/output/devnet/M2_from_scratch_deployment_data.json"));

        string memory eigenLayerOutput_data = vm.readFile(eigenLayerOutputFile);
        address wethStrategyAddr =
            stdJson.readAddress(eigenLayerOutput_data, ".addresses.strategies.WETH");
        address allocationManagerAddr =
            stdJson.readAddress(eigenLayerOutput_data, ".addresses.allocationManager");

        AllocationManager allocationManager = AllocationManager(allocationManagerAddr);

        vm.startBroadcast(implPrivateKey);
        // Update registry coordinator with new registries
        taiyiRegistryCoordinator.updateSocketRegistry(address(socketRegistry));
        taiyiRegistryCoordinator.updatePubkeyRegistry(address(pubkeyRegistry));

        linglongSlasher.setEigenLayerMiddleware(address(eigenLayerMiddleware));
        taiyiRegistryCoordinator.setRestakingProtocol(
            address(eigenLayerMiddleware),
            ITaiyiRegistryCoordinator.RestakingProtocol.EIGENLAYER
        );

        IStrategy[] memory strategies = new IStrategy[](1);
        strategies[0] = IStrategy(wethStrategyAddr);

        uint32 validatorOperatorSetId = eigenLayerMiddleware.createOperatorSet(strategies);
        uint32 underwriterOperatorSetId =
            eigenLayerMiddleware.createOperatorSet(strategies);

        OperatorSet memory opSet;
        opSet.id = validatorOperatorSetId;
        opSet.avs = address(eigenLayerMiddleware);

        bool exists = allocationManager.isOperatorSet(opSet);

        assert(exists);

        opSet.id = underwriterOperatorSetId;
        opSet.avs = address(eigenLayerMiddleware);

        exists = allocationManager.isOperatorSet(opSet);

        assert(exists);
        console.log("validator operator set id ", validatorOperatorSetId);
        console.log("underwriter operator set id ", underwriterOperatorSetId);

        vm.serializeUint(
            "operatorSetId", "validatorOperatorSetId", validatorOperatorSetId
        );
        string memory operatorSetId = vm.serializeUint(
            "operatorSetId", "underwriterOperatorSetId", underwriterOperatorSetId
        );

        string memory output = "output";
        vm.serializeString(output, "operatorSetId", operatorSetId);
        string memory finalJ = vm.serializeString(output, "operatorSetId", operatorSetId);
        vm.writeJson(finalJ, "script/output/devnet/operatorSetId.json");
        vm.stopBroadcast();
    }
}
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

import { OperatorSubsetLib } from "src/libs/OperatorSubsetLib.sol";

contract SetupContract is Script, Test {
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

    function getNetworkAddresses(Network network)
        internal
        view
        returns (address wethStrategyAddr, address allocationManagerAddr)
    {
        if (network == Network.DEVNET) {
            string memory eigenLayerOutputFile = string(
                bytes(
                    "script/output/devnet/SLASHING_deploy_from_scratch_deployment_data.json"
                )
            );

            string memory eigenLayerOutput_data = vm.readFile(eigenLayerOutputFile);
            wethStrategyAddr =
                stdJson.readAddress(eigenLayerOutput_data, ".addresses.strategies.WETH");
            allocationManagerAddr =
                stdJson.readAddress(eigenLayerOutput_data, ".addresses.allocationManager");
        } else if (network == Network.HOLESKY) {
            allocationManagerAddr = 0x78469728304326CBc65f8f95FA756B0B73164462;
            wethStrategyAddr = 0xdfB5f6CE42aAA7830E94ECFCcAd411beF4d4D5b6;
        } else if (network == Network.HOODI) {
            allocationManagerAddr = 0x95a7431400F362F3647a69535C5666cA0133CAA0;
            wethStrategyAddr = 0x24579aD4fe83aC53546E5c2D3dF5F85D6383420d;
        } else {
            revert("Invalid network");
        }
    }

    function getContractAddresses(string memory output_data)
        internal
        view
        returns (
            address socketRegistry,
            address pubkeyRegistry,
            address taiyiRegistryCoordinatorAddr,
            address eigenLayerMiddlewareAddr,
            address linglongSlasherAddr
        )
    {
        socketRegistry =
            stdJson.readAddress(output_data, ".taiyiAddresses.socketRegistryImpl");
        pubkeyRegistry =
            stdJson.readAddress(output_data, ".taiyiAddresses.pubkeyRegistryImpl");
        taiyiRegistryCoordinatorAddr =
            stdJson.readAddress(output_data, ".taiyiAddresses.taiyiRegistryCoordinator");
        eigenLayerMiddlewareAddr =
            stdJson.readAddress(output_data, ".taiyiAddresses.eigenLayerMiddleware");
        linglongSlasherAddr =
            stdJson.readAddress(output_data, ".taiyiAddresses.linglongSlasher");
    }

    function setupOperatorSets(
        EigenLayerMiddleware eigenLayerMiddleware,
        address wethStrategyAddr,
        address allocationManagerAddr
    )
        internal
        returns (uint32 validatorOperatorSetId, uint32 underwriterOperatorSetId)
    {
        IStrategy[] memory strategies = new IStrategy[](1);
        strategies[0] = IStrategy(wethStrategyAddr);

        validatorOperatorSetId = eigenLayerMiddleware.createOperatorSet(
            strategies, OperatorSubsetLib.EIGENLAYER_VALIDATOR_SUBSET_ID, 0
        );
        underwriterOperatorSetId = eigenLayerMiddleware.createOperatorSet(
            strategies, OperatorSubsetLib.EIGENLAYER_UNDERWRITER_SUBSET_ID, 0
        );

        verifyOperatorSets(
            validatorOperatorSetId,
            underwriterOperatorSetId,
            address(eigenLayerMiddleware),
            allocationManagerAddr
        );
    }

    function verifyOperatorSets(
        uint32 validatorOperatorSetId,
        uint32 underwriterOperatorSetId,
        address eigenLayerMiddleware,
        address allocationManagerAddr
    )
        internal
        view
    {
        AllocationManager allocationManager = AllocationManager(allocationManagerAddr);

        OperatorSet memory opSet;
        opSet.id = validatorOperatorSetId;
        opSet.avs = eigenLayerMiddleware;
        assert(allocationManager.isOperatorSet(opSet));

        opSet.id = underwriterOperatorSetId;
        opSet.avs = eigenLayerMiddleware;
        assert(allocationManager.isOperatorSet(opSet));
    }

    function saveOperatorSetIds(
        string memory outputDir,
        uint32 validatorOperatorSetId,
        uint32 underwriterOperatorSetId
    )
        internal
    {
        vm.serializeUint(
            "operatorSetId", "validatorOperatorSetId", validatorOperatorSetId
        );
        string memory operatorSetId = vm.serializeUint(
            "operatorSetId", "underwriterOperatorSetId", underwriterOperatorSetId
        );

        string memory output = "output";
        vm.serializeString(output, "operatorSetId", operatorSetId);
        string memory finalJ = vm.serializeString(output, "operatorSetId", operatorSetId);

        string memory outputPath =
            string(bytes(string.concat(outputDir, "/operatorSetId.json")));
        vm.writeJson(finalJ, outputPath);
    }

    function setupContracts(
        address socketRegistry,
        address pubkeyRegistry,
        address eigenLayerMiddlewareAddr,
        TaiyiRegistryCoordinator taiyiRegistryCoordinator,
        LinglongSlasher linglongSlasher
    )
        internal
    {
        taiyiRegistryCoordinator.updateSocketRegistry(socketRegistry);
        taiyiRegistryCoordinator.updatePubkeyRegistry(pubkeyRegistry);

        linglongSlasher.setEigenLayerMiddleware(eigenLayerMiddlewareAddr);
        taiyiRegistryCoordinator.setRestakingProtocol(
            eigenLayerMiddlewareAddr,
            ITaiyiRegistryCoordinator.RestakingProtocol.EIGENLAYER
        );
    }

    function executeSetup(
        uint256 implPrivateKey,
        string memory outputDir,
        address socketRegistry,
        address pubkeyRegistry,
        address taiyiRegistryCoordinatorAddr,
        address eigenLayerMiddlewareAddr,
        address linglongSlasherAddr,
        address wethStrategyAddr,
        address allocationManagerAddr
    )
        internal
    {
        TaiyiRegistryCoordinator taiyiRegistryCoordinator =
            TaiyiRegistryCoordinator(taiyiRegistryCoordinatorAddr);
        EigenLayerMiddleware eigenLayerMiddleware =
            EigenLayerMiddleware(eigenLayerMiddlewareAddr);
        LinglongSlasher linglongSlasher = LinglongSlasher(linglongSlasherAddr);

        vm.startBroadcast(implPrivateKey);

        setupContracts(
            socketRegistry,
            pubkeyRegistry,
            eigenLayerMiddlewareAddr,
            taiyiRegistryCoordinator,
            linglongSlasher
        );

        (uint32 validatorOperatorSetId, uint32 underwriterOperatorSetId) =
        setupOperatorSets(eigenLayerMiddleware, wethStrategyAddr, allocationManagerAddr);

        console.log("validator operator set id ", validatorOperatorSetId);
        console.log("underwriter operator set id ", underwriterOperatorSetId);

        saveOperatorSetIds(outputDir, validatorOperatorSetId, underwriterOperatorSetId);

        vm.stopBroadcast();
    }

    function run() public {
        // Get deployer address from private key
        string memory implPkString = vm.envString("IMPL_OWNER_PRIVATE_KEY");

        bytes memory implPkBytes = bytes(implPkString);
        if (implPkBytes.length < 2 || implPkBytes[0] != 0x30 || implPkBytes[1] != 0x78) {
            implPkString = string.concat("0x", implPkString);
        }
        uint256 implPrivateKey = vm.parseUint(implPkString);

        // Get network and set up paths
        Network network = getNetwork();
        string memory outputDir = getOutputDir(network);
        string memory outputFile =
            string(bytes(string.concat(outputDir, "/taiyiAddresses.json")));

        // Create output directory if it doesn't exist
        vm.createDir(outputDir, true);

        string memory output_data = vm.readFile(outputFile);

        (
            address socketRegistry,
            address pubkeyRegistry,
            address taiyiRegistryCoordinatorAddr,
            address eigenLayerMiddlewareAddr,
            address linglongSlasherAddr
        ) = getContractAddresses(output_data);

        (address wethStrategyAddr, address allocationManagerAddr) =
            getNetworkAddresses(network);

        executeSetup(
            implPrivateKey,
            outputDir,
            socketRegistry,
            pubkeyRegistry,
            taiyiRegistryCoordinatorAddr,
            eigenLayerMiddlewareAddr,
            linglongSlasherAddr,
            wethStrategyAddr,
            allocationManagerAddr
        );
    }
}

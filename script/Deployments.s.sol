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
import {
    ITransparentUpgradeableProxy,
    TransparentUpgradeableProxy
} from
    "../lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import { IRegistry } from "@urc/IRegistry.sol";
import { Registry } from "@urc/Registry.sol";
import { PubkeyRegistry } from "src/operator-registries/PubkeyRegistry.sol";
import { SocketRegistry } from "src/operator-registries/SocketRegistry.sol";
import { LinglongSlasher } from "src/slasher/LinglongSlasher.sol";

import { ITaiyiRegistryCoordinator } from "src/interfaces/ITaiyiRegistryCoordinator.sol";

import { IAVSRegistrar } from
    "../lib/eigenlayer-contracts/src/contracts/interfaces/IAVSRegistrar.sol";
import { PermissionController } from
    "../lib/eigenlayer-contracts/src/contracts/permissions/PermissionController.sol";

import { EmptyContract } from "./lib/EmptyContract.sol";
import { StdStorage, stdStorage } from "forge-std/Test.sol";

import { IEigenLayerMiddleware } from "src/interfaces/IEigenLayerMiddleware.sol";

contract Deploy is Script, Test {
    using stdStorage for StdStorage;

    address public avsDirectory;
    address public delegationManager;
    address public strategyManagerAddr;
    address public eigenPodManager;
    address public rewardInitiator;
    address public rewardCoordinator;
    address public allocationManager;
    address public eigenPauserReg;
    address public permissionController;
    address public deployer;
    address public urc;
    address public implOwner;

    LinglongSlasher public linglongSlasher;
    EigenLayerMiddleware public eigenLayerMiddleware;
    TaiyiRegistryCoordinator public taiyiRegistryCoordinator;

    function deployEigenLayer(string memory configFileName) internal {
        DeployFromScratch deployFromScratch = new DeployFromScratch();
        deployFromScratch.run(configFileName);

        string memory outputFile =
            string(bytes("script/output/devnet/M2_from_scratch_deployment_data.json"));
        string memory output_data = vm.readFile(outputFile);

        // whitelist weth
        address strategyWethAddr =
            stdJson.readAddress(output_data, ".addresses.strategies.WETH");
        strategyManagerAddr =
            stdJson.readAddress(output_data, ".addresses.strategyManager");
        IStrategy strategyWeth = IStrategy(strategyWethAddr);
        IStrategy[] memory strategiesToWhitelist = new IStrategy[](1);
        bool[] memory thirdPartyTransfersForbiddenValues = new bool[](1);
        strategiesToWhitelist[0] = strategyWeth;
        thirdPartyTransfersForbiddenValues[0] = true;
        IStrategyManager strategyManager = IStrategyManager(strategyManagerAddr);
        vm.startBroadcast();
        strategyManager.addStrategiesToDepositWhitelist(strategiesToWhitelist);
        vm.stopBroadcast();

        avsDirectory = stdJson.readAddress(output_data, ".addresses.avsDirectory");
        delegationManager =
            stdJson.readAddress(output_data, ".addresses.delegationManager");
        strategyManagerAddr =
            stdJson.readAddress(output_data, ".addresses.strategyManager");
        eigenPodManager = stdJson.readAddress(output_data, ".addresses.eigenPodManager");
        rewardCoordinator =
            stdJson.readAddress(output_data, ".addresses.rewardsCoordinator");
        allocationManager =
            stdJson.readAddress(output_data, ".addresses.allocationManager");
        eigenPauserReg =
            stdJson.readAddress(output_data, ".addresses.eigenLayerPauserReg");
        permissionController =
            stdJson.readAddress(output_data, ".addresses.permissionController");
    }

    function run(string memory configFileName) public {
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
        deployer = vm.addr(proxyDeployerPrivateKey);
        implOwner = vm.addr(implPrivateKey);

        string memory network = vm.envString("NETWORK");

        string memory taiyiAddresses = "taiyiAddresses";

        vm.createDir("script/output/devnet", true);

        if (keccak256(abi.encodePacked(network)) == keccak256(abi.encodePacked("devnet")))
        {
            vm.startBroadcast(proxyDeployerPrivateKey);
            WETH9 weth = new WETH9();
            emit log_address(address(weth));
            vm.serializeAddress(taiyiAddresses, "weth", address(weth));

            Reverter reverter = new Reverter();
            emit log_address(address(reverter));
            vm.serializeAddress(taiyiAddresses, "reverter", address(reverter));
            vm.stopBroadcast();

            deployEigenLayer(configFileName);

            IRegistry.Config memory config = IRegistry.Config({
                minCollateralWei: 0.1 ether,
                fraudProofWindow: 7200,
                unregistrationDelay: 7200,
                slashWindow: 7200,
                optInDelay: 7200
            });

            Registry registry = new Registry(config);
            emit log_address(address(registry));
            urc = address(registry);
        } else if (
            keccak256(abi.encodePacked(network)) == keccak256(abi.encodePacked("holesky"))
        ) {
            // holesky address reference: https://github.com/Layr-Labs/eigenlayer-contracts/tree/testnet-holesky
            avsDirectory = 0x055733000064333CaDDbC92763c58BF0192fFeBf;
            delegationManager = 0xA44151489861Fe9e3055d95adC98FbD462B948e7;
            strategyManagerAddr = 0xdfB5f6CE42aAA7830E94ECFCcAd411beF4d4D5b6;
            eigenPodManager = 0x30770d7E3e71112d7A6b7259542D1f680a70e315;
            rewardCoordinator = 0xAcc1fb458a1317E886dB376Fc8141540537E68fE;
            allocationManager = 0x78469728304326CBc65f8f95FA756B0B73164462;
            permissionController = 0x0000000000000000000000000000000000000000;
            // TODO: update this
            urc = 0x0000000000000000000000000000000000000000;
        }
        rewardInitiator = address(0xd8F3183DEf51a987222d845Be228E0bBB932c292); // Arbitrary address
        vm.startBroadcast(proxyDeployerPrivateKey);

        EmptyContract emptyContract = new EmptyContract();

        TransparentUpgradeableProxy taiyiRegistryCoordinatorProxy =
            new TransparentUpgradeableProxy(address(emptyContract), deployer, "");

        bytes32 taiyiRegistryCoordinatorProxyAdmin = vm.load(
            address(taiyiRegistryCoordinatorProxy),
            0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
        );
        address taiyiRegistryCoordinatorProxyAdminAddress =
            address(uint160(uint256(taiyiRegistryCoordinatorProxyAdmin)));

        TaiyiRegistryCoordinator taiyiRegistryCoordinator =
            TaiyiRegistryCoordinator(address(taiyiRegistryCoordinatorProxy));

        TransparentUpgradeableProxy linglongSlasherProxy =
            new TransparentUpgradeableProxy(address(emptyContract), deployer, "");

        bytes32 linglongSlasherProxyAdmin = vm.load(
            address(linglongSlasherProxy),
            0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
        );
        address linglongSlasherProxyAdminAddress =
            address(uint160(uint256(linglongSlasherProxyAdmin)));

        LinglongSlasher linglongSlasher = LinglongSlasher(address(linglongSlasherProxy));

        TransparentUpgradeableProxy pubkeyRegistryProxy =
            new TransparentUpgradeableProxy(address(emptyContract), deployer, "");

        bytes32 pubkeyRegistryProxyAdmin = vm.load(
            address(pubkeyRegistryProxy),
            0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
        );
        address pubkeyRegistryProxyAdminAddress =
            address(uint160(uint256(pubkeyRegistryProxyAdmin)));

        PubkeyRegistry pubkeyRegistry = PubkeyRegistry(address(pubkeyRegistryProxy));

        TransparentUpgradeableProxy socketRegistryProxy =
            new TransparentUpgradeableProxy(address(emptyContract), deployer, "");

        bytes32 socketRegistryProxyAdmin = vm.load(
            address(socketRegistryProxy),
            0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
        );
        address socketRegistryProxyAdminAddress =
            address(uint160(uint256(socketRegistryProxyAdmin)));

        SocketRegistry socketRegistry = SocketRegistry(address(socketRegistryProxy));

        TransparentUpgradeableProxy eigenLayerMiddlewareProxy =
            new TransparentUpgradeableProxy(address(emptyContract), deployer, "");

        bytes32 eigenLayerMiddlewareProxyAdmin = vm.load(
            address(eigenLayerMiddlewareProxy),
            0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
        );
        address eigenLayerMiddlewareProxyAdminAddress =
            address(uint160(uint256(eigenLayerMiddlewareProxyAdmin)));

        EigenLayerMiddleware eigenLayerMiddleware =
            EigenLayerMiddleware(address(eigenLayerMiddlewareProxy));

        TransparentUpgradeableProxy taiyiCoreProxy =
            new TransparentUpgradeableProxy(address(emptyContract), deployer, "");

        bytes32 taiyiCoreProxyAdmin = vm.load(
            address(taiyiCoreProxy),
            0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
        );
        address taiyiCoreProxyAdminAddress =
            address(uint160(uint256(taiyiCoreProxyAdmin)));

        TaiyiCore taiyiCore = TaiyiCore(payable(address(taiyiCoreProxy)));
        ///###################################
        // Deploy TaiyiRegistryCoordinator implementation and proxy
        TaiyiRegistryCoordinator registryCoordinatorImpl = new TaiyiRegistryCoordinator(
            IAllocationManager(allocationManager),
            IPauserRegistry(eigenPauserReg),
            "TaiyiRegistryCoordinator"
        );

        ProxyAdmin(taiyiRegistryCoordinatorProxyAdminAddress).upgradeAndCall(
            ITransparentUpgradeableProxy(address(taiyiRegistryCoordinator)),
            address(registryCoordinatorImpl),
            abi.encodeWithSelector(
                TaiyiRegistryCoordinator.initialize.selector,
                implOwner,
                0,
                allocationManager,
                eigenPauserReg
            )
        );

        emit log_address(address(registryCoordinatorImpl));

        vm.serializeAddress(
            "taiyiAddresses",
            "taiyiRegistryCoordinatorImpl",
            address(registryCoordinatorImpl)
        );
        vm.serializeAddress(
            "taiyiAddresses",
            "taiyiRegistryCoordinator",
            address(taiyiRegistryCoordinatorProxy)
        );
        vm.serializeAddress(
            "taiyiAddresses",
            "taiyiRegistryCoordinatorProxyAdminAddress",
            taiyiRegistryCoordinatorProxyAdminAddress
        );

        ///###################################

        LinglongSlasher slasherImpl = new LinglongSlasher();
        ProxyAdmin(linglongSlasherProxyAdminAddress).upgradeAndCall(
            ITransparentUpgradeableProxy(address(linglongSlasher)),
            address(slasherImpl),
            abi.encodeWithSelector(
                LinglongSlasher.initialize.selector, implOwner, allocationManager
            )
        );

        vm.serializeAddress("taiyiAddresses", "linglongSlasherImpl", address(slasherImpl));
        vm.serializeAddress("taiyiAddresses", "linglongSlasher", address(linglongSlasher));
        vm.serializeAddress(
            "taiyiAddresses",
            "linglongSlasherProxyAdminAddress",
            linglongSlasherProxyAdminAddress
        );
        ///###################################
        PubkeyRegistry pubkeyRegistryImpl = new PubkeyRegistry(taiyiRegistryCoordinator);
        ProxyAdmin(pubkeyRegistryProxyAdminAddress).upgradeAndCall(
            ITransparentUpgradeableProxy(address(pubkeyRegistry)),
            address(pubkeyRegistryImpl),
            ""
        );
        vm.serializeAddress(
            "taiyiAddresses", "pubkeyRegistryImpl", address(pubkeyRegistryImpl)
        );
        vm.serializeAddress("taiyiAddresses", "pubkeyRegistry", address(pubkeyRegistry));
        vm.serializeAddress(
            "taiyiAddresses",
            "pubkeyRegistryProxyAdminAddress",
            pubkeyRegistryProxyAdminAddress
        );
        ///###################################

        SocketRegistry socketRegistryImpl = new SocketRegistry(taiyiRegistryCoordinator);
        ProxyAdmin(socketRegistryProxyAdminAddress).upgradeAndCall(
            ITransparentUpgradeableProxy(address(socketRegistry)),
            address(socketRegistryImpl),
            ""
        );
        vm.serializeAddress(
            "taiyiAddresses", "socketRegistryImpl", address(socketRegistryImpl)
        );
        vm.serializeAddress("taiyiAddresses", "socketRegistry", address(socketRegistry));
        vm.serializeAddress(
            "taiyiAddresses",
            "socketRegistryProxyAdminAddress",
            socketRegistryProxyAdminAddress
        );
        ///###################################

        EigenLayerMiddleware eigenLayerMiddlewareImpl = new EigenLayerMiddleware();
        IEigenLayerMiddleware.Config memory config = IEigenLayerMiddleware.Config({
            avsDirectory: avsDirectory,
            delegationManager: delegationManager,
            rewardCoordinator: rewardCoordinator,
            rewardInitiator: rewardInitiator,
            registryCoordinator: address(taiyiRegistryCoordinatorProxy),
            underwriterShareBips: 8000,
            registry: urc,
            slasher: address(linglongSlasherProxy),
            allocationManager: allocationManager,
            registrationMinCollateral: 0
        });
        ProxyAdmin(eigenLayerMiddlewareProxyAdminAddress).upgradeAndCall(
            ITransparentUpgradeableProxy(address(eigenLayerMiddleware)),
            address(eigenLayerMiddlewareImpl),
            abi.encodeWithSelector(
                EigenLayerMiddleware.initialize.selector, implOwner, config
            )
        );

        vm.serializeAddress(
            "taiyiAddresses",
            "eigenLayerMiddlewareImpl",
            address(eigenLayerMiddlewareImpl)
        );
        vm.serializeAddress(
            "taiyiAddresses", "eigenLayerMiddleware", address(eigenLayerMiddleware)
        );
        vm.serializeAddress(
            "taiyiAddresses",
            "eigenLayerMiddlewareProxyAdminAddress",
            eigenLayerMiddlewareProxyAdminAddress
        );

        ///###################################
        TaiyiCore taiyiCoreImpl = new TaiyiCore();
        ProxyAdmin(taiyiCoreProxyAdminAddress).upgradeAndCall(
            ITransparentUpgradeableProxy(address(taiyiCore)),
            address(taiyiCoreImpl),
            abi.encodeWithSelector(TaiyiCore.initialize.selector, implOwner)
        );

        vm.serializeAddress("taiyiAddresses", "taiyiCoreImpl", address(taiyiCoreImpl));
        vm.serializeAddress("taiyiAddresses", "taiyiCore", address(taiyiCore));
        string memory addresses = vm.serializeAddress(
            "taiyiAddresses", "taiyiCoreProxyAdminAddress", taiyiCoreProxyAdminAddress
        );

        string memory output = "output";
        string memory finalJ = vm.serializeString(output, "taiyiAddresses", addresses);
        vm.writeJson(finalJ, "script/output/devnet/taiyiAddresses.json");

        vm.stopBroadcast();
    }
}
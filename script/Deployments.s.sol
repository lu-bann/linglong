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

import { AllocationManager } from
    "../lib/eigenlayer-contracts/src/contracts/core/AllocationManager.sol";
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

    // Constant for admin storage slot
    bytes32 constant ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    // Store proxy information
    struct ProxyInfo {
        address proxy;
        address admin;
    }

    // Proxies
    ProxyInfo internal registryCoordinatorInfo;
    ProxyInfo internal linglongSlasherInfo;
    ProxyInfo internal pubkeyRegistryInfo;
    ProxyInfo internal socketRegistryInfo;
    ProxyInfo internal eigenLayerMiddlewareInfo;
    ProxyInfo internal taiyiCoreInfo;

    // Helper struct for temporary storage
    struct DeploymentContracts {
        EmptyContract emptyContract;
        TaiyiRegistryCoordinator taiyiRegistryCoordinator;
        LinglongSlasher linglongSlasher;
        PubkeyRegistry pubkeyRegistry;
        SocketRegistry socketRegistry;
        EigenLayerMiddleware eigenLayerMiddleware;
        TaiyiCore taiyiCore;
    }

    DeploymentContracts internal deployedContracts;

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

    // Helper function to create and setup a proxy
    function createProxy(
        address emptyImpl,
        address admin,
        bytes memory data
    )
        internal
        returns (ProxyInfo memory)
    {
        TransparentUpgradeableProxy proxy =
            new TransparentUpgradeableProxy(emptyImpl, admin, data);

        bytes32 proxyAdmin = vm.load(address(proxy), ADMIN_SLOT);
        address proxyAdminAddr = address(uint160(uint256(proxyAdmin)));

        return ProxyInfo({ proxy: address(proxy), admin: proxyAdminAddr });
    }

    // Setup all proxies to avoid stack too deep
    function setupProxies() internal {
        EmptyContract emptyContract = new EmptyContract();
        deployedContracts.emptyContract = emptyContract;

        // Create proxies
        registryCoordinatorInfo = createProxy(address(emptyContract), deployer, "");
        deployedContracts.taiyiRegistryCoordinator =
            TaiyiRegistryCoordinator(address(registryCoordinatorInfo.proxy));

        linglongSlasherInfo = createProxy(address(emptyContract), deployer, "");
        deployedContracts.linglongSlasher =
            LinglongSlasher(address(linglongSlasherInfo.proxy));

        pubkeyRegistryInfo = createProxy(address(emptyContract), deployer, "");
        deployedContracts.pubkeyRegistry =
            PubkeyRegistry(address(pubkeyRegistryInfo.proxy));

        socketRegistryInfo = createProxy(address(emptyContract), deployer, "");
        deployedContracts.socketRegistry =
            SocketRegistry(address(socketRegistryInfo.proxy));

        eigenLayerMiddlewareInfo = createProxy(address(emptyContract), deployer, "");
        deployedContracts.eigenLayerMiddleware =
            EigenLayerMiddleware(address(eigenLayerMiddlewareInfo.proxy));

        taiyiCoreInfo = createProxy(address(emptyContract), deployer, "");
        deployedContracts.taiyiCore = TaiyiCore(payable(address(taiyiCoreInfo.proxy)));
    }

    // Deploy implementation contracts and initialize them
    function deployImplementations() internal {
        string memory taiyiAddresses = "taiyiAddresses";

        // Deploy TaiyiRegistryCoordinator implementation and proxy
        TaiyiRegistryCoordinator registryCoordinatorImpl = new TaiyiRegistryCoordinator(
            IAllocationManager(allocationManager),
            IPauserRegistry(eigenPauserReg),
            "TaiyiRegistryCoordinator"
        );

        ProxyAdmin(registryCoordinatorInfo.admin).upgradeAndCall(
            ITransparentUpgradeableProxy(
                address(deployedContracts.taiyiRegistryCoordinator)
            ),
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
            taiyiAddresses,
            "taiyiRegistryCoordinatorImpl",
            address(registryCoordinatorImpl)
        );
        vm.serializeAddress(
            taiyiAddresses,
            "taiyiRegistryCoordinator",
            address(registryCoordinatorInfo.proxy)
        );
        vm.serializeAddress(
            taiyiAddresses,
            "taiyiRegistryCoordinatorProxyAdminAddress",
            registryCoordinatorInfo.admin
        );

        // Deploy LinglongSlasher
        LinglongSlasher slasherImpl = new LinglongSlasher();
        ProxyAdmin(linglongSlasherInfo.admin).upgradeAndCall(
            ITransparentUpgradeableProxy(address(deployedContracts.linglongSlasher)),
            address(slasherImpl),
            abi.encodeWithSelector(
                LinglongSlasher.initialize.selector, implOwner, allocationManager, urc
            )
        );

        vm.serializeAddress(taiyiAddresses, "linglongSlasherImpl", address(slasherImpl));
        vm.serializeAddress(
            taiyiAddresses, "linglongSlasher", address(linglongSlasherInfo.proxy)
        );
        vm.serializeAddress(
            taiyiAddresses, "linglongSlasherProxyAdminAddress", linglongSlasherInfo.admin
        );

        // Deploy PubkeyRegistry
        PubkeyRegistry pubkeyRegistryImpl =
            new PubkeyRegistry(address(deployedContracts.taiyiRegistryCoordinator));
        ProxyAdmin(pubkeyRegistryInfo.admin).upgradeAndCall(
            ITransparentUpgradeableProxy(address(deployedContracts.pubkeyRegistry)),
            address(pubkeyRegistryImpl),
            ""
        );

        vm.serializeAddress(
            taiyiAddresses, "pubkeyRegistryImpl", address(pubkeyRegistryImpl)
        );
        vm.serializeAddress(
            taiyiAddresses, "pubkeyRegistry", address(pubkeyRegistryInfo.proxy)
        );
        vm.serializeAddress(
            taiyiAddresses, "pubkeyRegistryProxyAdminAddress", pubkeyRegistryInfo.admin
        );

        // Deploy SocketRegistry
        SocketRegistry socketRegistryImpl =
            new SocketRegistry(deployedContracts.taiyiRegistryCoordinator);
        ProxyAdmin(socketRegistryInfo.admin).upgradeAndCall(
            ITransparentUpgradeableProxy(address(deployedContracts.socketRegistry)),
            address(socketRegistryImpl),
            ""
        );
        vm.serializeAddress(
            taiyiAddresses, "socketRegistryImpl", address(socketRegistryImpl)
        );
        vm.serializeAddress(
            taiyiAddresses, "socketRegistry", address(socketRegistryInfo.proxy)
        );
        vm.serializeAddress(
            taiyiAddresses, "socketRegistryProxyAdminAddress", socketRegistryInfo.admin
        );

        // Deploy EigenLayerMiddleware
        EigenLayerMiddleware eigenLayerMiddlewareImpl = new EigenLayerMiddleware();
        IEigenLayerMiddleware.Config memory config = IEigenLayerMiddleware.Config({
            avsDirectory: avsDirectory,
            delegationManager: delegationManager,
            rewardCoordinator: rewardCoordinator,
            rewardInitiator: rewardInitiator,
            registryCoordinator: address(registryCoordinatorInfo.proxy),
            underwriterShareBips: 8000,
            registry: urc,
            slasher: address(linglongSlasherInfo.proxy),
            allocationManager: allocationManager,
            registrationMinCollateral: 0
        });
        ProxyAdmin(eigenLayerMiddlewareInfo.admin).upgradeAndCall(
            ITransparentUpgradeableProxy(address(deployedContracts.eigenLayerMiddleware)),
            address(eigenLayerMiddlewareImpl),
            abi.encodeWithSelector(
                EigenLayerMiddleware.initialize.selector, implOwner, config
            )
        );

        vm.serializeAddress(
            taiyiAddresses, "eigenLayerMiddlewareImpl", address(eigenLayerMiddlewareImpl)
        );
        vm.serializeAddress(
            taiyiAddresses,
            "eigenLayerMiddleware",
            address(eigenLayerMiddlewareInfo.proxy)
        );
        vm.serializeAddress(
            taiyiAddresses,
            "eigenLayerMiddlewareProxyAdminAddress",
            eigenLayerMiddlewareInfo.admin
        );

        // Deploy TaiyiCore
        TaiyiCore taiyiCoreImpl = new TaiyiCore();
        ProxyAdmin(taiyiCoreInfo.admin).upgradeAndCall(
            ITransparentUpgradeableProxy(address(deployedContracts.taiyiCore)),
            address(taiyiCoreImpl),
            abi.encodeWithSelector(TaiyiCore.initialize.selector, implOwner)
        );

        vm.serializeAddress(taiyiAddresses, "taiyiCoreImpl", address(taiyiCoreImpl));
        vm.serializeAddress(taiyiAddresses, "taiyiCore", address(taiyiCoreInfo.proxy));
        string memory addresses = vm.serializeAddress(
            taiyiAddresses, "taiyiCoreProxyAdminAddress", taiyiCoreInfo.admin
        );

        string memory output = "output";
        string memory finalJ = vm.serializeString(output, "taiyiAddresses", addresses);
        vm.writeJson(finalJ, "script/output/devnet/taiyiAddresses.json");
    }

    function setupDevnetAddresses(
        uint256 proxyDeployerPrivateKey,
        string memory taiyiAddresses,
        string memory configFileName
    )
        internal
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

        IRegistry.Config memory registryConfig = IRegistry.Config({
            minCollateralWei: 0.1 ether,
            fraudProofWindow: 7200,
            unregistrationDelay: 7200,
            slashWindow: 7200,
            optInDelay: 7200
        });

        Registry registry = new Registry(registryConfig);
        emit log_address(address(registry));
        urc = address(registry);
    }

    function setupHoleskyAddresses() internal {
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

    function run(string memory configFileName) public {
        // Get deployer address from private key
        (uint256 proxyDeployerPrivateKey, uint256 implPrivateKey) = getPrivateKeys();
        deployer = vm.addr(proxyDeployerPrivateKey);
        implOwner = vm.addr(implPrivateKey);

        string memory network = vm.envString("NETWORK");
        string memory taiyiAddresses = "taiyiAddresses";

        vm.createDir("script/output/devnet", true);

        if (keccak256(abi.encodePacked(network)) == keccak256(abi.encodePacked("devnet")))
        {
            setupDevnetAddresses(proxyDeployerPrivateKey, taiyiAddresses, configFileName);
        } else if (
            keccak256(abi.encodePacked(network)) == keccak256(abi.encodePacked("holesky"))
        ) {
            setupHoleskyAddresses();
        }

        rewardInitiator = address(0xd8F3183DEf51a987222d845Be228E0bBB932c292); // Arbitrary address

        vm.startBroadcast(proxyDeployerPrivateKey);

        // Setup proxies
        setupProxies();

        // Deploy implementations
        deployImplementations();

        vm.stopBroadcast();
    }

    function getPrivateKeys()
        internal
        returns (uint256 proxyDeployerPrivateKey, uint256 implPrivateKey)
    {
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

        proxyDeployerPrivateKey = vm.parseUint(pkString); // Parse as hex
        implPrivateKey = vm.parseUint(implPkString); // Parse as hex

        return (proxyDeployerPrivateKey, implPrivateKey);
    }
}

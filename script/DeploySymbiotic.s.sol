// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import { Script, console2 } from "forge-std/Script.sol";

import { DelegatorFactory } from
    "../lib/middleware-sdk/lib/core/src/contracts/DelegatorFactory.sol";

import { NetworkRegistry } from
    "../lib/middleware-sdk/lib/core/src/contracts/NetworkRegistry.sol";
import { OperatorRegistry } from
    "../lib/middleware-sdk/lib/core/src/contracts/OperatorRegistry.sol";
import { SlasherFactory } from
    "../lib/middleware-sdk/lib/core/src/contracts/SlasherFactory.sol";
import { VaultFactory } from
    "../lib/middleware-sdk/lib/core/src/contracts/VaultFactory.sol";

import { MetadataService } from
    "../lib/middleware-sdk/lib/core/src/contracts/service/MetadataService.sol";
import { NetworkMiddlewareService } from
    "../lib/middleware-sdk/lib/core/src/contracts/service/NetworkMiddlewareService.sol";
import { OptInService } from
    "../lib/middleware-sdk/lib/core/src/contracts/service/OptInService.sol";

import { FullRestakeDelegator } from
    "../lib/middleware-sdk/lib/core/src/contracts/delegator/FullRestakeDelegator.sol";
import { NetworkRestakeDelegator } from
    "../lib/middleware-sdk/lib/core/src/contracts/delegator/NetworkRestakeDelegator.sol";

import { OperatorNetworkSpecificDelegator } from
    "../lib/middleware-sdk/lib/core/src/contracts/delegator/OperatorNetworkSpecificDelegator.sol";
import { OperatorSpecificDelegator } from
    "../lib/middleware-sdk/lib/core/src/contracts/delegator/OperatorSpecificDelegator.sol";
import { Slasher } from "../lib/middleware-sdk/lib/core/src/contracts/slasher/Slasher.sol";
import { VetoSlasher } from
    "../lib/middleware-sdk/lib/core/src/contracts/slasher/VetoSlasher.sol";
import { Vault } from "../lib/middleware-sdk/lib/core/src/contracts/vault/Vault.sol";
import { VaultTokenized } from
    "../lib/middleware-sdk/lib/core/src/contracts/vault/VaultTokenized.sol";

import { VaultConfigurator } from
    "../lib/middleware-sdk/lib/core/src/contracts/VaultConfigurator.sol";

contract CoreScript is Script {
    function run(address owner) public {
        vm.startBroadcast();
        (,, address deployer) = vm.readCallers();

        VaultFactory vaultFactory = new VaultFactory(deployer);
        DelegatorFactory delegatorFactory = new DelegatorFactory(deployer);
        SlasherFactory slasherFactory = new SlasherFactory(deployer);
        NetworkRegistry networkRegistry = new NetworkRegistry();
        OperatorRegistry operatorRegistry = new OperatorRegistry();
        MetadataService operatorMetadataService =
            new MetadataService(address(operatorRegistry));
        MetadataService networkMetadataService =
            new MetadataService(address(networkRegistry));
        NetworkMiddlewareService networkMiddlewareService =
            new NetworkMiddlewareService(address(networkRegistry));
        OptInService operatorVaultOptInService = new OptInService(
            address(operatorRegistry), address(vaultFactory), "OperatorVaultOptInService"
        );
        OptInService operatorNetworkOptInService = new OptInService(
            address(operatorRegistry),
            address(networkRegistry),
            "OperatorNetworkOptInService"
        );

        address vaultImpl = address(
            new Vault(
                address(delegatorFactory), address(slasherFactory), address(vaultFactory)
            )
        );
        vaultFactory.whitelist(vaultImpl);
        assert(vaultFactory.implementation(1) == address(vaultImpl));
        address vaultTokenizedImpl = address(
            new VaultTokenized(
                address(delegatorFactory), address(slasherFactory), address(vaultFactory)
            )
        );
        vaultFactory.whitelist(vaultTokenizedImpl);
        assert(vaultFactory.implementation(2) == address(vaultTokenizedImpl));

        address networkRestakeDelegatorImpl = address(
            new NetworkRestakeDelegator(
                address(networkRegistry),
                address(vaultFactory),
                address(operatorVaultOptInService),
                address(operatorNetworkOptInService),
                address(delegatorFactory),
                delegatorFactory.totalTypes()
            )
        );
        delegatorFactory.whitelist(networkRestakeDelegatorImpl);
        assert(NetworkRestakeDelegator(networkRestakeDelegatorImpl).TYPE() == 0);

        address fullRestakeDelegatorImpl = address(
            new FullRestakeDelegator(
                address(networkRegistry),
                address(vaultFactory),
                address(operatorVaultOptInService),
                address(operatorNetworkOptInService),
                address(delegatorFactory),
                delegatorFactory.totalTypes()
            )
        );
        delegatorFactory.whitelist(fullRestakeDelegatorImpl);
        assert(FullRestakeDelegator(fullRestakeDelegatorImpl).TYPE() == 1);

        address operatorSpecificDelegatorImpl = address(
            new OperatorSpecificDelegator(
                address(operatorRegistry),
                address(networkRegistry),
                address(vaultFactory),
                address(operatorVaultOptInService),
                address(operatorNetworkOptInService),
                address(delegatorFactory),
                delegatorFactory.totalTypes()
            )
        );
        delegatorFactory.whitelist(operatorSpecificDelegatorImpl);
        assert(OperatorSpecificDelegator(operatorSpecificDelegatorImpl).TYPE() == 2);

        address operatorNetworkSpecificDelegatorImpl = address(
            new OperatorNetworkSpecificDelegator(
                address(operatorRegistry),
                address(networkRegistry),
                address(vaultFactory),
                address(operatorVaultOptInService),
                address(operatorNetworkOptInService),
                address(delegatorFactory),
                delegatorFactory.totalTypes()
            )
        );
        delegatorFactory.whitelist(operatorNetworkSpecificDelegatorImpl);
        assert(
            OperatorNetworkSpecificDelegator(operatorNetworkSpecificDelegatorImpl).TYPE()
                == 3
        );

        address slasherImpl = address(
            new Slasher(
                address(vaultFactory),
                address(networkMiddlewareService),
                address(slasherFactory),
                slasherFactory.totalTypes()
            )
        );
        slasherFactory.whitelist(slasherImpl);
        assert(Slasher(slasherImpl).TYPE() == 0);

        address vetoSlasherImpl = address(
            new VetoSlasher(
                address(vaultFactory),
                address(networkMiddlewareService),
                address(networkRegistry),
                address(slasherFactory),
                slasherFactory.totalTypes()
            )
        );
        slasherFactory.whitelist(vetoSlasherImpl);
        assert(VetoSlasher(vetoSlasherImpl).TYPE() == 1);

        VaultConfigurator vaultConfigurator = new VaultConfigurator(
            address(vaultFactory), address(delegatorFactory), address(slasherFactory)
        );

        vaultFactory.transferOwnership(owner);
        delegatorFactory.transferOwnership(owner);
        slasherFactory.transferOwnership(owner);
        assert(vaultFactory.owner() == owner);
        assert(delegatorFactory.owner() == owner);
        assert(slasherFactory.owner() == owner);

        console2.log("VaultFactory: ", address(vaultFactory));
        console2.log("DelegatorFactory: ", address(delegatorFactory));
        console2.log("SlasherFactory: ", address(slasherFactory));
        console2.log("NetworkRegistry: ", address(networkRegistry));
        console2.log("OperatorRegistry: ", address(operatorRegistry));
        console2.log("OperatorMetadataService: ", address(operatorMetadataService));
        console2.log("NetworkMetadataService: ", address(networkMetadataService));
        console2.log("NetworkMiddlewareService: ", address(networkMiddlewareService));
        console2.log("OperatorVaultOptInService: ", address(operatorVaultOptInService));
        console2.log(
            "OperatorNetworkOptInService: ", address(operatorNetworkOptInService)
        );
        console2.log("VaultConfigurator: ", address(vaultConfigurator));

        vm.stopBroadcast();
    }
}

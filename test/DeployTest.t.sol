// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import { Deploy } from "../script/Deployments.s.sol";
import { SetRegistry } from "../script/SetRegistry.s.sol";
import { SetupContract } from "../script/SetupContract.s.sol";
import "forge-std/Test.sol";

contract DeployTest is Test {
    Deploy deploy;
    SetRegistry setRegistry;
    SetupContract setupContract;

    function setUp() public {
        deploy = new Deploy();
        setRegistry = new SetRegistry();
        setupContract = new SetupContract();
    }

    function testRunDeployScript() public {
        vm.setEnv(
            "PROXY_OWNER_PRIVATE_KEY",
            "c5114526e042343c6d1899cad05e1c00ba588314de9b96929914ee0df18d46b2"
        );
        vm.setEnv(
            "IMPL_OWNER_PRIVATE_KEY",
            "a492823c3e193d6c595f37a18e3c06650cf4c74558cc818b16130b293716106f"
        );
        vm.setEnv("NETWORK", "devnet");
        (uint256 proxyDeployerPrivateKey, uint256 implPrivateKey) =
            deploy.getPrivateKeys();
        address deployer = vm.addr(proxyDeployerPrivateKey);
        address implOwner = vm.addr(implPrivateKey);
        vm.deal(deployer, 1000 ether);
        vm.deal(implOwner, 1000 ether);

        deploy.run("deploy-test-config.json");
        setRegistry.run();
        setupContract.run();
    }
}

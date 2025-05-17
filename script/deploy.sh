#! /bin/bash
if [ -z "$EXECUTION_URL" ]; then
    export EXECUTION_URL="http://localhost:8545"
fi
if [ -z "$PROXY_OWNER_PRIVATE_KEY" ]; then
    export PROXY_OWNER_PRIVATE_KEY="c5114526e042343c6d1899cad05e1c00ba588314de9b96929914ee0df18d46b2"
fi
if [ -z "$IMPL_OWNER_PRIVATE_KEY" ]; then
    export IMPL_OWNER_PRIVATE_KEY="a492823c3e193d6c595f37a18e3c06650cf4c74558cc818b16130b293716106f"

fi
if [ -z "$NETWORK" ]; then
    export NETWORK="devnet"
fi
export FOUNDRY_PROFILE=ci
forge script --rpc-url $EXECUTION_URL \
-vvvv --broadcast ./script/Deployments.s.sol:Deploy \
--sig "run(string memory configFile, uint256 minCollateral)" \
-- eigenlayer-deploy-config-devnet.json 0.01ether

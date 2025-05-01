# Operator Registration Guide

This document walks through registering an **operator** with LingLong's two supported restaking protocols.

> If you are looking for an architectural overview see `README.md`. For low-level contract docs see the other files inside the `docs/` directory.

---

## 1. EigenLayer Path

### 1.1 Register as an Operator
```solidity
DELEGATION_MANAGER.registerAsOperator(
    address(0), // No delegation approver (optional)
    0,          // No allocation delay      (optional)
    "https://example.com/metadata" // Operator metadata URL
);
```

### 1.2 Stake Into Strategies
```solidity
WETH.approve(address(STRATEGY_MANAGER), amount);

uint256 shares = STRATEGY_MANAGER.depositIntoStrategy(
    strategy_address,
    token_address,
    amount
);
```

### 1.3 Allocate Stake to an Operator Set
```solidity
// Remove allocation delay (optional)
allocationManager.setAllocationDelay(operatorAddress, 0);

IAllocationManagerTypes.AllocateParams[] memory allocParams = new IAllocationManagerTypes.AllocateParams[](1);
allocParams[0] = IAllocationManagerTypes.AllocateParams({
    operatorSet: OperatorSet(taiyiMiddlewareAddress, operatorSetId),
    strategies: strategies,
    newMagnitudes: magnitudes
});

ALLOCATION_MANAGER.modifyAllocations(operatorAddress, allocParams);
```

### 1.4 Finalise Registration via the Coordinator
```solidity
string memory socket = "operator.example.com";
IPubkeyRegistry.PubkeyRegistrationParams memory pubkeyParams = /* … */;
bytes memory data = abi.encode(socket, pubkeyParams);

IAllocationManagerTypes.RegisterParams memory registerParams = IAllocationManagerTypes.RegisterParams({
    avs: taiyiMiddlewareAddress,
    operatorSetIds: [operatorSetId],
    data: data
});

ALLOCATION_MANAGER.registerForOperatorSets(operatorAddress, registerParams);
```

---

## 2. Symbiotic Path *(TBD)*
Integration with Symbiotic will follow the same flow – stake → allocate → register – but uses `encodeOperatorSetId96` (see [`OperatorSubsetLib`](OperatorSubsetLib.md)) to generate subnetwork IDs and interacts with vaults instead of strategies. 
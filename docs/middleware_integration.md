# Middleware Integration

| File | Notes |
| -------- | -------- |
| [`SymbioticNetworkMiddleware.sol`](../src/symbiotic-network/SymbioticNetworkMiddleware.sol) | Symbiotic network middleware implementation |
| [`TaiyiRegistryCoordinator.sol`](../src/operator-registries/TaiyiRegistryCoordinator.sol) | Main registry coordinator |
| [`LinglongSlasher.sol`](../src/storage/LinglongSlasherStorage.sol) | Slashing mechanism storage |

Libraries and Dependencies:

| File | Notes |
| -------- | -------- |
| [`RestakingProtocolMapLib.sol`](../src/libs/RestakingProtocolMapLib.sol) | Protocol mapping utilities |
| [`EigenLayerMiddlewareLib.sol`](../src/libs/EigenLayerMiddlewareLib.sol) | EigenLayer middleware utilities |

## Overview

This document outlines the design and implementation plan for integrating `SymbioticNetworkMiddleware` with the existing architecture alongside `EigenLayerMiddleware`. The goal is to create a unified infrastructure that allows both middleware systems to work together with shared components like `TaiyiRegistryCoordinator` and `LinglongSlasher`.

## Architectural Design

### Unified Registry Coordinator

The `TaiyiRegistryCoordinator` will be enhanced to support both middleware implementations by:

- Adding a new enum type to identify the middleware protocol (EigenLayer or Symbiotic)
- Implementing protocol-specific routing for operations
- Supporting both operator set (EigenLayer) and subnetwork (Symbiotic) paradigms

### Operator Registration Flow

#### For EigenLayer

The EigenLayer registration flow follows this process:

- Operators register through `TaiyiRegistryCoordinator` specifying operator sets
- Operators allocate stake via EigenLayer's allocation system
- Registration information is stored in operator sets

#### For Symbiotic

The Symbiotic registration flow follows a different process:

- Operators register through `TaiyiRegistryCoordinator` specifying subnetworks
- Registration process maps subnetwork IDs to appropriate operator sets internally
- `SymbioticNetworkMiddleware` handles the subnetwork-specific logic

### Core Components Integration

#### Registry Coordinator Enhancements

The Registry Coordinator requires several enhancements:

- Add protocol type tracking for each registration
- Implement middleware-specific function routing
- Group protocol-specific functions under clear sections

#### Slashing Integration

Slashing mechanisms need to support both protocols:

- Enhance `LinglongSlasher` to handle both protocols
- For EigenLayer: Continue using `AllocationManager.slashOperator()`
- For Symbiotic: Implement slashing via Symbiotic's vault mechanism

#### Rewards Distribution

Each middleware will handle its own rewards:

- `EigenLayerRewardsHandler` continues handling EigenLayer rewards
- Add a new `SymbioticRewardsHandler` for Symbiotic rewards

## Detailed Component Design

### TaiyiRegistryCoordinator Changes

```solidity
/**
 * @notice Enum for different restaking protocols supported by the coordinator
 */
enum RestakingProtocol {
    NONE,
    EIGENLAYER,
    SYMBIOTIC
}

/**
 * @notice Maps middleware addresses to their protocol type
 * @dev Used for protocol-specific routing of function calls
 */
mapping(address => RestakingProtocol) public restakingProtocol;

/**
 * @notice Tracks all registered middleware addresses
 */
EnumerableSet.AddressSet internal restakingMiddleware;

/**
 * @notice Registers an operator with a service type based on protocol
 * @param operator The address of the operator being registered
 * @param serviceTypeId The ID of the service type (operator set or subnetwork)
 * @param data Protocol-specific registration data
 */
function registerOperatorWithServiceType(
    address operator,
    uint32 serviceTypeId,
    bytes calldata data
) external {
    // Route based on msg.sender's protocol type
    if (restakingProtocol[msg.sender] == RestakingProtocol.SYMBIOTIC) {
        // Handle Symbiotic-specific logic
        // Map subnetwork ID to operator sets
    } else {
        // Handle EigenLayer logic (existing implementation)
    }
}
```

*Effects*:
* Updates the operator's registration status
* Adds the operator to the appropriate protocol tracking
* Emits a registration event

*Requirements*:
* Sender must be a registered middleware contract
* Operator must not already be registered for the specified service type
* All required parameters must be valid

### SymbioticNetworkMiddleware Changes

```solidity
/**
 * @notice Registers validators with the Symbiotic network
 * @param registrations Array of validator registrations
 * @param delegationSignatures BLS signatures for delegation
 * @param delegateePubKey Public key of the delegatee
 * @param delegateeAddress Address of the delegatee
 * @param data Additional registration data
 * @return registrationRoot The root of the registration merkle tree
 */
function registerValidators(
    IRegistry.Registration[] calldata registrations,
    BLS.G2Point[] calldata delegationSignatures,
    BLS.G1Point calldata delegateePubKey,
    address delegateeAddress,
    bytes[] calldata data
) external payable returns (bytes32 registrationRoot) {
    // Implement similar to EigenLayerMiddleware.registerValidators
}

/**
 * @notice Handles slashing of an operator in the Symbiotic network
 * @param operator The address of the operator to slash
 * @param subnetwork The ID of the subnetwork
 * @param slashAmount The amount to slash
 * @param reason The reason for slashing
 */
function handleSlashing(
    address operator,
    uint96 subnetwork,
    uint256 slashAmount,
    string memory reason
) external {
    // Implement Symbiotic-specific slashing
}

/**
 * @notice Distributes rewards to operators in a subnetwork
 * @param token The address of the reward token
 * @param amount The amount of rewards to distribute
 * @param subnetwork The ID of the subnetwork
 */
function distributeRewards(
    address token,
    uint256 amount,
    uint96 subnetwork
) external {
    // Implement Symbiotic rewards distribution
}
```

*Effects*:
* For `registerValidators`: Creates new validator registrations in the Symbiotic network
* For `handleSlashing`: Slashes the operator's stake in the specified subnetwork
* For `distributeRewards`: Distributes rewards to operators in the specified subnetwork

*Requirements*:
* For `registerValidators`: Valid BLS signatures, sufficient payment, and valid registration data
* For `handleSlashing`: Caller must have slashing authority, operator must be registered
* For `distributeRewards`: Caller must have rewards distribution authority, sufficient token balance

### LinglongSlasher Enhancements

```solidity
/**
 * @notice Slashes an operator based on an opt-in commitment
 * @param commitment The commitment data containing slashing parameters
 * @param evidence Evidence supporting the slashing claim
 * @param challenger Address of the challenger initiating the slash
 * @return slashAmountGwei The amount slashed in Gwei
 */
function slashFromOptIn(
    ISlasher.Commitment calldata commitment,
    bytes calldata evidence,
    address challenger
) external override returns (uint256 slashAmountGwei) {
    // Extract middleware address from commitment
    address middleware = _extractMiddlewareFromCommitment(commitment);
    
    // Determine protocol and handle accordingly
    if (restakingProtocol[middleware] == RestakingProtocol.SYMBIOTIC) {
        // Call Symbiotic-specific slashing mechanism
        return _slashSymbioticOperator(...);
    } else {
        // Existing EigenLayer slashing implementation
        return _slashEigenLayerOperator(...);
    }
}
```

*Effects*:
* Slashes the operator's stake based on the commitment
* Rewards the challenger if applicable
* Emits a slashing event

*Requirements*:
* Valid commitment and evidence
* Middleware must be registered
* Operator must have opted in to the slashing conditions

## Implementation Plan

### Phase 1: TaiyiRegistryCoordinator Enhancements

1. Add protocol type tracking
2. Implement middleware address management
3. Modify operator registration to support both protocols
4. Group protocol-specific functions

### Phase 2: SymbioticNetworkMiddleware Integration

1. Add Registry integration for validator registration
2. Implement subnetwork to operator set mapping
3. Add rewards distribution for Symbiotic
4. Implement Symbiotic-specific slashing mechanisms

### Phase 3: LinglongSlasher Adaptation

1. Enhance slashing to support both protocols
2. Implement protocol detection and routing
3. Add Symbiotic-specific slashing implementations

### Phase 4: Testing and Validation

1. Unit tests for each component
2. Integration tests for cross-protocol functionality
3. End-to-end testing of operator flows

## Backward Compatibility

The design ensures that all existing EigenLayer functionality continues to work without interruption. New protocol-specific paths are added alongside existing ones rather than replacing them.

## Security Considerations

1. **Access Control**: Ensure proper access control between protocols
2. **Asset Isolation**: Maintain clear separation of assets and slashing mechanisms
3. **Cross-Protocol Guards**: Implement careful handling of cross-protocol interactions
4. **Audit Requirements**: Perform thorough audit of all new code paths

## Conclusion

This integration design allows for a unified infrastructure that supports both EigenLayer and Symbiotic protocols while maintaining the unique characteristics of each system. The implementation plan provides a structured approach to adding the necessary functionality without disrupting existing operations. 